// Build 65 — DLL-side mirror of the server's NPC ownership registry.
// See ownership_manager.h for the threading model + Phase A scope.

#include "ownership_manager.h"

#include <windows.h>          // GetTickCount64
#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "../log.h"
#include "../net/client.h"

namespace fw::ownership {
namespace {

using PeerIdBytes = std::array<std::uint8_t, fw::net::PEER_ID_BYTES>;

struct LocalOwnership {
    std::uint32_t epoch        = 0;
    PeerIdBytes   owner_peer_id{};   // all-zero = unowned (transient state)
};

constexpr PeerIdBytes kZeroPeer{};   // value-initialised → all-zero

struct State {
    std::shared_mutex                                mtx;
    std::unordered_map<std::uint32_t, LocalOwnership> map;
    PeerIdBytes                                       local_peer_id{};
    bool                                              local_peer_id_set = false;
    std::atomic<std::uint64_t>                        phase2_count{0};
    std::atomic<std::uint64_t>                        bcast_count{0};
};

State& state() {
    static State s;
    return s;
}

// Forward-declared TX side state — definitions for notify_observation /
// record_owned_state / tick_periodic live further down, but on_phase2
// needs the obs-set handle to invalidate the dedup on release. Keeping
// the type + accessor here lets us split the file logically while
// satisfying the C++ "use-before-define" rule.
struct OwnedSnapshot {
    std::uint32_t epoch = 0;
    float         pos_x = 0.0f;
    float         pos_y = 0.0f;
    float         pos_z = 0.0f;
    float         yaw_rad      = 0.0f;
    std::uint8_t  anim_state   = 0;
    std::uint8_t  hp_pct       = 100;
    std::uint64_t last_seen_ms = 0;
};

struct TxState {
    std::shared_mutex                                 obs_mtx;
    // Build 68.1 — observe dedup CLASS map (was a plain one-shot set). The
    // sphere proximity seed burned the one-shot dedup BEFORE combat ever
    // started, so the later COMBAT observe (the only observe that stamps
    // server-side engage, ownership.py on_observed) was silently dropped for
    // every seeded fid → all peers stuck at proximity-only threat (~1.0) →
    // ABS_DELTA(3) unclearable → the 2026-06-11 aggro asymmetry. Classes:
    // 1=proximity seed, 2=combat. A fid observed as seed may be re-observed
    // ONCE as combat (upgrade → server stamps engage); everything else stays
    // deduped → max 2 observes per fid per epoch = no UDP storm (the c.8
    // storm was UNBOUNDED per-frame observation; this is a one-shot upgrade).
    std::unordered_map<std::uint32_t, std::uint8_t>   observed;
    // Build 68.5 — last COMBAT observe per fid, so engage can be refreshed at a
    // bounded rate instead of being stamped once and decaying to zero forever.
    std::unordered_map<std::uint32_t, std::uint64_t>  last_combat_obs_ms;
    std::shared_mutex                                 owned_mtx;
    std::unordered_map<std::uint32_t, OwnedSnapshot>  owned;
    std::uint64_t                                     last_hb_ms      = 0;
    std::uint64_t                                     last_state_ms   = 0;
    std::atomic<std::uint64_t>                        observed_emitted{0};
    std::atomic<std::uint64_t>                        hb_emitted{0};
    std::atomic<std::uint64_t>                        state_emitted{0};
};

TxState& tx_state() {
    static TxState s;
    return s;
}

PeerIdBytes pack_peer_id(const std::uint8_t* src) {
    PeerIdBytes out{};
    std::memcpy(out.data(), src, fw::net::PEER_ID_BYTES);
    return out;
}

PeerIdBytes pack_peer_id_str(const std::string& peer_id) {
    PeerIdBytes out{};
    const std::size_t n = std::min(peer_id.size(), fw::net::PEER_ID_BYTES);
    std::memcpy(out.data(), peer_id.data(), n);
    return out;
}

bool is_zero_peer(const PeerIdBytes& p) {
    return p == kZeroPeer;
}

} // namespace

void init() {
    // Defaults already correct from zero-initialised State. Log once for
    // post-mortem alignment.
    FW_LOG("ownership_manager: init");
}

void set_local_peer_id(const std::string& peer_id) {
    auto& s = state();
    {
        std::unique_lock lk(s.mtx);
        s.local_peer_id     = pack_peer_id_str(peer_id);
        s.local_peer_id_set = true;
    }
    FW_LOG("ownership_manager: local peer_id set (%s, %zu chars)",
            peer_id.c_str(), peer_id.size());
}

void shutdown() {
    auto& s = state();
    std::unique_lock lk(s.mtx);
    s.map.clear();
    s.local_peer_id_set = false;
    s.local_peer_id     = kZeroPeer;
    FW_LOG("ownership_manager: shutdown");
}

void on_phase2(const fw::net::NPCOwnershipHandoffPhase2Payload& p) {
    auto& s = state();
    const PeerIdBytes new_owner = pack_peer_id(p.new_owner_peer_id);
    const bool is_release = is_zero_peer(new_owner);

    {
        std::unique_lock lk(s.mtx);

        // All-zero new_owner = release: drop the entry entirely so
        // is_owner_of / is_non_owner_tracked both return false.
        if (is_release) {
            const auto it = s.map.find(p.form_id);
            if (it != s.map.end()) {
                s.map.erase(it);
                FW_LOG("ownership: PHASE_2 release fid=0x%X epoch=%u",
                        p.form_id, p.new_epoch);
            } else {
                FW_DBG("ownership: PHASE_2 release for unknown fid=0x%X epoch=%u",
                       p.form_id, p.new_epoch);
            }
        } else {
            LocalOwnership rec;
            rec.epoch         = p.new_epoch;
            rec.owner_peer_id = new_owner;
            s.map[p.form_id]  = rec;
            FW_DBG("ownership: PHASE_2 fid=0x%X epoch=%u",
                   p.form_id, p.new_epoch);
        }
    }
    s.phase2_count.fetch_add(1, std::memory_order_relaxed);

    // Build 65.c.5 fix — on release, clear the TX-side observation dedup
    // so the next detour fire emits a fresh NPC_OBSERVED. Otherwise we'd
    // never re-elect this NPC after a health-gate timeout: clients dedup
    // observation per-session forever, server never sees a new OBSERVED,
    // record stays in the unowned state, raider just freezes.
    if (is_release) {
        auto& tx = tx_state();
        std::unique_lock olk(tx.obs_mtx);
        tx.observed.erase(p.form_id);
    }
}

void on_bcast(const fw::net::NPCOwnershipBcastEntry* entries,
              std::size_t                            count) {
    if (entries == nullptr || count == 0) return;
    auto& s = state();

    std::unique_lock lk(s.mtx);
    for (std::size_t i = 0; i < count; ++i) {
        const auto& e = entries[i];
        const PeerIdBytes owner = pack_peer_id(e.owner_peer_id);
        if (is_zero_peer(owner)) {
            // Server should not include unowned entries in a bootstrap
            // snapshot (registry drops releases). Tolerate anyway.
            s.map.erase(e.form_id);
        } else {
            LocalOwnership rec;
            rec.epoch         = e.epoch;
            rec.owner_peer_id = owner;
            s.map[e.form_id]  = rec;
        }
    }
    s.bcast_count.fetch_add(count, std::memory_order_relaxed);
    FW_LOG("ownership: BCAST applied %zu entries (map size now %zu)",
            count, s.map.size());
}

bool is_owner_of(std::uint32_t form_id) {
    auto& s = state();
    std::shared_lock lk(s.mtx);
    if (!s.local_peer_id_set) return false;
    const auto it = s.map.find(form_id);
    if (it == s.map.end()) return false;
    return it->second.owner_peer_id == s.local_peer_id;
}

bool is_non_owner_tracked(std::uint32_t form_id) {
    auto& s = state();
    std::shared_lock lk(s.mtx);
    const auto it = s.map.find(form_id);
    if (it == s.map.end()) return false;
    if (!s.local_peer_id_set) {
        // We're in the map but haven't learned our identity yet — safest
        // default is "non-owner" so AI suppresses until WELCOME lands.
        return true;
    }
    return it->second.owner_peer_id != s.local_peer_id;
}

bool epoch_for(std::uint32_t form_id, std::uint32_t* out_epoch) {
    if (out_epoch == nullptr) return false;
    auto& s = state();
    std::shared_lock lk(s.mtx);
    const auto it = s.map.find(form_id);
    if (it == s.map.end()) return false;
    *out_epoch = it->second.epoch;
    return true;
}

std::uint64_t tracked_count() {
    auto& s = state();
    std::shared_lock lk(s.mtx);
    return static_cast<std::uint64_t>(s.map.size());
}

std::uint64_t phase2_applied() {
    return state().phase2_count.load(std::memory_order_relaxed);
}

std::uint64_t bcast_applied() {
    return state().bcast_count.load(std::memory_order_relaxed);
}

// ===========================================================================
// TX side (Build 65.c.2) — observation dedup, owner state cache, periodic
// emit. The detour records into the cache (main thread); tick_periodic
// drains it (net thread) into batched payloads.
//
// `OwnedSnapshot` + `TxState` + `tx_state()` are forward-declared above
// (near `state()`) so `on_phase2` can poke at the obs-dedup set on
// release. Definitions of the TX entry points live below.
// ===========================================================================

namespace {

// Build 65.c.5 — bumped from 1000 → 5000 ms. The 1-second window was
// too aggressive: a single dropped detour frame could evict the snapshot
// and silence heartbeats long enough for the server's 2.5 s timeout to
// fire. With 5 s we still drop cell-unloads (engine stops ticking the
// actor) but tolerate transient gaps in the per-frame tick.
// Sphere upgrade (idle-sync fix A) — 5000 → 12000. A proximity-seeded IDLE NPC
// in a slow ProcessLists tier (Low / round-robin) ticks only every few seconds;
// at 5 s it could drop from the owned cache between ticks → heartbeat stops →
// server release → reseed loop. 12 s keeps a slow-ticked idle NPC cached so its
// heartbeat stays continuous (paired with server HEARTBEAT_TIMEOUT_MS 2500→8000).
// A real cell-unload (engine stops ticking entirely) still drops it after 12 s.
constexpr std::uint64_t OWNED_SNAPSHOT_STALE_MS = 12000;

// Build 65.c.5 — bumped from 500 ms → 250 ms (4 Hz). Server's
// HEARTBEAT_TIMEOUT_MS is 2500 ms, so 4 Hz gives 10 consecutive losses of
// margin before a forced release. Previous 500 ms (2 Hz) was tight under
// real-world UDP loss patterns and consistently triggered timeouts.
constexpr std::uint64_t HEARTBEAT_INTERVAL_MS = 250;
constexpr std::uint64_t STATE_INTERVAL_MS     = 100;

} // namespace

void notify_observation(std::uint32_t form_id,
                        std::uint32_t base_id,
                        std::uint32_t cell_id,
                        float pos_x, float pos_y, float pos_z,
                        float dist_sq)
{
    if (form_id == 0 || form_id == 0xFFFFFFFFu) return;
    auto& tx = tx_state();
    // Build 68.1 — class-aware dedup: 1=proximity seed (negative wire dist²),
    // 2=combat. Same-or-lower class → deduped; seed→combat → ONE upgrade
    // observe passes (the server stamps engage on it — the signal the plain
    // one-shot set was silently eating for every sphere-seeded fid).
    //
    // Build 68.5 — COMBAT OBSERVES MUST REPEAT. Measured 2026-07-29: across
    // 1,711 server-side ownership evaluations the challenger threat NEVER once
    // exceeded 1.0 — i.e. pure proximity, engage always zero. Root cause: the
    // server stamps `threat_engaged[peer]` ONLY when it receives an observe
    // (ownership.py:584), and that term decays over THREAT_ENGAGE_WINDOW_MS
    // (4500 ms). With a permanent one-shot dedup the stamp happened exactly
    // ONCE per fid, decayed to zero 4.5 s later and could never refresh — so
    // the engage weight (10) was dead and ONLY damage (weight 30) could ever
    // clear the ABS_DELTA(3) hysteresis. That is precisely the reported
    // behaviour: "raiders only sync once hit" and "aggro only moves if the
    // other client actually shoots them".
    // Fix: a COMBAT observe (cls 2) may re-fire every kCombatReobserveMs while
    // this client is genuinely fighting the NPC, keeping engage fresh. Bounded
    // by construction: 1 packet per actively-fought NPC per 1.5 s (~13/s at 20
    // NPCs) versus the 278/s unbounded per-frame storm the dedup was created to
    // stop. PROXIMITY seeds (cls 1) stay strictly one-shot — they must never
    // refresh, or a merely-near peer would accrue standing and steal ownership.
    static constexpr std::uint64_t kCombatReobserveMs = 1500;
    const std::uint8_t cls = (dist_sq < 0.0f) ? 1u : 2u;
    const std::uint64_t now_ms = GetTickCount64();
    {
        std::shared_lock lk(tx.obs_mtx);
        auto it = tx.observed.find(form_id);
        if (it != tx.observed.end() && it->second >= cls) {
            if (cls != 2u) return;                       // seed: one-shot
            auto lt = tx.last_combat_obs_ms.find(form_id);
            if (lt != tx.last_combat_obs_ms.end()
                && (now_ms - lt->second) < kCombatReobserveMs) {
                return;                                  // combat: rate-limited
            }
        }
    }
    {
        std::unique_lock lk(tx.obs_mtx);
        auto [it, inserted] = tx.observed.try_emplace(form_id, cls);
        if (!inserted) {
            if (it->second >= cls) {
                if (cls != 2u) return;                   // seed: one-shot
                auto& last = tx.last_combat_obs_ms[form_id];
                if ((now_ms - last) < kCombatReobserveMs) return;  // raced
                last = now_ms;                           // combat refresh
            } else {
                it->second = cls;                        // seed → combat upgrade
                tx.last_combat_obs_ms[form_id] = now_ms;
            }
        } else if (cls == 2u) {
            tx.last_combat_obs_ms[form_id] = now_ms;
        }
    }
    fw::net::client().enqueue_npc_observed(
        form_id, base_id, cell_id, pos_x, pos_y, pos_z, dist_sq);
    const auto n = tx.observed_emitted.fetch_add(
        1, std::memory_order_relaxed);
    if (n < 20 || (n % 50) == 0) {
        FW_LOG("ownership: OBSERVED tx #%llu fid=0x%X base=0x%X cell=0x%X "
               "pos=(%.1f,%.1f,%.1f) cls=%u",
               static_cast<unsigned long long>(n + 1),
               form_id, base_id, cell_id, pos_x, pos_y, pos_z,
               static_cast<unsigned>(cls));
    }
}

void record_owned_state(std::uint32_t form_id,
                        float pos_x, float pos_y, float pos_z,
                        float yaw_rad,
                        std::uint8_t anim_state,
                        std::uint8_t hp_pct)
{
    if (form_id == 0 || form_id == 0xFFFFFFFFu) return;
    std::uint32_t epoch = 0;
    if (!epoch_for(form_id, &epoch)) return;   // not tracked

    auto& tx = tx_state();
    OwnedSnapshot snap;
    snap.epoch        = epoch;
    snap.pos_x        = pos_x;
    snap.pos_y        = pos_y;
    snap.pos_z        = pos_z;
    snap.yaw_rad      = yaw_rad;
    snap.anim_state   = anim_state;
    snap.hp_pct       = hp_pct;
    snap.last_seen_ms = static_cast<std::uint64_t>(GetTickCount64());

    // Build 65.c.26 Tier 1 — STICKY HIGH-WATER for anim_state.
    //
    // Per Agent 1 forensics post-c.25 (B65_clientB_asymmetry_AGENT_1.md):
    // Even when the owner's local engine had bit 0x4000 set for 30
    // consecutive frames (= 300 ms continuous combat), wire TX never
    // carried anim=3 to non-owners. Root cause: this function is called
    // 60 Hz from npc_ai_suppress detour and OVERWRITES anim_state every
    // call. The STATE_FROM_OWNER batch fires only every 100 ms (~6
    // captures per window). Engine bit 0x4000 flickers between set and
    // clear per frame (the perception walker re-evaluates each tick). A
    // single anim=0 capture between the last anim=3 and the next TX
    // erases the combat signal for that batch.
    //
    // Fix: KEEP MAX(stored, new) for anim_state. Reset to 0 only after
    // a successful TX in `tick_periodic` so each 100 ms window has a
    // fresh high-water. Net effect: any frame with anim=3 inside the
    // TX window propagates anim=3 over the wire. The receiver-side c.22
    // force-bit + c.23 INTERP-APPLY pipelines (gated on anim_state >= 3)
    // can finally fire on the non-owner client.
    //
    // pos/yaw/hp_pct are always fresh (latest sample); only anim_state
    // is sticky-high because it's the only field where transient zeroes
    // are net-loss vs net-gain (a "stale by 100 ms" combat marker is
    // strictly better than a "fresh anim=0 missed the combat burst").
    std::unique_lock lk(tx.owned_mtx);
    auto it = tx.owned.find(form_id);
    std::uint8_t prev_anim = 0;
    if (it != tx.owned.end()) {
        prev_anim = it->second.anim_state;
        it->second = snap;
    } else {
        auto [new_it, _] = tx.owned.emplace(form_id, snap);
        it = new_it;
    }
    if (prev_anim > it->second.anim_state) {
        it->second.anim_state = prev_anim;
    }
}

void tick_periodic(std::uint64_t now_ms) {
    auto& tx = tx_state();

    // Build 65.c.4 fix — internal timing uses GetTickCount64() to match
    // the `last_seen_ms` stamps written by `record_owned_state`. The
    // `now_ms` parameter (wall-clock ms since epoch) is wired to the
    // outgoing payload's `ts_ms` field (informational for the receiver's
    // lerp); using it for interval comparisons would produce a billion-
    // millisecond delta against the boot-relative tick count and erase
    // every owned snapshot on every call.
    const std::uint64_t tick_now =
        static_cast<std::uint64_t>(GetTickCount64());

    // ---------- Drop stale entries (cell unload, ownership flipped away)
    {
        std::unique_lock lk(tx.owned_mtx);
        for (auto it = tx.owned.begin(); it != tx.owned.end(); ) {
            const bool stale = (tick_now - it->second.last_seen_ms)
                               > OWNED_SNAPSHOT_STALE_MS;
            if (stale || !is_owner_of(it->first)) {
                it = tx.owned.erase(it);
            } else {
                ++it;
            }
        }
    }

    // ---------- HEARTBEAT every 500 ms
    if (tick_now - tx.last_hb_ms >= HEARTBEAT_INTERVAL_MS) {
        tx.last_hb_ms = tick_now;
        std::vector<fw::net::NPCOwnerHeartbeatEntry> hb;
        {
            std::shared_lock lk(tx.owned_mtx);
            hb.reserve(tx.owned.size());
            for (const auto& [fid, snap] : tx.owned) {
                fw::net::NPCOwnerHeartbeatEntry e{};
                e.form_id = fid;
                e.epoch   = snap.epoch;
                hb.push_back(e);
                if (hb.size() >= fw::net::MAX_HEARTBEAT_ENTRIES) break;
            }
        }
        if (!hb.empty()) {
            fw::net::client().enqueue_npc_owner_heartbeat(
                hb.data(), hb.size());
            const auto n = tx.hb_emitted.fetch_add(
                1, std::memory_order_relaxed);
            if (n < 5 || (n % 60) == 0) {
                FW_LOG("ownership: HEARTBEAT tx #%llu entries=%zu",
                       static_cast<unsigned long long>(n + 1),
                       hb.size());
            }
        }
    }

    // ---------- STATE every 100 ms (10 Hz). Owner-driven state batch.
    if (tick_now - tx.last_state_ms >= STATE_INTERVAL_MS) {
        tx.last_state_ms = tick_now;
        // Build 68.6 — SEND EVERY OWNED NPC, NOT THE SAME FIRST 17 FOREVER.
        //
        // The old loop walked tx.owned from begin() and broke at
        // MAX_OWNER_STATES_PER_FRAME (17, an MTU limit). With no rotation and a
        // stable unordered_map iteration order, the SAME 17 fids were streamed
        // on every 100 ms tick and every additional owned NPC NEVER had its
        // position sent at all. Measured 2026-07-29: client A owned 29 NPCs,
        // every batch logged "enqueued 17 entries", and client B mirrored
        // exactly 17 of them — the other 12 got their POSE driven (a separate
        // per-fid channel with no cap) but never a position, so on B they were
        // fully animated while standing wherever B's own vanilla AI had left
        // them. That is the "raiders in the wrong place on client B" report;
        // measured drift on the fids that WERE streamed was 0.0 on 4,591 of
        // 5,133 samples with a 36-unit maximum, i.e. the apply path was never
        // the problem — the data simply never arrived.
        //
        // Fix: emit as many batches as needed to cover the whole owned set
        // (bounded by kMaxStateBatches so a pathological owner count can never
        // flood the link). Nobody starves, and every NPC keeps the full 10 Hz
        // rate — a round-robin cursor would have halved it to 5 Hz past 17.
        static constexpr std::size_t kMaxStateBatches = 4;   // 4 x 17 = 68 NPCs
        std::vector<fw::net::NPCOwnerStateEntry> all;
        {
            std::shared_lock lk(tx.owned_mtx);
            all.reserve(tx.owned.size());
            for (const auto& [fid, snap] : tx.owned) {
                fw::net::NPCOwnerStateEntry e{};
                e.form_id    = fid;
                e.epoch      = snap.epoch;
                e.pos_x      = snap.pos_x;
                e.pos_y      = snap.pos_y;
                e.pos_z      = snap.pos_z;
                e.yaw_rad    = snap.yaw_rad;
                e.pitch_rad  = 0.0f;
                e.anim_state = snap.anim_state;
                e.hp_pct     = snap.hp_pct;
                e.ts_ms      = now_ms;
                // All other fields default to zero. Anim/aim/velocity
                // capture lands in 65.c.3 once we wire the engine-side
                // readers (CombatAimController, locomotion controller).
                all.push_back(e);
            }
        }
        std::vector<fw::net::NPCOwnerStateEntry> st;   // first batch (for logs)
        if (!all.empty()) {
            const std::size_t per = fw::net::MAX_OWNER_STATES_PER_FRAME;
            const std::size_t batches =
                std::min(kMaxStateBatches, (all.size() + per - 1) / per);
            for (std::size_t b = 0; b < batches; ++b) {
                const std::size_t off = b * per;
                const std::size_t cnt = std::min(per, all.size() - off);
                fw::net::client().enqueue_npc_state_from_owner(
                    all.data() + off, cnt);
                if (b == 0) st.assign(all.begin(), all.begin() + cnt);
            }
            if (all.size() > batches * per) {
                static std::atomic<std::uint64_t> s_drop{0};
                const auto dn = s_drop.fetch_add(1, std::memory_order_relaxed);
                if (dn < 5 || (dn % 300) == 0) {
                    FW_WRN("ownership: owned=%zu exceeds %zu batches x %zu — "
                           "%zu NPC(s) get NO position this tick",
                           all.size(), kMaxStateBatches, per,
                           all.size() - batches * per);
                }
            }
        }
        if (!st.empty()) {
            const auto n = tx.state_emitted.fetch_add(
                1, std::memory_order_relaxed);
            if (n < 5 || (n % 300) == 0) {
                FW_LOG("ownership: STATE_FROM_OWNER tx #%llu entries=%zu",
                       static_cast<unsigned long long>(n + 1),
                       st.size());
            }

            // Build 65.c.26 Tier 1 completion — reset anim_state to 0 on
            // emitted fids so the next 100 ms window starts a fresh
            // high-water (see record_owned_state comment block for full
            // rationale). pos/yaw/hp_pct are not reset because they're
            // always fresh-on-write (record_owned_state overwrites them
            // every 60 Hz capture); only anim_state needed sticky-high.
            //
            // If no anim=3 frame lands in the next 100 ms window, the
            // emitted value will be the most recent anim=0. If at least
            // one anim=3 frame lands, MAX(0, 3)=3 propagates. Net effect:
            // any combat burst gets through, idle periods still report 0.
            std::unique_lock lk_reset(tx.owned_mtx);
            for (const auto& entry : st) {
                auto it = tx.owned.find(entry.form_id);
                if (it != tx.owned.end()) {
                    it->second.anim_state = 0;
                }
            }
        }
    }
}

} // namespace fw::ownership
