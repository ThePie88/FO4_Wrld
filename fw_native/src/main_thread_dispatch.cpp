#include "main_thread_dispatch.h"

#include <atomic>
#include <cmath>      // sqrtf — Build 65.c.30 handoff-blend distance log
#include <deque>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <windows.h>  // GetTickCount64 — Build 65.c.22 staleness check

#include "engine/engine_calls.h"
#include "hooks/container_hook.h"   // ApplyingRemoteGuard + tls_applying_remote
#include "hooks/ownership_manager.h" // Build 65.c.10 — owner-driven apply gate
#include "hooks/npc_ai_suppress.h"  // Build 65.c.47 WEDGE3 — mark_dying (corpse guard)
#include "hooks/npc_hp_probe.h"     // HP bar — apply_pool_health_to_actor (vita-dal-pool)
#include "log.h"
#include "native/scene_inject.h"    // M9 wedge 2: ghost armor attach/detach
#include "offsets.h"                // Build 53: POS_OFF for ghost.+0xD0 read
#include "net/protocol.h"           // Build 55a: NPC_FIRE_TARGET_LOCAL / _GHOST

namespace fw::dispatch {

namespace {

std::mutex g_mtx;
std::deque<PendingContainerOp> g_queue;

// B6.1: door queue — separate mutex so doors don't contend with container
// ops. Doors are toggle-only and high-frequency (one per E press).
std::mutex g_door_mtx;
std::deque<PendingDoorOp> g_door_queue;

// M9 wedge 2: equip queue — for armor visual sync.
//   Per-event: net thread enqueues + posts FW_MSG_EQUIP_APPLY.
//   Drained on main thread by WndProc dispatcher.
std::mutex g_equip_mtx;
std::deque<PendingEquipOp> g_equip_queue;

// M9 wedge 4 v9: mesh blob queue — for raw weapon-mesh visual sync.
//   Net thread reassembles chunks → decodes blob → enqueues + posts.
//   Drained on main thread; rebuilds each mesh on the matching ghost
//   weapon root via factory call (Step 4c).
std::mutex g_mesh_blob_mtx;
std::deque<PendingMeshBlob> g_mesh_blob_queue;

// B6.3 v0.5.3: lock queue — separate mutex so locks don't contend with
// doors/containers. Lower-frequency than doors (1 per lockpick / hack).
std::mutex g_lock_mtx;
std::deque<PendingLockOp> g_lock_queue;

// Build 65.c.47 WEDGE3: NPC death-apply queue. Event-driven + reliable +
// very low frequency (one per NPC death). Separate mutex so it never blocks
// the 10 Hz NPC state / fire lanes. The drain holds an ApplyingRemoteGuard
// around engine::kill_actor so the relayed kill doesn't echo to the server.
std::mutex g_npc_death_mtx;
std::deque<PendingNPCDeath> g_npc_death_queue;

// Build 65.c.47 WEDGE3: idempotency dedup. A re-delivered NPC_DEATH_FROM_OWNER
// (reliable channel can re-deliver on retransmit) must NOT double-kill the
// mirror. Main-thread-only (mutated solely in drain_npc_death_apply_queue), so
// no lock needed — but kept as a plain set for clarity. Never pruned: at a few
// dozen deaths per session the memory is negligible; a fid that respawns gets
// a NEW form_id from the engine so stale entries can't false-positive.
std::unordered_set<std::uint32_t> g_killed_fids;

// HP bar (vita-locale-dal-pool): pool→local-Health apply queue. Event-driven
// (one per NPC_HP_POOL_BCAST claim, ≈6 Hz/fid max), tiny POD. Separate mutex so
// it never blocks the death/state lanes. Drained on the main thread (AVO call).
std::mutex g_npc_pool_health_mtx;
std::deque<PendingNpcPoolHealth> g_npc_pool_health_queue;

// B6.5w3.b: NPC continuous-state queue. Higher frequency than locks
// (10 Hz × N npcs server-side) but each entry is small (24 B POD).
// Separate mutex so NPC traffic doesn't block lock/door/container drains.
std::mutex g_npc_mtx;
std::deque<PendingNPCStateEntry> g_npc_queue;

// B6.6w1: server-driven fire trigger queue. Frequency is low (event-
// driven, typically <5 Hz aggregate across all raiders) and entries are
// tiny (12 B POD). Separate mutex so a slow drain doesn't block the
// 10 Hz NPC state lane.
std::mutex g_npc_fire_mtx;
std::deque<PendingNPCFire> g_npc_fire_queue;

// Build 65.c.10: owner-driven STATE_FROM_OWNER apply queue (receiver
// side). Net thread enqueues entries from the relayed batch; main
// thread drains and writes pos to engine actor via apply_npc_pos.
// Separate mutex from g_npc_mtx so the legacy NPC_STATE_BCAST path
// and the new owner-driven path don't contend.
std::mutex g_npc_owner_mtx;
std::deque<PendingNPCOwnerState> g_npc_owner_queue;

// Build 62 — perception trigger queue, separate from fire queue so
// drain timings are independent. Triggers are reliable (server uses
// send_reliable) so we expect small bursts (~5/sec at startup, then
// ~1/sec during ongoing combat after debounce).
std::mutex g_npc_perception_trigger_mtx;
std::deque<PendingNPCPerceptionTrigger> g_npc_perception_trigger_queue;

// B6.5w4 round 2: per-NPC state cache (replaces the bare set from
// round 1). Net thread updates on each BCAST; main thread suppression
// detour reads on each Actor::Update_PerFrame fire and applies state
// POST-hook so renderer sees our pos.
//
// Round 9 extension: track PREV+CURRENT snapshot pair for client-side
// linear interpolation. update_npc_cache shifts current → prev on each
// BCAST before writing new current. Render thread linearly interpolates
// between the two based on elapsed time.
struct CachedNPCStateImpl {
    // Current (latest from server)
    float pos_x;
    float pos_y;
    float pos_z;
    float yaw_deg_math;
    std::uint8_t anim_state;
    std::uint64_t last_update_ms;
    // Previous (before last BCAST)
    float prev_pos_x;
    float prev_pos_y;
    float prev_pos_z;
    float prev_yaw_deg_math;
    std::uint64_t prev_update_ms;
    bool has_prev;
    // B6.5w12 v14 — Ghost AI server-authoritative state. Flat (no
    // prev/current pair) — these are discrete decisions, not
    // interpolatable. Hooks read latest only.
    std::uint32_t package_form_id;
    std::uint32_t combat_target_form_id;
    float         velocity_x;
    float         velocity_y;
    float         velocity_z;
    std::uint8_t  movement_override;
};
std::mutex g_npc_cache_mtx;
std::unordered_map<std::uint32_t, CachedNPCStateImpl> g_npc_cache;

// The FO4 main window handle. Set exactly once by main_menu_hook after
// it subclasses WndProc (post-B3.b-registrar detection). Read lock-free
// thereafter; atomic for publish/acquire ordering.
std::atomic<HWND> g_hwnd{nullptr};

// Post the wake-up message. Swallows failures (HWND missing at boot is
// expected; the queue will flush on next post after set_target_hwnd).
void post_wakeup_container() noexcept {
    HWND h = g_hwnd.load(std::memory_order_acquire);
    if (!h) return;
    if (!PostMessageW(h, FW_MSG_CONTAINER_APPLY, 0, 0)) {
        FW_DBG("dispatch: PostMessage(FW_MSG_CONTAINER_APPLY) failed (err=%lu)",
               GetLastError());
    }
}

void post_wakeup_door() noexcept {
    HWND h = g_hwnd.load(std::memory_order_acquire);
    if (!h) return;
    if (!PostMessageW(h, FW_MSG_DOOR_APPLY, 0, 0)) {
        FW_DBG("dispatch: PostMessage(FW_MSG_DOOR_APPLY) failed (err=%lu)",
               GetLastError());
    }
}

void post_wakeup_equip() noexcept {
    HWND h = g_hwnd.load(std::memory_order_acquire);
    if (!h) return;
    if (!PostMessageW(h, FW_MSG_EQUIP_APPLY, 0, 0)) {
        FW_DBG("dispatch: PostMessage(FW_MSG_EQUIP_APPLY) failed (err=%lu)",
               GetLastError());
    }
}

void post_wakeup_mesh_blob() noexcept {
    HWND h = g_hwnd.load(std::memory_order_acquire);
    if (!h) return;
    if (!PostMessageW(h, FW_MSG_MESH_BLOB_APPLY, 0, 0)) {
        FW_DBG("dispatch: PostMessage(FW_MSG_MESH_BLOB_APPLY) failed (err=%lu)",
               GetLastError());
    }
}

void post_wakeup_lock() noexcept {
    HWND h = g_hwnd.load(std::memory_order_acquire);
    if (!h) return;
    if (!PostMessageW(h, FW_MSG_LOCK_APPLY, 0, 0)) {
        FW_DBG("dispatch: PostMessage(FW_MSG_LOCK_APPLY) failed (err=%lu)",
               GetLastError());
    }
}

void post_wakeup_npc_death() noexcept {
    HWND h = g_hwnd.load(std::memory_order_acquire);
    if (!h) return;
    if (!PostMessageW(h, FW_MSG_NPC_DEATH_APPLY, 0, 0)) {
        FW_DBG("dispatch: PostMessage(FW_MSG_NPC_DEATH_APPLY) failed (err=%lu)",
               GetLastError());
    }
}

void post_wakeup_npc_pool_health() noexcept {
    HWND h = g_hwnd.load(std::memory_order_acquire);
    if (!h) return;
    if (!PostMessageW(h, FW_MSG_NPC_POOL_HEALTH_APPLY, 0, 0)) {
        FW_DBG("dispatch: PostMessage(FW_MSG_NPC_POOL_HEALTH_APPLY) failed (err=%lu)",
               GetLastError());
    }
}

void post_wakeup_npc() noexcept {
    HWND h = g_hwnd.load(std::memory_order_acquire);
    if (h && PostMessageW(h, FW_MSG_NPC_STATE_APPLY, 0, 0)) {
        return;  // happy path — WndProc will drain
    }
    // Either no HWND yet or PostMessage failed. Diagnose:
    if (h) {
        const DWORD err = GetLastError();
        if (err == ERROR_INVALID_WINDOW_HANDLE) {
            // HWND went stale (FO4 recreates the main window across cell
            // transitions / menu open / DXGI reset). Clear it so we don't
            // spam this branch every BCAST; main_menu_hook will call
            // set_target_hwnd again when it re-subclasses the new window
            // and full main-thread drain resumes. Until then we fall
            // back to inline pos-only drain so visible sync keeps
            // working across clients.
            g_hwnd.store(nullptr, std::memory_order_release);
            FW_WRN("dispatch: NPC HWND %p stale (err 1400) — clearing, "
                   "falling back to inline pos-only drain until next "
                   "set_target_hwnd", h);
        } else {
            FW_DBG("dispatch: PostMessage(FW_MSG_NPC_STATE_APPLY) failed err=%lu",
                   err);
        }
    }
    // No HWND OR failed post — apply pos-only from this thread so the
    // NPC at least stays at the right world position on the receiver.
    drain_npc_state_apply_queue_pos_only();
}

void post_wakeup_npc_owner_state() noexcept {
    HWND h = g_hwnd.load(std::memory_order_acquire);
    if (!h) return;
    if (!PostMessageW(h, FW_MSG_NPC_OWNER_STATE_APPLY, 0, 0)) {
        // HWND went stale across cell load / main menu — drop the wake
        // and let the next enqueue try again after WndProc rebinds.
        FW_DBG("dispatch: PostMessage(FW_MSG_NPC_OWNER_STATE_APPLY) failed err=%lu",
               GetLastError());
    }
}

void post_wakeup_npc_fire() noexcept {
    HWND h = g_hwnd.load(std::memory_order_acquire);
    if (!h) return;
    if (!PostMessageW(h, FW_MSG_NPC_FIRE, 0, 0)) {
        FW_DBG("dispatch: PostMessage(FW_MSG_NPC_FIRE) failed (err=%lu)",
               GetLastError());
    }
}

// Build 62 — reuse FW_MSG_NPC_FIRE for now (same drain timing, both queues
// are draining engine-native calls that need main-thread affinity). If we
// see contention or starvation, split to FW_MSG_NPC_PERCEPTION later.
void post_wakeup_npc_perception() noexcept {
    HWND h = g_hwnd.load(std::memory_order_acquire);
    if (!h) return;
    if (!PostMessageW(h, FW_MSG_NPC_FIRE, 0, 0)) {
        FW_DBG("dispatch: PostMessage for perception trigger failed (err=%lu)",
               GetLastError());
    }
}

} // namespace

void enqueue_container_apply(const PendingContainerOp& op) {
    std::size_t qsize;
    {
        std::lock_guard lk(g_mtx);
        g_queue.push_back(op);
        qsize = g_queue.size();
    }
    FW_DBG("dispatch: enqueued kind=%u cfid=0x%X item=0x%X count=%d (qsize=%zu)",
           op.kind, op.container_form_id, op.item_base_id, op.count, qsize);
    post_wakeup_container();
}

void enqueue_door_apply(const PendingDoorOp& op) {
    std::size_t qsize;
    {
        std::lock_guard lk(g_door_mtx);
        g_door_queue.push_back(op);
        qsize = g_door_queue.size();
    }
    FW_DBG("dispatch: door enqueued form=0x%X base=0x%X cell=0x%X (qsize=%zu)",
           op.door_form_id, op.door_base_id, op.door_cell_id, qsize);
    post_wakeup_door();
}

void enqueue_lock_apply(const PendingLockOp& op) {
    std::size_t qsize;
    {
        std::lock_guard lk(g_lock_mtx);
        g_lock_queue.push_back(op);
        qsize = g_lock_queue.size();
    }
    FW_DBG("dispatch: lock enqueued form=0x%X base=0x%X cell=0x%X locked=%u (qsize=%zu)",
           op.lock_form_id, op.lock_base_id, op.lock_cell_id,
           static_cast<unsigned>(op.locked), qsize);
    post_wakeup_lock();
}

void enqueue_npc_death_apply(const PendingNPCDeath& op) {
    std::size_t qsize;
    {
        std::lock_guard lk(g_npc_death_mtx);
        g_npc_death_queue.push_back(op);
        qsize = g_npc_death_queue.size();
    }
    FW_LOG("dispatch: NPC death enqueued fid=0x%X killer=0x%X pos=(%.1f,%.1f,%.1f) (qsize=%zu)",
           op.form_id, op.killer_form_id, op.pos_x, op.pos_y, op.pos_z, qsize);
    post_wakeup_npc_death();
}

// HP bar (vita-locale-dal-pool) — net thread enqueues on each NPC_HP_POOL_BCAST.
void enqueue_npc_pool_health(const PendingNpcPoolHealth& op) {
    {
        std::lock_guard lk(g_npc_pool_health_mtx);
        g_npc_pool_health_queue.push_back(op);
    }
    post_wakeup_npc_pool_health();
}

// Main thread (WndProc) — resolve each fid → Actor* and drive its LOCAL Health to
// the shared pool fraction so the vanilla enemy-health bar reads + repaints it.
void drain_npc_pool_health_queue() {
    std::deque<PendingNpcPoolHealth> local;
    {
        std::lock_guard lk(g_npc_pool_health_mtx);
        local.swap(g_npc_pool_health_queue);
    }
    if (local.empty()) return;
    for (const auto& op : local) {
        if (op.form_id == 0 || op.form_id == 0xFFFFFFFFu) continue;
        void* actor = fw::engine::lookup_by_form_id(op.form_id);
        if (!actor) continue;   // mirror not loaded on this client → nothing to set
        fw::hooks::apply_pool_health_to_actor(actor, op.hp_cur, op.hp_max);
    }
}

void enqueue_npc_state_apply(const std::vector<PendingNPCStateEntry>& entries) {
    if (entries.empty()) return;
    std::size_t qsize;
    {
        std::lock_guard lk(g_npc_mtx);
        for (const auto& e : entries) g_npc_queue.push_back(e);
        qsize = g_npc_queue.size();
    }
    // 10 Hz × N npcs makes this chatty — keep at DBG.
    FW_DBG("dispatch: npc enqueued %zu entries (qsize=%zu)",
           entries.size(), qsize);
    post_wakeup_npc();
}

// Build 65.c.10 — owner-driven state apply enqueue. Same pattern as
// enqueue_npc_state_apply but on the separate g_npc_owner_queue lane.
void enqueue_npc_owner_state_apply(
    const std::vector<PendingNPCOwnerState>& entries)
{
    if (entries.empty()) return;
    std::size_t qsize;
    {
        std::lock_guard lk(g_npc_owner_mtx);
        for (const auto& e : entries) g_npc_owner_queue.push_back(e);
        qsize = g_npc_owner_queue.size();
    }
    FW_DBG("dispatch: npc_owner_state enqueued %zu entries (qsize=%zu)",
           entries.size(), qsize);
    post_wakeup_npc_owner_state();
}

void enqueue_equip_apply(const PendingEquipOp& op) {
    std::size_t qsize;
    {
        std::lock_guard lk(g_equip_mtx);
        g_equip_queue.push_back(op);
        qsize = g_equip_queue.size();
    }
    FW_DBG("dispatch: equip enqueued peer=%s form=0x%X kind=%u (qsize=%zu)",
           op.peer_id, op.item_form_id, op.kind, qsize);
    post_wakeup_equip();
}

void enqueue_mesh_blob_apply(PendingMeshBlob op) {
    std::size_t qsize;
    const std::size_t mesh_count = op.meshes.size();
    const std::uint32_t form_id = op.item_form_id;
    const std::uint32_t equip_seq = op.equip_seq;
    char peer_buf[16] = {};
    std::memcpy(peer_buf, op.peer_id, sizeof(peer_buf));
    {
        std::lock_guard lk(g_mesh_blob_mtx);
        g_mesh_blob_queue.push_back(std::move(op));
        qsize = g_mesh_blob_queue.size();
    }
    FW_LOG("dispatch: mesh-blob enqueued peer=%s form=0x%X equip_seq=%u "
           "meshes=%zu (qsize=%zu)",
           peer_buf, form_id, equip_seq, mesh_count, qsize);
    post_wakeup_mesh_blob();
}

void drain_mesh_blob_apply_queue() {
    std::deque<PendingMeshBlob> local;
    {
        std::lock_guard lk(g_mesh_blob_mtx);
        local.swap(g_mesh_blob_queue);
    }
    if (local.empty()) {
        FW_DBG("dispatch: mesh-blob drain with empty queue — no-op");
        return;
    }

    // M9 wedge 4 v9 step 4c (PIVOT 2026-05-01 21:50 — Opzione A pragmatic):
    //   Factory + donor pattern crashed (vd format mismatch with donor
    //   shader). Pivot: skip factory entirely. Use the wire blob ONLY to
    //   derive the proper base weapon NIF path from the first mesh's
    //   bgsm path, then call the existing ghost_attach_weapon path which
    //   loads the NIF + apply_materials + attach_child_direct (proven-
    //   working for manganello / armor sync).
    //
    //   Cost: only base weapon visible (no mod-specific meshes). For PoC
    //   acceptable. Mod-mesh visibility deferred to v0.5+ (full BSVertex-
    //   Desc RE work).
    //
    //   Replacement: detach prior weapon for same peer/form first, so
    //   the legacy EQUIP_BCAST attach (which loaded "RecieverDummy.nif"
    //   from the wrong TESModel slot) is replaced by our proper NIF.
    std::size_t applied_blobs = 0;
    int total_attached = 0;
    for (auto& blob : local) {
        // 2026-05-06 LATE evening (M9 closure, PLAN B) — NIF blob
        // shortcut. If sender shipped a serialized assembled-weapon
        // tree, deserialize it via NiStream::Load and attach the root
        // to ghost's WEAPON bone. Skip all per-mesh / per-path logic.
        if (!blob.nif_blob_bytes.empty()) {
            FW_LOG("[mesh-rx] APPLY (NIF-blob) peer=%s form=0x%X "
                   "equip_seq=%u nif_bytes=%zu",
                   blob.peer_id, blob.item_form_id, blob.equip_seq,
                   blob.nif_blob_bytes.size());

            // Cleanup previous equip's deserialized roots first.
            fw::native::clear_ghost_extra_mods(blob.peer_id);

            const bool ok = fw::native::deserialize_and_attach_nif_blob(
                blob.peer_id, blob.item_form_id,
                blob.nif_blob_bytes.data(),
                blob.nif_blob_bytes.size());
            if (ok) {
                ++applied_blobs;
                FW_LOG("[mesh-rx] NIF-blob attached OK peer=%s form=0x%X",
                       blob.peer_id, blob.item_form_id);
            } else {
                FW_WRN("[mesh-rx] NIF-blob attach FAILED peer=%s form=0x%X "
                       "size=%zu — ghost weapon may be empty until next "
                       "equip", blob.peer_id, blob.item_form_id,
                       blob.nif_blob_bytes.size());
            }
            continue;  // done with this blob, skip per-mesh path
        }

        FW_LOG("[mesh-rx] APPLY peer=%s form=0x%X equip_seq=%u meshes=%zu",
               blob.peer_id, blob.item_form_id, blob.equip_seq,
               blob.meshes.size());

        // M9.w4 PROPER (v0.4.2+, Path NIF-CAPTURE, 2026-05-04 PM) —
        // detect "path-only" blob (sentinel: any mesh with vert_count=0
        // AND non-empty m_name treated as path). The sender shipped the
        // engine's actually-loaded NIF paths instead of raw geometry.
        // We replay them: first path = base weapon, rest = mod NIFs
        // attached to base. Engine handles shader/material/vd binding.
        const bool is_path_only = !blob.meshes.empty()
            && blob.meshes[0].vert_count == 0
            && !blob.meshes[0].m_name.empty();
        if (is_path_only) {
            FW_LOG("[mesh-rx] PATH-ONLY blob peer=%s form=0x%X paths=%zu",
                   blob.peer_id, blob.item_form_id, blob.meshes.size());
            for (std::size_t pi = 0; pi < blob.meshes.size(); ++pi) {
                FW_DBG("[mesh-rx]   path[%zu]='%s'", pi,
                       blob.meshes[pi].m_name.c_str());
            }

            // First path → base weapon via ghost_set_weapon (handles slot
            // tracking + replacement). Use it as a single candidate.
            const std::string& base_path = blob.meshes[0].m_name;
            const char* base_candidates[] = { base_path.c_str() };
            const bool base_ok = fw::native::ghost_set_weapon(
                blob.peer_id, blob.item_form_id, base_candidates, 1);
            if (!base_ok) {
                FW_WRN("[mesh-rx] PATH-ONLY base load FAILED path='%s' "
                       "peer=%s form=0x%X — skipping mod paths too",
                       base_path.c_str(), blob.peer_id, blob.item_form_id);
                continue;
            }
            FW_LOG("[mesh-rx] PATH-ONLY base loaded: '%s'", base_path.c_str());

            // Subsequent paths → mod NIFs attached as children of base.
            int mods_attached = 0;
            int mods_failed = 0;
            for (std::size_t pi = 1; pi < blob.meshes.size(); ++pi) {
                const std::string& mod_path = blob.meshes[pi].m_name;
                if (mod_path.empty()) continue;
                if (mod_path == base_path) continue;  // dedup against base
                if (fw::native::attach_extra_nif_to_ghost_weapon(
                        blob.peer_id, mod_path.c_str())) {
                    ++mods_attached;
                } else {
                    ++mods_failed;
                }
            }
            FW_LOG("[mesh-rx] PATH-ONLY peer=%s form=0x%X DONE base=ok "
                   "mods_attached=%d mods_failed=%d",
                   blob.peer_id, blob.item_form_id,
                   mods_attached, mods_failed);
            ++applied_blobs;
            ++total_attached;
            continue;  // skip the legacy bgsm-derived path below
        }

        // Derive base NIF path from blob's meshes via SMART bgsm pick:
        // walk all meshes, prefer the one whose bgsm matches the canonical
        // pattern "Weapons\<X>\<X>.bgsm" (folder name == file basename).
        // That's where vanilla FO4 stores the main weapon body material.
        // Sub-components (Rocket, ShotgunShell, BloodWeapon) live in
        // sibling files like "Weapons\<X>\<XComponent>.bgsm" or sub-
        // folders like "Blood\BloodWeapon.bgsm" — those don't match the
        // pattern and get skipped.
        //
        // Helper lambda: convert a bgsm path to nif path, return empty
        // string on parse failure.
        auto bgsm_to_nif = [](const std::string& bgsm) -> std::string {
            std::string s = bgsm;
            static const char kPrefix[] = "Materials\\";
            static const char kPrefixLow[] = "materials\\";
            const std::size_t plen = sizeof(kPrefix) - 1;
            if (s.size() >= plen &&
                (std::strncmp(s.c_str(), kPrefix, plen) == 0 ||
                 std::strncmp(s.c_str(), kPrefixLow, plen) == 0))
            {
                s = s.substr(plen);
            }
            const std::size_t dot = s.find_last_of('.');
            if (dot != std::string::npos) {
                s.replace(dot, std::string::npos, ".nif");
            }
            return s;
        };

        // Helper: get folder + filename pieces.
        auto split_path = [](const std::string& p, std::string& folder,
                             std::string& filename) {
            const std::size_t backslash = p.find_last_of('\\');
            if (backslash == std::string::npos) {
                folder.clear();
                filename = p;
                return;
            }
            const std::size_t prev_backslash = p.find_last_of('\\', backslash - 1);
            if (prev_backslash == std::string::npos) {
                folder = p.substr(0, backslash);
            } else {
                folder = p.substr(prev_backslash + 1, backslash - prev_backslash - 1);
            }
            filename = p.substr(backslash + 1);
        };

        // Helper: filename without extension.
        auto strip_ext = [](const std::string& fn) -> std::string {
            const std::size_t dot = fn.find_last_of('.');
            if (dot == std::string::npos) return fn;
            return fn.substr(0, dot);
        };

        // Score each mesh's bgsm path: prefer canonical pattern.
        std::string nif_path;
        std::string fallback_path;
        for (const auto& m : blob.meshes) {
            if (m.bgsm_path.empty()) continue;
            std::string candidate = bgsm_to_nif(m.bgsm_path);
            if (candidate.empty()) continue;
            if (fallback_path.empty()) fallback_path = candidate;

            // Canonical: folder name == filename without ext.
            std::string folder, filename;
            split_path(candidate, folder, filename);
            const std::string base = strip_ext(filename);
            if (!folder.empty() && !base.empty() &&
                _stricmp(folder.c_str(), base.c_str()) == 0)
            {
                nif_path = candidate;
                FW_DBG("[mesh-rx] bgsm pick: canonical match '%s' (folder="
                       "'%s' base='%s')",
                       candidate.c_str(), folder.c_str(), base.c_str());
                break;
            }
        }
        if (nif_path.empty()) nif_path = fallback_path;

        if (nif_path.empty()) {
            FW_WRN("[mesh-rx] no bgsm-derived nif path for blob (peer=%s "
                   "form=0x%X) — skip", blob.peer_id, blob.item_form_id);
            continue;
        }

        FW_LOG("[mesh-rx] bgsm-derived nif path='%s' for peer=%s form=0x%X",
               nif_path.c_str(), blob.peer_id, blob.item_form_id);

        // === Build candidate list for ghost_set_weapon ===
        //
        // Priority order (highest first):
        //   1. nif_path (smart pick: canonical "Weapons\X\X.bgsm" pattern,
        //      e.g. for 10mm pistol the bgsm "10mmPistol.bgsm" exists)
        //   2. **FOLDER-DERIVED canonical**: for each unique parent folder
        //      seen in mesh bgsms, construct "Weapons\<folder>\<folder>.nif"
        //      and add as candidate. Catches runtime-assembled weapons
        //      whose sub-components live in a folder named after the base
        //      weapon (assault rifle = MachineGun folder → MachineGun.nif,
        //      shotgun = Shotgun folder → Shotgun.nif).
        //   3. All sub-component bgsm-derived paths (last resort — these
        //      load only one part of the assembled weapon).
        //
        // ghost_set_weapon will also auto-fallback to legacy resolve_weapon
        // _nif_path if all our candidates fail.
        std::vector<std::string> candidate_paths_storage;
        candidate_paths_storage.reserve(blob.meshes.size() + 4);
        auto push_unique = [&](std::string p) {
            if (p.empty()) return;
            for (const auto& s : candidate_paths_storage) {
                if (s == p) return;
            }
            candidate_paths_storage.push_back(std::move(p));
        };

        // 1. Smart-pick winner (if any).
        push_unique(nif_path);

        // 2. Folder-derived canonical: extract unique parent folders from
        //    every mesh's bgsm, construct "<folder>\<basename>.nif" where
        //    basename = last folder component.
        for (const auto& m : blob.meshes) {
            if (m.bgsm_path.empty()) continue;
            std::string nif = bgsm_to_nif(m.bgsm_path);
            if (nif.empty()) continue;
            const std::size_t bs = nif.find_last_of('\\');
            if (bs == std::string::npos) continue;
            std::string folder_path = nif.substr(0, bs);
            // Last folder name = basename of folder_path
            const std::size_t prev_bs = folder_path.find_last_of('\\');
            std::string last_folder = (prev_bs == std::string::npos)
                ? folder_path
                : folder_path.substr(prev_bs + 1);
            if (last_folder.empty()) continue;
            std::string canonical = folder_path + "\\" + last_folder + ".nif";
            push_unique(std::move(canonical));
        }

        // 3. Per-mesh bgsm-derived (sub-component fallbacks).
        for (const auto& m : blob.meshes) {
            if (m.bgsm_path.empty()) continue;
            std::string c = bgsm_to_nif(m.bgsm_path);
            push_unique(std::move(c));
        }

        // Convert to char*[] for the API.
        std::vector<const char*> candidate_paths;
        candidate_paths.reserve(candidate_paths_storage.size());
        for (const auto& s : candidate_paths_storage) {
            candidate_paths.push_back(s.c_str());
        }

        const bool ok = fw::native::ghost_set_weapon(
            blob.peer_id, blob.item_form_id,
            candidate_paths.empty() ? nullptr : candidate_paths.data(),
            candidate_paths.size());
        if (ok) {
            ++applied_blobs;
            ++total_attached;
            FW_LOG("[mesh-rx] ghost_set_weapon OK peer=%s form=0x%X "
                   "candidates=%zu",
                   blob.peer_id, blob.item_form_id,
                   candidate_paths.size());

            // M9.w4 PROPER (v0.4.2+, Path Y, 2026-05-04 PM) — disk-loaded
            // mod NIFs. The captured mesh data tells us WHICH mods the
            // peer has equipped (via parent_placeholder = mod root name).
            // For each, derive a candidate disk path and load via the
            // engine's nif_load_by_path — engine does shader binding
            // naturally so no vertex format mismatch crash (which doomed
            // factory-reconstruct + donor-shader in v0.4.0 + v0.4.2 P3.1).
            //
            // Convert blob.meshes (PendingMeshRecord) → CapturedMeshView.
            std::vector<fw::native::CapturedMeshView> views;
            views.reserve(blob.meshes.size());
            for (const auto& m : blob.meshes) {
                fw::native::CapturedMeshView v{};
                v.m_name             = m.m_name.c_str();
                v.parent_placeholder = m.parent_placeholder.c_str();
                v.positions          = m.positions.empty()
                                          ? nullptr : m.positions.data();
                v.indices            = m.indices.empty()
                                          ? nullptr : m.indices.data();
                v.vert_count         = m.vert_count;
                v.tri_count          = m.tri_count;
                v.local_transform    = m.local_transform;
                views.push_back(v);
            }

            // M9.w4 PROPER (v0.4.2+, RESMGR-LOOKUP, 2026-05-04 PM) —
            // walk the engine's NIF resource manager (singleton at
            // *qword_1430DD618), find each captured parent_placeholder
            // by m_name match, refbump-share the BSFadeNode, attach
            // to ghost weapon root. Engine handles shader/material/vd
            // binding because the node was loaded by the engine itself
            // — no factory reconstruction, no donor shader crash.
            //
            // The BSResource::EntryDB<BSModelDB> singleton holds ALL
            // pre-loaded NIFs including weapon mod sub-NIFs. Once the
            // local player has equipped a modded weapon, every mod's
            // BSFadeNode is in the cache, keyed by m_name. We just
            // look it up and share-attach to the ghost.
            // Hybrid: resmgr-share PRIMARY + disk-load FALLBACK.
            // Receiver's local resmgr only contains NIFs the receiver's
            // own engine has loaded; mod NIFs never seen on receiver
            // require disk fetch via nif_load_by_path (engine then caches
            // them for future use).
            //
            // Derive base folder from slot's loaded nif_path for disk
            // candidate paths.
            std::string base_folder;
            {
                // ghost_set_weapon stored the loaded path; we re-read it
                // by calling find via captured base bgsm. Already done by
                // attach_mod_nifs_via_disk path; here we replicate to
                // avoid that function's overhead.
                std::size_t bs = nif_path.find_last_of('\\');
                if (bs != std::string::npos) {
                    base_folder = nif_path.substr(0, bs);
                }
            }

            // 2026-05-06 evening — UNCONDITIONALLY clear extra_mods at the
            // start of every blob receive. Was: gated behind `any_mod` so
            // a blob carrying ZERO mod descriptors didn't trigger cleanup.
            // Bug exposed by live test: user equipped 10mm-with-silencer,
            // then switched to a different 10mm-without-silencer instance
            // from inventory. Second blob had no mods → any_mod=false →
            // clear skipped → silencer from first equip remained attached
            // to the cached base. Now we always clear; the per-blob
            // attach loop below re-attaches whatever mods THIS blob
            // describes (possibly zero). User reported: "cambio arma
            // senza silenziatore ma il silenziatore ora permane".
            fw::native::clear_ghost_extra_mods(blob.peer_id);
            bool any_mod = false;
            for (const auto& m : blob.meshes) {
                if (!m.parent_placeholder.empty()) { any_mod = true; break; }
            }
            if (any_mod) {
                fw::native::dump_ghost_weapon_subtree(blob.peer_id, 6);
                // 2026-05-06 evening — CULL DISABLED. Was culling EVERY
                // BSGeometry leaf inside the base BSFadeNode → killed
                // not just stock-mod-default leaves but also the
                // ALWAYS-VISIBLE body parts (receiver casting, slide,
                // frame, hand-grip stock). User reported: "manca la
                // base dove si attaccano, la pistola non c'è".
                //
                // The original intent was to hide stock defaults inside
                // placeholder NiNodes that were going to be REPLACED by
                // mod attachments (e.g. cull the default-short-barrel
                // BSTriShape under "PistolMuzzle" before attaching the
                // suppressor mod). But our cull walker treated all
                // base-stock leaves uniformly — no distinction between
                // "always-visible body part" vs "default that mod
                // replaces". To do this properly we'd need per-
                // placeholder cull info: only cull leaves whose parent
                // placeholder is targeted by an incoming mod.
                //
                // For now: NO cull. Mods overlay on full stock weapon.
                // Some defaults may show through under mods (e.g.
                // default-short-barrel sticking out from suppressor) —
                // visually imperfect but at least the body is visible.
                // Selective placeholder-aware cull is a follow-up.
                //
                // const int culled = fw::native::
                //     cull_base_geometry_for_modded_weapon(blob.peer_id);
                // FW_LOG("[mesh-rx] base-cull peer=%s form=0x%X "
                //        "culled %d BSGeometry leaves (stock geom hidden, "
                //        "mods attach on top)",
                //        blob.peer_id, blob.item_form_id, culled);
            }

            // === M9 closure (Phase 1, 2026-05-06) — OMOD-derived path attach ===
            //
            // 2026-05-06 PM — DISABLED. The OMOD-derive path attaches
            // every mod as a direct child of base_root with no
            // positioning info (no slot placeholder, no transform).
            // The pre-existing resmgr-share path (above this block) does
            // proper placeholder-aware attach via slot_name +
            // find_node_by_name_w4 against the loaded base, with the
            // sender's captured local_transform.
            //
            // 2026-05-06 PM landings that make resmgr-share self-sufficient:
            //   • name-reader bug fixed (was reading wrong offset → ALL
            //     placeholder lookups silently failed → fell back to
            //     attaching at base_root → "tutte uguali e troppo moddate").
            //   • cull walker stops at BSFadeNode/BSLeafAnimNode for
            //     non-root nodes (was descending into mod children and
            //     culling THEIR geometry → growing-cull-count bug).
            //   • clone_nif_subtree replaced with vt[26] dispatch — every
            //     peer's loaded base + each attached mod is now an
            //     independent deep-clone (engine-grade, with GPU buffer
            //     AddRef on BSTriShape leaves). No more cache-share
            //     mutation across peers / across equips.
            //
            // Keep OMOD-derive gated off as a clean default. If the live
            // test reveals MISSING mods (e.g. mods whose geometry was
            // capture-culled at sender side), re-enable as a transform-
            // less fallback below.
            int mods_omod_attached = 0;
            std::unordered_set<std::string> seen_omod_paths;
            std::uint32_t peer_omod_forms[32]{};
            const std::uint8_t peer_omod_count = 0;  // FORCED 0 — keep declaration for log compat
            (void)seen_omod_paths;
            (void)peer_omod_forms;
            // const std::uint8_t peer_omod_count =
            //     fw::native::snapshot_peer_omod_forms_public(
            //         blob.peer_id, peer_omod_forms, 32);
            if (peer_omod_count > 0) {
                FW_LOG("[mesh-rx] OMOD-derive peer=%s has %u OMODs to resolve",
                       blob.peer_id,
                       static_cast<unsigned>(peer_omod_count));
                // 2026-05-06 v2 — self-attach guard. Some OMODs (the
                // "stock" / default components) have their TESModel.modelPath
                // pointing to the BASE weapon NIF itself rather than a
                // distinct mod NIF. Live test caught
                //   OMOD 0x148337 → 'Weapons\\10mmPistol\\10MMPistol.nif'
                // which equals the loaded base; nif_load_by_path returns
                // the cached base node, attach_child_direct then makes the
                // base its OWN child → cycle in scene graph → AV on next
                // render walk (the user's "saw it for half a second then
                // crashed" symptom). Detect via case-insensitive equality
                // against the slot's stored nif_path.
                auto path_eq_ci = [](const char* a, const char* b) -> bool {
                    if (!a || !b) return false;
                    while (*a && *b) {
                        char ca = *a, cb = *b;
                        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca - 'A' + 'a');
                        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb - 'A' + 'a');
                        if (ca != cb) return false;
                        ++a; ++b;
                    }
                    return *a == 0 && *b == 0;
                };

                for (std::uint8_t i = 0; i < peer_omod_count; ++i) {
                    const std::uint32_t fid = peer_omod_forms[i];
                    if (fid == 0) continue;
                    const char* path =
                        fw::native::resolve_omod_model_path(fid);
                    if (!path || !path[0]) {
                        FW_DBG("[mesh-rx]   OMOD 0x%X: no NIF (numeric-only "
                               "or unresolved)", fid);
                        continue;
                    }
                    // Self-attach guard: skip if this OMOD's modelPath is
                    // the base weapon NIF itself. Such OMODs are stock
                    // components that the engine bakes into the base —
                    // there's nothing extra to attach.
                    if (!nif_path.empty() && path_eq_ci(path, nif_path.c_str())) {
                        FW_DBG("[mesh-rx]   OMOD 0x%X path='%s' EQUALS base — "
                               "stock mod, skip (would self-attach)",
                               fid, path);
                        continue;
                    }
                    // Dedupe — same NIF path attached more than once would
                    // waste refbumps and pile up duplicate geometry.
                    if (!seen_omod_paths.insert(path).second) {
                        FW_DBG("[mesh-rx]   OMOD 0x%X path='%s' DUP — skip",
                               fid, path);
                        continue;
                    }
                    if (fw::native::attach_extra_nif_to_ghost_weapon(
                            blob.peer_id, path)) {
                        ++mods_omod_attached;
                        FW_LOG("[mesh-rx]   OMOD 0x%X path='%s' ATTACHED",
                               fid, path);
                    } else {
                        FW_DBG("[mesh-rx]   OMOD 0x%X path='%s' attach FAILED",
                               fid, path);
                    }
                }
                FW_LOG("[mesh-rx] OMOD-derive: %d/%u attached for peer=%s "
                       "(form=0x%X)",
                       mods_omod_attached,
                       static_cast<unsigned>(peer_omod_count),
                       blob.peer_id, blob.item_form_id);
            }

            // 2026-05-05 — pre-pass: group meshes by parent_placeholder
            // and pick a BEST representative per group. The criteria:
            // a mesh whose bgsm_path starts with "Materials\\Weapons\\"
            // gives us the actual weapon-mod NIF filename (e.g.
            // "Materials\\Weapons\\10mmPistol\\10mmReflexSight.BGSM"
            // → derive "Weapons\\10mmPistol\\10mmReflexSight.nif"),
            // whereas a leaf using an EFFECTS material like the reflex
            // glass overlay (Materials\\Effects\\ReflexGlass10mm.BGSM
            // .BGEM) is a sub-mesh useless for path derivation.
            //
            // Without this pre-pass the simple "first wins" dedupe was
            // grabbing whatever leaf appeared first in clone-factory
            // order and missing the canonical mod NIF.
            struct BestMod {
                const PendingMeshRecord* mesh        = nullptr;
                bool                     weapons_bgsm = false;
            };
            std::unordered_map<std::string, BestMod> mods_by_parent;
            mods_by_parent.reserve(blob.meshes.size());
            int mods_dup = 0;
            for (const auto& m : blob.meshes) {
                if (m.parent_placeholder.empty()) continue;
                auto& slot = mods_by_parent[m.parent_placeholder];
                // Case-insensitive prefix check for "Materials\\Weapons\\".
                auto starts_ci = [](const std::string& s, const char* pre) {
                    const std::size_t pl = std::strlen(pre);
                    if (s.size() < pl) return false;
                    for (std::size_t i = 0; i < pl; ++i) {
                        char a = s[i]; char b = pre[i];
                        if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
                        if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
                        if (a != b) return false;
                    }
                    return true;
                };
                const bool this_is_weapons =
                    starts_ci(m.bgsm_path, "Materials\\Weapons\\");
                if (!slot.mesh ||
                    (this_is_weapons && !slot.weapons_bgsm)) {
                    if (slot.mesh) ++mods_dup;
                    slot.mesh = &m;
                    slot.weapons_bgsm = this_is_weapons;
                } else {
                    ++mods_dup;
                }
            }

            // Helper: derive NIF path from a bgsm_path. Bethesda's
            // weapon mod authoring puts the NIF and the BGSM next to
            // each other with the same basename — only the extension
            // differs. We strip the leading "Materials\\" subfolder and
            // swap the trailing extension. Returns empty on
            // un-derivable input.
            auto derive_nif_from_bgsm =
                [](const std::string& bgsm) -> std::string {
                if (bgsm.size() < 11) return {};
                // Case-insensitive strip of "Materials\\".
                std::string p;
                {
                    std::string head = bgsm.substr(0, 10);
                    std::string lower;
                    lower.reserve(10);
                    for (char c : head) {
                        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
                        lower.push_back(c);
                    }
                    if (lower == "materials\\") p = bgsm.substr(10);
                    else                         p = bgsm;
                }
                // Replace trailing extension. Bethesda chains like
                // "*.BGSM.BGEM" exist — take the LAST dot's content
                // and swap if it's BGSM/BGEM/BGSM.BGEM/etc.
                auto rfind_ext = p.rfind('.');
                if (rfind_ext == std::string::npos) return {};
                std::string ext = p.substr(rfind_ext + 1);
                // lowercase
                for (auto& c : ext) {
                    if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
                }
                if (ext != "bgsm" && ext != "bgem") return {};
                return p.substr(0, rfind_ext) + ".nif";
            };

            int mods_share_attached  = 0;
            int mods_bgsm_attached   = 0;
            int mods_disk_attached   = 0;
            int mods_total_miss      = 0;
            for (const auto& [parent, info] : mods_by_parent) {
                const auto& m = *info.mesh;

                // Step 1: try resmgr-share (free if already cached).
                // - parent_placeholder = mod NIF root m_name → resmgr KEY
                // - slot_name          = base NIF slot name → attach point
                // - local_transform    = sender-captured leaf transform
                //                        (written to mod node so it lands
                //                        at the same offset within slot)
                void* cached_node = fw::native::find_loaded_nif_by_m_name(
                    m.parent_placeholder.c_str());
                if (cached_node) {
                    if (fw::native::attach_extra_node_to_ghost_weapon(
                            blob.peer_id, cached_node,
                            m.parent_placeholder.c_str(),
                            m.slot_name.empty() ? nullptr : m.slot_name.c_str(),
                            m.local_transform)) {
                        ++mods_share_attached;
                        continue;
                    }
                }

                // Step 2: bgsm-derived disk path. Bethesda-naming
                // convention says the mod NIF and its BGSM share a
                // basename — so converting the bgsm_path into a NIF
                // path lets us locate the actual file even when the
                // mod's runtime m_name (parent_placeholder) doesn't
                // match the file basename — e.g. when the engine
                // renames the loaded BSFadeNode root via OMOD INNT
                // ("10mmReflexSight.nif" loads with m_name set to
                // "10mmReflexDot" at runtime, so resmgr-by-name lookup
                // for "10mmReflexDot" misses while the file IS
                // available on disk under its real basename).
                //
                // SKIP if the derived path equals the loaded base — the
                // sender ships parent_placeholder="Pistol10mmReceiver"
                // for the 10mm receiver mod whose bgsm_path also points
                // at "10mmPistol.bgsm" (= base file). Loading that
                // would just re-load the base nested inside itself.
                if (!m.bgsm_path.empty()) {
                    std::string derived = derive_nif_from_bgsm(m.bgsm_path);
                    bool same_as_base = false;
                    if (!derived.empty() && !nif_path.empty()) {
                        // Case-insensitive match against the loaded
                        // base path.
                        if (derived.size() == nif_path.size()) {
                            same_as_base = true;
                            for (std::size_t i = 0; i < derived.size(); ++i) {
                                char a = derived[i], b = nif_path[i];
                                if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
                                if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
                                if (a != b) { same_as_base = false; break; }
                            }
                        }
                    }
                    if (!derived.empty() && !same_as_base) {
                        // 2026-05-06 evening — pass slot_name so the
                        // disk-loaded mod routes to the right placeholder
                        // (same multi-tier resolver as resmgr-share path).
                        const char* slot_cstr = m.slot_name.empty()
                            ? nullptr
                            : m.slot_name.c_str();
                        if (fw::native::attach_extra_nif_to_ghost_weapon(
                                blob.peer_id, derived.c_str(),
                                slot_cstr)) {
                            ++mods_bgsm_attached;
                            continue;
                        }
                    }
                }

                // Step 3: heuristic disk fallback — try multiple path
                // patterns. The first that loads is attached. Cache
                // populates as side effect (next equip of same combo
                // will hit step 1 or step 2).
                if (base_folder.empty()) {
                    ++mods_total_miss;
                    continue;
                }
                static const char* const kSubfolders[] = {
                    "",                        // <folder>\<name>.nif
                    "Mods\\",
                    "Mods\\Barrels\\",
                    "Mods\\Barrel\\",
                    "Mods\\Muzzles\\",
                    "Mods\\Muzzle\\",
                    "Mods\\Sights\\",
                    "Mods\\Sight\\",
                    "Mods\\Iron\\",
                    "Mods\\Receivers\\",
                    "Mods\\Receiver\\",
                    "Mods\\Magazines\\",
                    "Mods\\Magazine\\",
                    "Mods\\Mag\\",
                    "Mods\\Grips\\",
                    "Mods\\Grip\\",
                    "Mods\\Stocks\\",
                    "Mods\\Stock\\",
                };
                bool disk_ok = false;
                {
                    const char* slot_cstr = m.slot_name.empty()
                        ? nullptr
                        : m.slot_name.c_str();
                    for (const char* sub : kSubfolders) {
                        std::string p = base_folder + "\\" + sub +
                                        m.parent_placeholder + ".nif";
                        if (fw::native::attach_extra_nif_to_ghost_weapon(
                                blob.peer_id, p.c_str(), slot_cstr)) {
                            disk_ok = true;
                            ++mods_disk_attached;
                            break;
                        }
                    }
                }
                if (!disk_ok) ++mods_total_miss;
            }
            FW_LOG("[mesh-rx] resmgr-hybrid: peer=%s form=0x%X "
                   "share=%d bgsm=%d disk=%d miss=%d dup=%d (of %zu meshes)",
                   blob.peer_id, blob.item_form_id,
                   mods_share_attached, mods_bgsm_attached,
                   mods_disk_attached,
                   mods_total_miss, mods_dup, blob.meshes.size());

            // ATTEMPT #6 diagnostic — see scene_inject.cpp.
            // Dump the WEAPON state right after we finished attaching
            // all mods for this blob. This is the canonical "what does
            // the engine actually see" snapshot for this equip cycle.
            fw::native::dump_weapon_attach_state("post-mesh-blob-attach");

            /* Path Y disk-load (kept for fallback diagnostic).
            const int n_loaded =
                fw::native::attach_mod_nifs_via_disk(
                    blob.peer_id, blob.item_form_id,
                    views.data(), views.size());
            FW_LOG("[mesh-rx] mod-nif: peer=%s form=0x%X loaded=%d of "
                   "%zu candidate meshes (grouped by parent_placeholder)",
                   blob.peer_id, blob.item_form_id,
                   n_loaded, views.size());
            */

            /* DISABLED: factory-reconstruct path (Phase 3 base).
            // Useful for diagnostics: logs what WOULD be reconstructed
            // from raw geometry. Disabled until shader binding (Phase 3.2)
            // resolves the vertex format mismatch that blocks visibility.
            const int n_attached =
                fw::native::attach_captured_meshes_to_ghost_weapon(
                    blob.peer_id, blob.item_form_id,
                    views.data(), views.size());
            FW_LOG("[mesh-rx] reconstruct: peer=%s form=0x%X attached=%d "
                   "of %zu candidate meshes",
                   blob.peer_id, blob.item_form_id,
                   n_attached, views.size());
            */
        } else {
            FW_WRN("[mesh-rx] ghost_set_weapon FAILED peer=%s form=0x%X "
                   "(no candidate loaded; existing slot left untouched)",
                   blob.peer_id, blob.item_form_id);
        }
    }
    FW_LOG("dispatch: drained %zu mesh-blob ops, applied=%zu blobs (pivot to "
           "NIF-load path)", local.size(), applied_blobs);
}

void drain_equip_apply_queue() {
    std::deque<PendingEquipOp> local;
    {
        std::lock_guard lk(g_equip_mtx);
        local.swap(g_equip_queue);
    }
    if (local.empty()) {
        FW_DBG("dispatch: equip drain with empty queue — no-op");
        return;
    }

    // We're on the main thread. Each equip op resolves the item form via
    // lookup_by_form_id and dispatches to the appropriate attach path:
    //
    //   1. Try ARMOR first — walks TESObjectARMO addon array → ARMA →
    //      TESModel → BSFixedString. Returns false if the form isn't ARMO
    //      (no addon array at +0x2A8) — silently, no AV.
    //   2. If ARMOR returns false AND ghost is live, try WEAPON — walks
    //      TESObjectWEAP TESModel directly (no addon array). Returns
    //      false if it isn't WEAP either, or if the path doesn't match
    //      the "Weapons\\" heuristic.
    //
    // The dual-attempt avoids needing to RE the FormType byte for ARMO vs
    // WEAP on this build (FO4 1.11.191 next-gen has a remapped formType
    // table — see door_hook for similar reasoning). The per-form struct
    // walks act as their own type-detection.
    //
    // Boot race note: if ghost isn't spawned yet, BOTH ghost_attach_armor
    // and ghost_attach_weapon will queue (one in armor's pending queue,
    // one in weapon's pending queue). On ghost spawn, the right-type
    // flush succeeds and the wrong-type flush silently fails — net cost
    // a few tens of bytes RAM during boot. Trade-off accepted to keep
    // the dispatcher form-agnostic.
    //
    // No ApplyingRemoteGuard needed here — we are NOT calling any engine
    // function that the equip_hook detour intercepts. Both attach paths
    // use g_r.nif_load_by_path + g_r.attach_child_direct, which are
    // NIF/scene primitives unrelated to ActorEquipManager.
    std::size_t applied_ok = 0, failed = 0;
    for (const auto& op : local) {
        // EquipOpKind: 1=EQUIP, 2=UNEQUIP. See net/protocol.h.
        const bool is_equip = (op.kind == 1);

        // Pass 1 — try as ARMOR.
        // M9.w2 PROPER (v10): pass effective_priority from the wire so
        // resolve_armor_nif_path's PrioritySelect filter picks the right
        // ARMA tier (Lite/Mid/Heavy) when OMOD upgrade is attached.
        bool ok = is_equip
            ? fw::native::ghost_attach_armor(op.peer_id, op.item_form_id,
                                              op.effective_priority)
            : fw::native::ghost_detach_armor(op.peer_id, op.item_form_id);

        // Pass 2 — if armor returned false, try as WEAPON. The armor
        // path returning false means either:
        //   (a) Form isn't ARMO (struct walk failed, path didn't match
        //       armor heuristics) — weapon attempt is the right next step.
        //   (b) Ghost not spawned yet (form was queued for armor flush
        //       on next ghost spawn) — weapon attempt will ALSO queue
        //       (harmlessly; see boot-race note above).
        //   (c) Genuine attach failure (NIF load error) — weapon attempt
        //       will likely also fail at the same step; logs both errors,
        //       not great but not harmful.
        // Cost of always attempting weapon on armor-false is one extra
        // form lookup + offset probe. Cheap.
        //
        // M9 w4 v9.1: route weapons through the unified state machine.
        //   - EQUIP: ghost_set_weapon with NO candidate list (forces use
        //            of legacy resolve_weapon_nif_path, which after the
        //            Dummy filter usually picks the proper NIF).
        //   - UNEQUIP: ghost_clear_weapon with expected_form_id guard
        //              (no-op if peer has already switched to a different
        //              weapon by the time UNEQUIP arrives).
        //
        // Mesh-blob path (drain_mesh_blob_apply_queue) provides the high-
        // priority candidate list for the SAME form_id. State machine's
        // downgrade protection ensures placeholder paths from this
        // path never overwrite the proper paths from mesh-blob.
        if (!ok) {
            if (is_equip) {
                // 2026-05-07 — Receiver applies each EQUIP_BCAST normally.
                // The off-by-one render lag (first equip displays as
                // stock or as previous weapon) is fixed sender-side via
                // the auto re-equip cycle in equip_hook.cpp: 50 ms after
                // the user's equip, the sender fires UnequipObject +
                // EquipObject for the same form. Receiver gets EQUIP-X,
                // UNEQUIP-X, EQUIP-X on the wire and applies each in
                // order — the second EQUIP-X is the "magic re-equip"
                // that renders the modded weapon correctly on the ghost.
                ok = fw::native::ghost_attach_assembled_weapon(
                    op.peer_id, op.item_form_id,
                    op.omod_form_ids, op.omod_count);
                if (!ok) {
                    FW_DBG("[equip-drain] name-match failed for peer=%s "
                           "form=0x%X — falling back to ghost_set_weapon",
                           op.peer_id, op.item_form_id);
                    ok = fw::native::ghost_set_weapon(
                        op.peer_id, op.item_form_id,
                        /*no candidates*/ nullptr, 0);
                }
            } else {
                // 2026-05-07 — TRANSIENT-SWAP-SLOT FILTER.
                //
                // The engine's ActorEquipManager internally fires
                //   Equip(new, slot=DefaultEquipSlot)
                //   Unequip(new, slot=0x4334D, force=1)   ← THIS LINE
                //   Unequip(old, slot=0x4334D)
                // as part of the "swap-into-slot" sequence. The middle
                // Unequip is targeting a TRANSIENT internal slot
                // (form id 0x4334D, the kReadiedWeapon BGSEquipSlot).
                // It does NOT mean "the player no longer has this
                // weapon equipped" — the engine immediately routes the
                // ready-state into the real slot afterwards.
                //
                // Pre-fix, our ghost_clear_weapon was matching this
                // Unequip's form_id against our slot's form_id and
                // wiping the freshly-attached weapon, leaving the
                // ghost empty. Live test 2026-05-07 06:34:47 showed
                // EQUIP 0x4822 followed 7ms later by UNEQUIP 0x4822
                // slot=0x4334D, instantly cancelling the visible weapon.
                //
                // Filter: Unequip with slot_form_id == 0x4334D is a
                // transient bookkeeping op, ignore it on the receiver.
                // Real "player put the weapon away" UNEQUIPs use
                // slot_form_id = 0x0 (DefaultEquipSlot) and survive
                // this filter.
                constexpr std::uint32_t TRANSIENT_SWAP_SLOT = 0x4334D;
                if (op.slot_form_id == TRANSIENT_SWAP_SLOT) {
                    FW_DBG("[equip-drain] skip transient-swap UNEQUIP "
                           "peer=%s form=0x%X slot=0x%X (engine internal)",
                           op.peer_id, op.item_form_id, op.slot_form_id);
                    ok = true;  // treat as handled — no action needed
                } else {
                    ok = fw::native::ghost_clear_weapon(
                        op.peer_id, op.item_form_id);
                }
            }
        }

        if (ok) ++applied_ok; else ++failed;
    }
    FW_LOG("dispatch: drained %zu equip ops (applied=%zu failed=%zu)",
           local.size(), applied_ok, failed);
}

void drain_door_apply_queue() {
    std::deque<PendingDoorOp> local;
    {
        std::lock_guard lk(g_door_mtx);
        local.swap(g_door_queue);
    }
    if (local.empty()) {
        FW_DBG("dispatch: door drain with empty queue — no-op");
        return;
    }

    // Main thread + ApplyingRemoteGuard scope so the door_hook detour
    // sees tls_applying_remote=true on the re-entry caused by our own
    // call to engine_activate (Activate worker fires its anim graph
    // notify which may re-enter the same hook). Without the guard we'd
    // echo the remote door op back to the server.
    fw::hooks::ApplyingRemoteGuard guard;

    std::size_t applied_ok = 0, failed = 0;
    for (const auto& op : local) {
        const bool ok = fw::engine::apply_door_op_to_engine(
            op.door_form_id,
            op.door_base_id,
            op.door_cell_id);
        if (ok) ++applied_ok; else ++failed;
    }
    FW_LOG("dispatch: drained %zu door ops (applied=%zu failed=%zu)",
           local.size(), applied_ok, failed);
}

void drain_lock_apply_queue() {
    std::deque<PendingLockOp> local;
    {
        std::lock_guard lk(g_lock_mtx);
        local.swap(g_lock_queue);
    }
    if (local.empty()) {
        FW_DBG("dispatch: lock drain with empty queue — no-op");
        return;
    }

    // Same guard pattern as door drain: receiver-side apply
    // (sub_141158640) recurses into ForceUnlock/ForceLock — our hooks
    // see tls_applying_remote=true and skip broadcasting back, so the
    // remote op doesn't echo to the server.
    fw::hooks::ApplyingRemoteGuard guard;

    std::size_t applied_ok = 0, failed = 0;
    for (const auto& op : local) {
        const bool ok = fw::engine::apply_lock_op_to_engine(
            op.lock_form_id,
            op.lock_base_id,
            op.lock_cell_id,
            op.locked != 0);
        if (ok) ++applied_ok; else ++failed;
    }
    FW_LOG("dispatch: drained %zu lock ops (applied=%zu failed=%zu)",
           local.size(), applied_ok, failed);
}

// Build 65.c.47 WEDGE3 — KILL-SWITCH for the whole non-owner death apply.
// Default true. Flip to false to fully disable the corpse-on-non-owner path
// (the drain becomes a no-op that still clears the queue). Paired with the
// owner-emit switch of the same name in kill_hook.cpp.
static constexpr bool kDeathSyncEnabled = true;

void drain_npc_death_apply_queue() {
    std::deque<PendingNPCDeath> local;
    {
        std::lock_guard lk(g_npc_death_mtx);
        local.swap(g_npc_death_queue);
    }
    if (local.empty()) {
        FW_DBG("dispatch: NPC death drain with empty queue — no-op");
        return;
    }
    if (!kDeathSyncEnabled) {
        FW_LOG("dispatch: NPC death drain — kDeathSyncEnabled=false, dropping %zu",
               local.size());
        return;
    }

    // ApplyingRemoteGuard so the engine Actor::Kill we invoke below re-enters
    // kill_hook::detour_kill with applying_remote()==true → the detour bails
    // WITHOUT re-reporting to the server (no echo loop). Same TLS flag shared
    // by door/lock/pickup/container apply paths.
    fw::hooks::ApplyingRemoteGuard guard;

    std::size_t killed = 0, skipped = 0, dedup = 0;
    for (const auto& op : local) {
        const std::uint32_t fid = op.form_id;
        if (fid == 0 || fid == 0xFFFFFFFFu || fid == fw::offsets::PLAYER_FORMID) {
            ++skipped;
            continue;   // never the player; never a sentinel
        }

        // a. resolve the mirror Actor. Null → not loaded locally; nothing to
        //    do (there is no live mirror to corpse on this client).
        void* actor = fw::engine::lookup_by_form_id(fid);
        if (!actor) {
            FW_DBG("dispatch: NPC death fid=0x%X — mirror not loaded, skip", fid);
            ++skipped;
            continue;
        }

        // c. idempotency — a re-delivered death must not double-kill. Check
        //    BEFORE the engine call. (Step c per spec; done before b/d/e/f so a
        //    retransmit is a pure no-op.)
        if (g_killed_fids.find(fid) != g_killed_fids.end()) {
            FW_DBG("dispatch: NPC death fid=0x%X — already killed, idempotent skip", fid);
            ++dedup;
            continue;
        }

        // b. mark the fid dying — STICKY so the c.41b keyframe machine never
        //    re-keyframes the corpse while the async Kill's KnockState bits lag.
        fw::hooks::mark_dying(fid);

        // d. un-keyframe so the body can ragdoll (a Keyframed body can't flop).
        fw::engine::set_actor_motion_dynamic(actor);

        // e. (cheap) pin the corpse at the synced death pos — deadlock-safe
        //    pure memory write (no cell-grid lock). Best-effort.
        fw::engine::apply_npc_pos_raw(actor, op.pos_x, op.pos_y, op.pos_z);

        // f. KILL the mirror via the engine's own Actor::Kill (killer=null;
        //    minimal build = no directional impulse). SEH-caged inside
        //    kill_actor. The ApplyingRemoteGuard above suppresses the echo.
        const bool ok = fw::engine::kill_actor(actor, /*killer=*/nullptr);
        g_killed_fids.insert(fid);   // latch even on a failed call — a retry
                                     // would hit the same engine state; idempotent.
        if (ok) ++killed; else ++skipped;
        FW_LOG("dispatch: NPC death APPLIED fid=0x%X killer=0x%X pos=(%.1f,%.1f,%.1f) ok=%d",
               fid, op.killer_form_id, op.pos_x, op.pos_y, op.pos_z, ok ? 1 : 0);
    }
    FW_LOG("dispatch: drained %zu NPC deaths (killed=%zu skipped=%zu dedup=%zu)",
           local.size(), killed, skipped, dedup);
}

void drain_npc_state_apply_queue() {
    std::deque<PendingNPCStateEntry> local;
    {
        std::lock_guard lk(g_npc_mtx);
        local.swap(g_npc_queue);
    }
    if (local.empty()) {
        // High-frequency queue — empty drains are normal between bursts.
        return;
    }

    // B6.6w5 REWIRED — POS-ONLY apply via engine::apply_npc_pos which
    // calls Actor::vt[202] (sub_140C60630) with a3=0. Sets the TLS
    // bypass flag via ApplyingRemoteGuard so our 2 pos hooks
    // (ghost_ai_pos_belt, ghost_ai_actor_setpos) passthrough instead
    // of bail. Receiver-side pos write reaches Actor+0xD0 + NIF root.
    //
    // Yaw + anim_state apply DEFERRED — would need separate engine fn
    // resolution + anim graph setter sync. For B.1 we just sync pos.
    //
    // Idempotent and main-thread-safe (per
    // re/B6.6w5_vt202_unknowns.md).
    std::size_t applied = 0, missed = 0;
    std::size_t ct_applied = 0, ct_missed = 0;
    for (const auto& e : local) {
        void* actor = fw::engine::lookup_by_form_id(e.form_id);
        if (!actor) {
            ++missed;
            continue;
        }
        if (e.apply_flags & 0x01) {
            const bool ok = fw::engine::apply_npc_pos(
                actor, e.pos_x, e.pos_y, e.pos_z);
            if (ok) ++applied; else ++missed;
        }
        // Build 64 (2026-05-25) — combat_target apply BUILD64_DISABLED.
        //
        // Under MVP-A (re/BUILD64_strategy/STRATEGY.md) the client does
        // not drive cross-client combat. Vanilla engine AI picks the
        // local PC as the hostile target on each client independently.
        // The wire path still carries combat_target_form_id (cached for
        // potential future use) but we never apply it.
        //
        // The trigger in client.cpp (NPC_STATE_BCAST handler) no longer
        // sets apply_flags bit 0x02. This check is belt-and-braces — if
        // some future code path enqueues with the bit set, we ignore it.
        if ((e.apply_flags & 0x02) && e.combat_target_form_id != 0) {
            (void)e;  // BUILD64_DISABLED — apply_npc_combat_target skipped
            ++ct_missed;  // count as missed so logs reveal stragglers
        }
    }
    FW_DBG("dispatch: drained %zu npc entries (pos applied=%zu missed=%zu, "
           "combat_target applied=%zu missed=%zu)",
           local.size(), applied, missed, ct_applied, ct_missed);
}

// Build 65.c.10 — drain owner-driven STATE_FROM_OWNER. Pos-only apply
// via the same `engine::apply_npc_pos` primitive that powers the legacy
// NPC_STATE_BCAST drain — proven main-thread-safe via Actor::vt[202]
// + ApplyingRemoteGuard TLS flag (motion hooks passthrough on it).
//
// Cautious guards:
//   - Skip ghost proxy fid (we never apply to our own ghost actor).
//   - Skip local PC fid (0x14).
//   - Skip if `is_owner_of(fid)` — we are the authority for that NPC
//     and we already run vanilla AI; applying a stale relay onto
//     ourselves would teleport us backward.
//   - lookup_by_form_id null → actor not loaded on this client; drop.
//   - All Actor accesses sit behind the SEH cage inside apply_npc_pos.
// Build 65.c.18 — SEH-safe InCombat flag setter. File-local helper because
// MSVC forbids `__try` in functions with unwind-required objects (we use
// std::deque + std::lock_guard in the drain). Same pattern as
// `safe_force_in_combat_flag` in npc_ai_suppress.cpp.
static void seh_set_actor_in_combat(void* actor) noexcept {
    if (!actor) return;
    __try {
        auto* const flags = reinterpret_cast<std::uint32_t*>(
            reinterpret_cast<std::uint8_t*>(actor) + 0x2D0);
        *flags |= 0x4000u;   // ACTOR_FLAG_IN_COMBAT
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // actor torn down between lookup and write. No-op.
    }
}

// Build 65.c.22 + c.23 — Unified owner-state cache (non-owner side).
//
// c.22 — InCombat-flag propagation: drain stores latest anim_state,
//   detour reads at 60 Hz and re-OR's bit 0x4000 on Actor+0x2D0 because
//   the engine perception walker clears it inside orig Update_PerFrame
//   when no local enemy is in perception range. Without this, behavior
//   tree drives idle/patrol anim despite combat being authoritative
//   on the owner side.
//
// c.23 — pos+yaw interpolation: drain ALSO records prev/cur snapshot
//   per fid. Detour reads via get_interpolated_owner_state and linearly
//   extrapolates from (prev, cur) to "now", producing a smooth 60 Hz
//   visual instead of the 10 Hz snap-teleport pattern Agent 1 forensics
//   showed as the visible flicker.
//
// Single struct + single mutex keeps the c.22 and c.23 reads atomic w.r.t.
// each other (so anim_state and pos are consistent in the same frame).
struct LatestOwnerStateEntry {
    // Current snapshot (latest STATE_FROM_OWNER entry processed by drain).
    float         cur_pos_x;
    float         cur_pos_y;
    float         cur_pos_z;
    float         cur_yaw_rad;
    std::uint8_t  anim_state;
    std::uint64_t cur_ts_ms;          // GetTickCount64() at drain time

    // Previous snapshot (one drain cycle ago). Used as the extrapolation
    // "origin" — the line from prev to cur is the actor's velocity vector
    // sampled across one ~100 ms drain interval; the detour extrapolates
    // forward along that line based on time-since-cur.
    float         prev_pos_x;
    float         prev_pos_y;
    float         prev_pos_z;
    float         prev_yaw_rad;
    std::uint64_t prev_ts_ms;
    bool          has_prev;            // false until the 2nd drain entry
};
std::shared_mutex g_latest_owner_mtx;
std::unordered_map<std::uint32_t, LatestOwnerStateEntry>
    g_latest_owner_state;

// Build 65.c.30 — handoff smoothing state (hold + short lerp).
//
// Root cause (re/reteleport_on_death_AGENT.md): while B is the non-owner of a
// raider, B's *visible* pos is pinned 60 Hz to the owner's relayed pose
// (apply_npc_pos, last writer each frame), but B's local engine AI + Havok run
// un-suppressed and silently diverge the raider's internal pos. The instant
// ownership leaves the remote peer (peer death → server PHASE_2 release → B
// re-claims / fid goes unowned), the override stops in the same frame and B's
// engine's diverged pos becomes visible → a one-frame SNAP. This blends FROM
// (last interp pose) → TO (B's engine pose) over HANDOFF_BLEND_MS so the swap
// is smooth instead of a jump.
//
// `note_non_owner_interp_pose` is called every frame the fid is non-owner
// (records the last applied interp pose = FROM, and marks was_non_owner).
// `poll_handoff_blend` is called every frame the fid is NOT non-owner; on the
// first such frame after a non-owner period it arms the blend, then returns the
// lerped pose each frame until HANDOFF_BLEND_MS elapses. A large FROM→TO gap
// (> HANDOFF_BLEND_MAX_DIST) is treated as a real teleport/cell-change and NOT
// blended (cut). All access is main-thread (npc_ai_suppress detour); a plain
// mutex is sufficient and cheap.
struct HandoffBlendEntry {
    float         from_x = 0.0f, from_y = 0.0f, from_z = 0.0f, from_yaw = 0.0f;
    bool          has_from = false;        // a FROM pose has been captured
    bool          was_non_owner = false;   // fid was non-owner-tracked recently
    std::uint64_t blend_start_ms = 0;      // 0 = not currently blending
};
std::mutex g_handoff_blend_mtx;
std::unordered_map<std::uint32_t, HandoffBlendEntry> g_handoff_blend;

// Build 65.c.24 — Recent-fire timestamp cache for Signal 3 of the multi-
// signal anim_state aggregation. See main_thread_dispatch.h comment block
// for full rationale. Writer = ghost_ai_fire.cpp on owner detour fire-
// decision-succeeds; reader = npc_ai_suppress.cpp owner capture path.
std::shared_mutex g_recent_fire_mtx;
std::unordered_map<std::uint32_t, std::uint64_t> g_recent_fire_ts;

// ============================================================================
// Build 67 — MAIN-THREAD STALL WATCHDOG (freeze forensics). See header.
//
// Design constraints:
//   - The capture must work on a thread that is NOT cooperating (it is hung),
//     so: SuspendThread + GetThreadContext + a raw stack SCAN (return-address
//     heuristic: any qword on the stack that points into the game EXE or this
//     DLL). No StackWalk64 (needs dbghelp + symbols), no RtlCaptureStackBackTrace
//     (current-thread only).
//   - NOTHING is logged while the main thread is suspended — if it hung while
//     holding the log/heap lock, logging would deadlock the watchdog too.
//     Collect first, resume, then log.
//   - SEH cages around every raw memory read (PE headers, stack scan).
// ============================================================================
namespace {

std::atomic<std::uint64_t> g_mt_alive_ms{0};
std::atomic<std::uint32_t> g_mt_tid{0};
std::atomic<bool>          g_mt_watchdog_started{false};

// Resolve [base, base+size) of the module containing `addr` (nullptr = the
// game EXE). SEH-caged PE-header read; no C++ dtors (SEH-safe).
bool wd_module_range(void* addr, std::uintptr_t* base,
                     std::uintptr_t* size) noexcept {
    HMODULE hm = nullptr;
    if (addr) {
        if (!GetModuleHandleExW(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                    GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCWSTR>(addr), &hm))
            return false;
    } else {
        hm = GetModuleHandleW(nullptr);
    }
    if (!hm) return false;
    __try {
        auto* b   = reinterpret_cast<std::uint8_t*>(hm);
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(b);
        auto* nt  = reinterpret_cast<IMAGE_NT_HEADERS64*>(b + dos->e_lfanew);
        *base = reinterpret_cast<std::uintptr_t>(b);
        *size = nt->OptionalHeader.SizeOfImage;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Scan up to 16KB of stack upward from rsp; collect qwords that land in the
// game EXE or our DLL (return-address heuristic). Partial scan on SEH is fine.
int wd_scan_stack(std::uintptr_t rsp,
                  std::uintptr_t gbase, std::uintptr_t gsize,
                  std::uintptr_t fbase, std::uintptr_t fsize,
                  std::uintptr_t* out, int out_cap) noexcept {
    int n = 0;
    __try {
        const auto* p = reinterpret_cast<const std::uintptr_t*>(rsp);
        for (int i = 0; i < 2048 && n < out_cap; ++i) {
            const std::uintptr_t v = p[i];
            if ((gsize && v >= gbase && v < gbase + gsize) ||
                (fsize && v >= fbase && v < fbase + fsize)) {
                out[n++] = v;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // stack page boundary — keep what we have
    }
    return n;
}

DWORD WINAPI wd_thread_main(LPVOID) {
    std::uintptr_t gbase = 0, gsize = 0, fbase = 0, fsize = 0;
    wd_module_range(nullptr, &gbase, &gsize);
    wd_module_range(reinterpret_cast<void*>(&wd_thread_main), &fbase, &fsize);
    FW_LOG("[mt-watchdog] running: tid=%lu game=[0x%llX+0x%llX] fw=[0x%llX+0x%llX]",
           static_cast<unsigned long>(g_mt_tid.load(std::memory_order_relaxed)),
           static_cast<unsigned long long>(gbase),
           static_cast<unsigned long long>(gsize),
           static_cast<unsigned long long>(fbase),
           static_cast<unsigned long long>(fsize));

    bool armed = true;
    int  captures = 0;
    for (;;) {
        Sleep(250);
        const std::uint64_t alive = g_mt_alive_ms.load(std::memory_order_relaxed);
        if (alive == 0) continue;
        const std::uint64_t now = GetTickCount64();
        const std::uint64_t stall = (now > alive) ? (now - alive) : 0;
        if (stall < 500) { armed = true; continue; }
        if (stall < 1500 || !armed || captures >= 5) continue;
        armed = false;   // one capture per stall episode
        ++captures;

        const DWORD tid = g_mt_tid.load(std::memory_order_relaxed);
        HANDLE th = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                                   THREAD_QUERY_INFORMATION,
                               FALSE, tid);
        if (!th) {
            FW_ERR("[mt-watchdog] STALL %llums but OpenThread(tid=%lu) failed "
                   "gle=%lu",
                   static_cast<unsigned long long>(stall),
                   static_cast<unsigned long>(tid), GetLastError());
            continue;
        }

        // ---- suspended window: collect only, NO logging ----
        CONTEXT ctx;
        ZeroMemory(&ctx, sizeof(ctx));
        ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        std::uintptr_t frames[24];
        int nf = 0;
        bool got_ctx = false;
        const DWORD sc = SuspendThread(th);
        if (sc != static_cast<DWORD>(-1)) {
            got_ctx = GetThreadContext(th, &ctx) != 0;
            if (got_ctx) {
                nf = wd_scan_stack(static_cast<std::uintptr_t>(ctx.Rsp),
                                   gbase, gsize, fbase, fsize,
                                   frames, 24);
            }
            ResumeThread(th);
        }
        CloseHandle(th);
        // ---- resumed: now log freely ----

        if (!got_ctx) {
            FW_ERR("[mt-watchdog] CAPTURE #%d: main-thread STALL %llums — "
                   "Suspend/GetThreadContext failed (sc=%ld gle=%lu)",
                   captures, static_cast<unsigned long long>(stall),
                   static_cast<long>(sc), GetLastError());
            continue;
        }

        const std::uintptr_t rip = static_cast<std::uintptr_t>(ctx.Rip);
        char where[64];
        if (gsize && rip >= gbase && rip < gbase + gsize)
            snprintf(where, sizeof(where), "FO4+0x%llX",
                     static_cast<unsigned long long>(rip - gbase));
        else if (fsize && rip >= fbase && rip < fbase + fsize)
            snprintf(where, sizeof(where), "FW+0x%llX",
                     static_cast<unsigned long long>(rip - fbase));
        else
            snprintf(where, sizeof(where), "EXT:0x%llX",
                     static_cast<unsigned long long>(rip));
        FW_ERR("[mt-watchdog] CAPTURE #%d: main-thread STALL %llums — "
               "RIP=%s RSP=0x%llX RBP=0x%llX RCX=0x%llX RDX=0x%llX",
               captures, static_cast<unsigned long long>(stall), where,
               static_cast<unsigned long long>(ctx.Rsp),
               static_cast<unsigned long long>(ctx.Rbp),
               static_cast<unsigned long long>(ctx.Rcx),
               static_cast<unsigned long long>(ctx.Rdx));

        // Stack scan as one compact line ("G+rva" = game, "F+rva" = our DLL).
        char buf[1024];
        int  off = snprintf(buf, sizeof(buf),
                            "[mt-watchdog]   stack-scan (%d hits):", nf);
        for (int i = 0; i < nf && off > 0 &&
                        off < static_cast<int>(sizeof(buf)) - 24; ++i) {
            const std::uintptr_t v = frames[i];
            if (gsize && v >= gbase && v < gbase + gsize)
                off += snprintf(buf + off, sizeof(buf) - off, " G+0x%llX",
                                static_cast<unsigned long long>(v - gbase));
            else
                off += snprintf(buf + off, sizeof(buf) - off, " F+0x%llX",
                                static_cast<unsigned long long>(v - fbase));
        }
        FW_ERR("%s", buf);
    }
    return 0;
}

}  // namespace

void note_main_thread_alive() noexcept {
    g_mt_alive_ms.store(GetTickCount64(), std::memory_order_relaxed);
    if (!g_mt_watchdog_started.exchange(true, std::memory_order_acq_rel)) {
        g_mt_tid.store(GetCurrentThreadId(), std::memory_order_relaxed);
        HANDLE h = CreateThread(nullptr, 0, &wd_thread_main, nullptr, 0, nullptr);
        if (h) {
            CloseHandle(h);
        } else {
            // No watchdog — heartbeat keeps updating, captures just won't fire.
            g_mt_watchdog_started.store(false, std::memory_order_release);
        }
    }
}

void drain_npc_owner_state_apply_queue() {
    std::deque<PendingNPCOwnerState> local;
    {
        std::lock_guard lk(g_npc_owner_mtx);
        local.swap(g_npc_owner_queue);   // always drain to bound the queue
    }
    if (local.empty()) return;

    // Build 67 — freeze forensics: bracket the drain with a START line. The
    // 2026-06-11 stall left one unresolvable ambiguity: was this drain on the
    // main thread's stack when it hung, or did the hang live in the 60Hz
    // detour? The completion summary alone can't say (it never printed); a
    // START line answers it for free at the next stall.
    static std::atomic<std::uint64_t> s_drain_seq{0};
    const auto dseq = s_drain_seq.fetch_add(1, std::memory_order_relaxed);
    FW_DBG("dispatch: owner-state drain START #%llu (%zu entries)",
           static_cast<unsigned long long>(dseq), local.size());

    // Build 65.c.28 — TELEPORT FREEZE GUARD.
    //
    // Two independent freezes (c.25 Fixed Selector, c.27 RNG) shared one
    // root: the main thread froze during the teleport cell-stream. apply_
    // npc_pos goes through Actor::vt[202] which mutates the destination
    // cell's hash. Calling it on a non-owner raider whose cell is mid-
    // stream deadlocks against the engine's own cell-load lock → drain
    // queue starves (qsize 255→280 observed) → Windows kills the hung
    // process.
    //
    // Build 65.c.46 — SUSPENDED-WINDOW SAFE PATH (was: DROP whole batch).
    //
    // Original c.28 behaviour DROPPED the batch AND skipped the snapshot-cache
    // update during recently_teleported(). But recently_teleported() false-
    // positives on exterior cell-edge streaming (it arms 1500ms on ANY local-
    // player parentCell change), so on a Concord cell-cross BOTH the 10Hz drain
    // (here) and the 60Hz detour (npc_ai_suppress) stop pinning the non-owner
    // keyframed raider for ~1.5s. Result: the body's pos FREEZES while its pose
    // keeps streaming ("runs in place") then SNAPS forward when the guard
    // releases (LOG_B 00:40:06.040→07.331, 10 consecutive skips ≈ 1.29s).
    //
    // The ONLY thing the guard must suppress is vt[202] (apply_npc_pos), because
    // its sub_140513A80→sub_140576030/sub_140575E20 grab a PROCESS-GLOBAL cell-
    // grid spinlock that the streaming thread can hold → main-thread deadlock
    // (the c.27/c.28 freeze — DO NOT re-introduce). Everything else here is
    // deadlock-safe (pure SEH-caged memory writes, no engine call):
    //   - the snapshot cache update (so interp endpoints stay FRESH — a frozen
    //     cache would make even a fresh apply write a stale pos),
    //   - apply_npc_pos_raw (Actor+0xD0 + NIF local/world — moves the keyframed
    //     body without the grid lock),
    //   - the InCombat bit (raw |= 0x4000).
    // So during the window we KEEP all of those and skip ONLY vt[202] + the
    // SetRotation engine call. KILL-SWITCH: kRawPinDuringTeleport=false restores
    // the old drop-batch behaviour.
    static constexpr bool kRawPinDuringTeleport = true;
    // Build 67.1 — REVERTED the Build 67 is_load_in_progress() widening.
    // Measured live (05:33 session, via the SUSPENDED-SAFE throttle math:
    // 21 lines = first-10 + every-200th → ~2200 of 2344 drains on A, ~2800 of
    // 2886 on B): the engine load byte is TRUE ~94-97% of NORMAL GAMEPLAY, so
    // the widening silently routed nearly every drain to the degraded path —
    // SetRotation skipped (stale yaw = the "raider running backwards" bug) and
    // the Build-67 native proxy snap NEVER executed (gated !suspended). The
    // byte is useless as a streaming gate; back to the teleport window only.
    const bool suspended = fw::engine::recently_teleported();
    if (suspended && !kRawPinDuringTeleport) {
        static std::atomic<std::uint64_t> s_load_skips{0};
        const auto sk = s_load_skips.fetch_add(1, std::memory_order_relaxed);
        if (sk < 10 || (sk % 200) == 0) {
            FW_DBG("dispatch: owner-state drain SKIPPED — cell transition "
                   "(teleport guard, dropped %zu entries, skip#%llu)",
                   local.size(), static_cast<unsigned long long>(sk));
        }
        return;
    }
    if (suspended) {
        static std::atomic<std::uint64_t> s_raw_pins{0};
        const auto rp = s_raw_pins.fetch_add(1, std::memory_order_relaxed);
        if (rp < 10 || (rp % 200) == 0) {
            FW_DBG("dispatch: owner-state drain SUSPENDED-SAFE — cell transition "
                   "(teleport guard: raw-pin %zu entries, skip vt[202] only, "
                   "skip#%llu)",
                   local.size(), static_cast<unsigned long long>(rp));
        }
    }

    std::size_t applied = 0, missed = 0, skipped_owner = 0;
    for (const auto& e : local) {
        if (e.form_id == 0 || e.form_id == 0xFFFFFFFFu ||
            e.form_id == 0x00000014u ||
            e.form_id == fw::offsets::GHOST_FORMID_BASE)
        {
            ++missed;
            continue;
        }
        if (fw::ownership::is_owner_of(e.form_id)) {
            // We're the authority — never apply server-relayed state to
            // ourselves. Defence in depth: server should already filter
            // these out, but a race during handoff could leak one frame.
            ++skipped_owner;
            continue;
        }
        void* actor = fw::engine::lookup_by_form_id(e.form_id);
        if (!actor) {
            // ===== B6.6 POS-MEAS (read-only) — RESIDENCY MISS.
            // Server relayed owner-state for this raider but it is NOT
            // loaded/resident in THIS client's process (lookup -> null). We
            // apply to nothing -> this client never shows the owner's pos for
            // it -> hard desync. Logs WHICH fids so we can tell if the user's
            // "raiders in different spots" is residency (B can't see it) vs
            // apply-drift (B sees it but the engine pulls it off sync).
            static std::atomic<std::uint64_t> g_posmeas_miss{0};
            const auto pmm = g_posmeas_miss.fetch_add(
                1, std::memory_order_relaxed);
            if (pmm < 40 || (pmm % 20) == 0) {
                FW_LOG("[pos-meas] RESIDENCY-MISS fid=0x%08X — relayed "
                       "owner-state but actor not loaded here "
                       "(apply to nothing -> desync)",
                       e.form_id);
            }
            ++missed;
            continue;
        }
        // Build 65.c.21 — ROLLBACK apply_npc_state_to_actor da drain.
        //
        // 65.c.19 introdusse `apply_npc_state_to_actor` per scrivere
        // anim graph vars (bIsAimingGun, bsSpeedSampled, ecc.) on the
        // non-owner side. Quel funzionava finché 65.c.20 manteneva il
        // bail Update_PerFrame su non-owner: in quel caso solo IL
        // NOSTRO drain toccava l'anim graph holder → single-writer.
        //
        // 65.c.20 ha rimosso il bail Update_PerFrame (L1 pass-through
        // per fix "tronchi"). Ora engine vanilla AI tickka l'NPC su
        // non-owner E chiama internamente SetGraphVariable a 60Hz +
        // il nostro drain chiamava SetGraphVariable a 10Hz sul medesimo
        // holder. Mid-cell-streaming (teleport in corso) lo smart-ptr
        // dell'holder è in init: il doppio writer race produce SEH
        // (READ addr=0xFFFFFFFFFFFFFFFF, sentinel di pointer "torn down")
        // a RVA 0x81B5CF — il SetGraphVariableFloat interno deref. VEH
        // cattura ma 30 AV consecutivi corrompono graph → process muore.
        //
        // Fix: ENGINE vanilla AI (ora live grazie a 65.c.20) gestisce
        // nativamente l'anim graph. NOI ci limitiamo a pos+yaw+InCombat
        // override post-orig. Niente più double-write sull'anim graph
        // holder, no SEH race.
        // Build 65.c.46 — during the teleport-guard window use the DEADLOCK-
        // SAFE raw pin (no cell-grid lock) instead of vt[202]; also skip the
        // SetRotation engine call (sibling of SetPosition — avoid any engine
        // recursion during a cell-stream). The body's facing is cosmetic vs
        // the freeze; the next post-window drain restores full vt[202]+yaw.
        const bool pos_ok =
            suspended ? fw::engine::apply_npc_pos_raw(
                            actor, e.pos_x, e.pos_y, e.pos_z)
                      : fw::engine::apply_npc_pos(
                            actor, e.pos_x, e.pos_y, e.pos_z);
        if (!suspended) {
            (void)fw::engine::aim_actor_at_target_rotation_only(
                actor, e.yaw_rad);
            // Build 66 — NATIVE char-controller proxy snap. We pin the VISIBLE
            // pos above (apply_npc_pos), but the AI-locomotion proxy keeps an
            // independent NATIVE pos that the non-owner's still-running AI
            // advances → it diverges from the owner and surfaces as the
            // "walks-in-place / not at the owner's spot / handoff snap". Snap
            // the proxy to the SAME relayed pos via the engine's own flush-free,
            // cell-grid-lock-free setter so the engine is natively AT the synced
            // spot at all times. Gated !suspended (cell-stream): the vtbl[+416]
            // leaf is still being RE'd, so we conservatively skip it while
            // streaming. Toggle for the live test:
            constexpr bool kNativeProxySync = true;
            if (kNativeProxySync) {
                (void)fw::engine::push_native_proxy_pos(
                    actor, e.pos_x, e.pos_y, e.pos_z);
            }
        }

        // Build 65.c.22 + c.23 — popola cache unificata pos/yaw/anim_state
        // per il detour 60Hz.
        //
        //   c.22: anim_state per re-set bit InCombat (Actor+0x2D0 |= 0x4000)
        //   c.23: prev/cur pos+yaw per interpolation/extrapolation 60Hz
        //
        // L'aggiornamento è "shift": cur diventa prev, nuovo entry diventa
        // cur. Al primo drain per un fid, has_prev resta false (no
        // interpolation possible until 2nd drain → detour usa cur as-is).
        {
            std::unique_lock<std::shared_mutex> lk(g_latest_owner_mtx);
            auto& s = g_latest_owner_state[e.form_id];
            const std::uint64_t now = GetTickCount64();
            // Shift cur → prev se cur era populated (ts != 0). All'inserzione
            // di un nuovo fid, s è value-init (tutto a 0), quindi has_prev
            // resta false alla prima iterazione.
            if (s.cur_ts_ms != 0) {
                s.prev_pos_x  = s.cur_pos_x;
                s.prev_pos_y  = s.cur_pos_y;
                s.prev_pos_z  = s.cur_pos_z;
                s.prev_yaw_rad = s.cur_yaw_rad;
                s.prev_ts_ms   = s.cur_ts_ms;
                s.has_prev     = true;
            }
            s.cur_pos_x   = e.pos_x;
            s.cur_pos_y   = e.pos_y;
            s.cur_pos_z   = e.pos_z;
            s.cur_yaw_rad = e.yaw_rad;
            s.anim_state  = e.anim_state;
            s.cur_ts_ms   = now;
        }

        // InCombat flag set se anim_state suggerisce combat. Quel non
        // è anim graph — è solo Actor+0x2D0 bit 0x4000 raw write, no
        // smart-pointer involved, no race con engine. Engine vanilla
        // AI legge questo flag ma non lo writes su questo path
        // (lo settta via sub_140CCF810 EnterCombat path che è separato).
        //
        // Build 65.c.22: questa scrittura 10Hz rimane (è "best effort"
        // immediato), ma il detour 60Hz è quello che dà davvero la
        // persistenza del bit contro engine clear.
        if (e.anim_state >= 3 && e.anim_state <= 5) {
            seh_set_actor_in_combat(actor);
        }

        // Build 68.7 — MIRROR LOCOMOTION. anim_state 0/1/2 (idle/walk/run,
        // now actually produced by the owner since 68.7's delta-pos
        // derivation) drives the mirror's own anim graph via SpeedSampled,
        // so the legs animate the translation instead of sliding in idle
        // ("tronco di legno"). Guards, in order:
        //   !suspended    — the c.21 crash was this setter mid cell-stream
        //                   (graph-holder smart-ptr in init); never again.
        //   !is_dying     — never drive a corpse's graph.
        //   change-or-400ms — the engine may also write these vars; writing
        //                   only on transition (+ a 400 ms refresh to win
        //                   sustained disagreements) keeps us to
    }
    if (applied || missed || skipped_owner) {
        FW_DBG("dispatch: drained %zu owner-state entries "
               "(applied=%zu missed=%zu skipped_owner=%zu)",
               local.size(), applied, missed, skipped_owner);
    }
}

// Build 65.c.22 — getter pubblico per il detour npc_ai_suppress.
// Chiamato 60Hz per ogni non-owner tracked NPC. Hot path: shared_lock
// per concurrent read, no contention col drain (drain è 10Hz unique_lock,
// detour è 60Hz shared_lock → contention rara).
bool get_latest_owner_anim_state(std::uint32_t form_id,
                                  std::uint8_t* out_anim_state) {
    if (form_id == 0 || form_id == 0xFFFFFFFFu) return false;
    std::shared_lock<std::shared_mutex> lk(g_latest_owner_mtx);
    auto it = g_latest_owner_state.find(form_id);
    if (it == g_latest_owner_state.end()) return false;
    const auto now = GetTickCount64();
    // Staleness: >2s significa che owner ha smesso di emettere (offline,
    // handoff, peer disconnect). Non forzare bit su entry stale → engine
    // gestisce naturalmente (raider decay a idle se appropriato).
    if (now < it->second.cur_ts_ms ||
        now - it->second.cur_ts_ms > 2000ULL) {
        return false;
    }
    if (out_anim_state) *out_anim_state = it->second.anim_state;
    return true;
}

// Build 65.c.23 — interpolated pos+yaw+anim getter for the detour 60Hz path.
//
// Logic:
//   1. Snapshot `s` under shared_lock (atomic w.r.t. drain writes).
//   2. Staleness gate: if cur is older than 500 ms, the owner has likely
//      stopped emitting (handoff in progress, peer disconnect, owner
//      out of cell). Return false so the detour yields and the engine's
//      own pos integration takes over.
//   3. Without prev (first drain only) → return cur as-is (no extrapolation
//      possible without 2 samples).
//   4. With prev → compute extrapolation factor t = (now - cur.ts) / (cur.ts -
//      prev.ts), capped at kMaxExtrapolation. Linear: pos = cur + (cur-prev)*t.
//      Yaw uses shortest-arc π wrap-around to avoid 6.28→0.01 jump.
//
// Capped extrapolation prevents wild overshoot if the owner emits at
// irregular cadence (TCP retransmit, GC pause). 1.5 = 50 % past current
// matches the existing legacy `get_interpolated_npc_state` cap.
bool get_interpolated_owner_state(std::uint32_t form_id,
                                   std::uint64_t now_ms,
                                   InterpolatedOwnerState* out) {
    if (form_id == 0 || form_id == 0xFFFFFFFFu || !out) return false;
    LatestOwnerStateEntry snap{};
    {
        std::shared_lock<std::shared_mutex> lk(g_latest_owner_mtx);
        auto it = g_latest_owner_state.find(form_id);
        if (it == g_latest_owner_state.end()) return false;
        snap = it->second;
    }
    if (snap.cur_ts_ms == 0) return false;
    if (now_ms < snap.cur_ts_ms) return false;
    const std::uint64_t dt_now = now_ms - snap.cur_ts_ms;

    // c.40b — STALENESS HANDLING REWRITTEN. ROOT-CAUSE FIX for the #1 desync
    // (raiders scattano/scompaiono/si ricollocano), confirmed 2026-05-31 from
    // handoff dist=1189 + relay gaps.
    //
    // OLD behaviour: after 700 ms with no fresh owner sample, return false →
    // the 60 Hz override (npc_ai_suppress c.23) stopped writing → the non-
    // owner's LOCAL engine AI ("natural integration", live since c.20) resumed
    // moving the raider → it walked off the owner's path → DIVERGENCE → on
    // handoff/owner-death the diverged local copy surfaced = teleport/relocate.
    // Yielding to the local AI is architecturally WRONG for owner-driven sync:
    // while we are the non-owner, the raider must NEVER be driven by our AI.
    //
    // NEW behaviour: HOLD the last-good owner pos through a relay gap — keep
    // pinning the body (frozen, no overshoot, no yield). This makes our post-
    // orig write the reliable last word every frame (same principle as the
    // c.37 pose freeze). Only release after a LONG gap (5 s ≈ raider unloaded
    // on the owner / genuinely abandoned), where the engine SHOULD take over.
    if (dt_now > 5000ULL) return false;

    out->anim_state = snap.anim_state;

    // Beyond a short fresh window (or before we have a velocity sample) HOLD
    // cur: pin the raider at its last-synced owner pos. THIS is the drift-stop.
    if (dt_now > 300ULL || !snap.has_prev) {
        out->pos_x   = snap.cur_pos_x;
        out->pos_y   = snap.cur_pos_y;
        out->pos_z   = snap.cur_pos_z;
        out->yaw_rad = snap.cur_yaw_rad;
        return true;
    }

    // FRESH (≤300 ms): extrapolate along the velocity vector for 60 Hz
    // smoothness between the ~13 Hz owner samples. dt_pc ≥ 1 avoids div-by-zero.
    const std::uint64_t dt_pc =
        (snap.cur_ts_ms > snap.prev_ts_ms)
            ? (snap.cur_ts_ms - snap.prev_ts_ms)
            : 1ULL;

    float t = static_cast<float>(dt_now) / static_cast<float>(dt_pc);
    // c.40b — 2.2→1.5. Less overshoot on a single late packet now that longer
    // gaps HOLD (above) instead of gliding forward unboundedly.
    constexpr float kMaxExtrapolation = 1.5f;
    if (t > kMaxExtrapolation) t = kMaxExtrapolation;

    // Linear position extrapolation from velocity vector (cur - prev).
    const float vx = snap.cur_pos_x - snap.prev_pos_x;
    const float vy = snap.cur_pos_y - snap.prev_pos_y;
    const float vz = snap.cur_pos_z - snap.prev_pos_z;
    out->pos_x = snap.cur_pos_x + vx * t;
    out->pos_y = snap.cur_pos_y + vy * t;
    out->pos_z = snap.cur_pos_z + vz * t;

    // Yaw: shortest-arc wrap. Without this 6.27 → 0.01 (= +1° real)
    // would extrapolate backwards 6.26 rad = ~−359° = visible spin.
    constexpr float kPi  = 3.14159265358979323846f;
    constexpr float k2Pi = 2.0f * kPi;
    float yaw_diff = snap.cur_yaw_rad - snap.prev_yaw_rad;
    if (yaw_diff > kPi)  yaw_diff -= k2Pi;
    if (yaw_diff < -kPi) yaw_diff += k2Pi;
    out->yaw_rad = snap.cur_yaw_rad + yaw_diff * t;

    return true;
}

// Build 65.c.30 — handoff smoothing impl. See struct comment above + the
// dossier re/reteleport_on_death_AGENT.md §5 (Option A).
void note_non_owner_interp_pose(std::uint32_t form_id,
                                float x, float y, float z, float yaw_rad) {
    if (form_id == 0 || form_id == 0xFFFFFFFFu) return;
    std::lock_guard<std::mutex> lk(g_handoff_blend_mtx);
    auto& e = g_handoff_blend[form_id];
    e.from_x   = x;
    e.from_y   = y;
    e.from_z   = z;
    e.from_yaw = yaw_rad;
    e.has_from = true;
    e.was_non_owner = true;
    e.blend_start_ms = 0;   // not blending while still non-owner
}

bool poll_handoff_blend(std::uint32_t form_id, std::uint64_t now_ms,
                        float eng_x, float eng_y, float eng_z, float eng_yaw,
                        InterpolatedOwnerState* out) {
    if (form_id == 0 || form_id == 0xFFFFFFFFu || !out) return false;
    std::lock_guard<std::mutex> lk(g_handoff_blend_mtx);
    auto it = g_handoff_blend.find(form_id);
    if (it == g_handoff_blend.end()) return false;
    auto& e = it->second;

    // Arm on the first frame after the non-owner period (the handoff frame).
    if (e.blend_start_ms == 0) {
        if (!e.was_non_owner || !e.has_from) {
            // Not a fresh handoff (steady owner / already consumed) → clean up.
            g_handoff_blend.erase(it);
            return false;
        }
        const float dx = eng_x - e.from_x;
        const float dy = eng_y - e.from_y;
        const float dz = eng_z - e.from_z;
        const float dist2 = dx * dx + dy * dy + dz * dz;
        const float maxd = HANDOFF_BLEND_MAX_DIST;
        const bool too_far = dist2 > maxd * maxd;
        // FROM/TO diagnostic — once per handoff arm (measures snap magnitude).
        FW_LOG("[handoff-blend] ARM fid=0x%08X FROM=(%.1f,%.1f,%.1f) "
               "TO=(%.1f,%.1f,%.1f) dist=%.1f blend_ms=%llu%s",
               form_id, e.from_x, e.from_y, e.from_z,
               eng_x, eng_y, eng_z, std::sqrt(dist2),
               static_cast<unsigned long long>(HANDOFF_BLEND_MS),
               too_far ? " — SKIP (gap too large, treat as real teleport)" : "");
        if (too_far) {
            g_handoff_blend.erase(it);
            return false;          // let engine pose stand (hard cut)
        }
        e.was_non_owner = false;   // consume
        e.blend_start_ms = now_ms; // begin blend
    }

    const std::uint64_t elapsed =
        (now_ms >= e.blend_start_ms) ? (now_ms - e.blend_start_ms) : 0ULL;
    if (elapsed >= HANDOFF_BLEND_MS) {
        g_handoff_blend.erase(it);  // blend complete → release to engine
        return false;
    }
    float t = static_cast<float>(elapsed) /
              static_cast<float>(HANDOFF_BLEND_MS);
    if (t < 0.0f) t = 0.0f;
    if (t > 1.0f) t = 1.0f;

    // lerp FROM → engine pose (TO moves each frame as B's engine pathes it).
    out->pos_x = e.from_x + (eng_x - e.from_x) * t;
    out->pos_y = e.from_y + (eng_y - e.from_y) * t;
    out->pos_z = e.from_z + (eng_z - e.from_z) * t;
    // Yaw: shortest-arc wrap (same as get_interpolated_owner_state).
    constexpr float kPi  = 3.14159265358979323846f;
    constexpr float k2Pi = 2.0f * kPi;
    float yd = eng_yaw - e.from_yaw;
    if (yd > kPi)  yd -= k2Pi;
    if (yd < -kPi) yd += k2Pi;
    out->yaw_rad    = e.from_yaw + yd * t;
    out->anim_state = 0;   // unused by the blend caller
    return true;
}

// Build 65.c.44 — handoff COMMIT. See header. Returns the last-synced owner pose
// (FROM, captured by note_non_owner_interp_pose while non-owner) ONCE on the
// handoff frame, then consumes the entry so the caller MoveTo's exactly once.
bool consume_handoff_commit(std::uint32_t form_id,
                            float* out_x, float* out_y, float* out_z,
                            float* out_yaw) {
    if (form_id == 0 || form_id == 0xFFFFFFFFu) return false;
    std::lock_guard<std::mutex> lk(g_handoff_blend_mtx);
    auto it = g_handoff_blend.find(form_id);
    if (it == g_handoff_blend.end()) return false;
    auto& e = it->second;
    // Only commit on a FRESH handoff: the fid was non-owner AND we captured a
    // FROM pose. Otherwise it's a steady owner / already-consumed entry → drop.
    if (!e.was_non_owner || !e.has_from) {
        g_handoff_blend.erase(it);
        return false;
    }
    if (out_x)   *out_x   = e.from_x;
    if (out_y)   *out_y   = e.from_y;
    if (out_z)   *out_z   = e.from_z;
    if (out_yaw) *out_yaw = e.from_yaw;
    g_handoff_blend.erase(it);   // one-shot: consume so we MoveTo exactly once
    return true;
}

// Build 65.c.24 — Recent-fire timestamp cache impl.
void mark_owner_actor_fired(std::uint32_t form_id) {
    if (form_id == 0 || form_id == 0xFFFFFFFFu) return;
    const auto now = GetTickCount64();
    std::unique_lock<std::shared_mutex> lk(g_recent_fire_mtx);
    g_recent_fire_ts[form_id] = now;
}

bool recently_fired(std::uint32_t form_id, std::uint64_t window_ms) {
    if (form_id == 0 || form_id == 0xFFFFFFFFu) return false;
    std::shared_lock<std::shared_mutex> lk(g_recent_fire_mtx);
    auto it = g_recent_fire_ts.find(form_id);
    if (it == g_recent_fire_ts.end()) return false;
    const auto now = GetTickCount64();
    // Guard against backward time (system clock changes); treat as stale.
    if (now < it->second) return false;
    return (now - it->second) <= window_ms;
}

void drain_npc_state_apply_queue_pos_only() {
    // B6.6w5 REWIRED — this fallback is now a NO-OP. The new pos
    // apply path uses Actor::vt[202] which makes cell-hash mutations
    // that are NOT safe from arbitrary threads. We refuse to dispatch
    // pos applies from the net thread; entries stay queued until the
    // main thread's PostMessage path resumes after HWND restore.
    std::deque<PendingNPCStateEntry> local;
    {
        std::lock_guard lk(g_npc_mtx);
        // Don't swap — leave entries in the queue for the next main-
        // thread drain attempt. Worst case: positions arrive late.
    }
    FW_DBG("dispatch: net-thread fallback pos-only drain SKIPPED — "
           "B6.6w5 requires main-thread serialization");
}

// =========================================================================
// B6.5w4 round 2 — Per-NPC state cache
// =========================================================================

void update_npc_cache(std::uint32_t form_id,
                     float pos_x, float pos_y, float pos_z,
                     float yaw_deg_math,
                     std::uint8_t anim_state,
                     std::uint32_t package_form_id,
                     std::uint32_t combat_target_form_id,
                     float velocity_x,
                     float velocity_y,
                     float velocity_z,
                     std::uint8_t movement_override) {
    if (form_id == 0) return;
    bool inserted_now = false;
    std::size_t new_size = 0;
    const auto now_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    {
        std::lock_guard lk(g_npc_cache_mtx);
        auto it = g_npc_cache.find(form_id);
        if (it == g_npc_cache.end()) {
            inserted_now = true;
            CachedNPCStateImpl fresh{};
            fresh.pos_x = pos_x;
            fresh.pos_y = pos_y;
            fresh.pos_z = pos_z;
            fresh.yaw_deg_math = yaw_deg_math;
            fresh.anim_state = anim_state;
            fresh.last_update_ms = now_ms;
            fresh.has_prev = false;
            fresh.package_form_id = package_form_id;
            fresh.combat_target_form_id = combat_target_form_id;
            fresh.velocity_x = velocity_x;
            fresh.velocity_y = velocity_y;
            fresh.velocity_z = velocity_z;
            fresh.movement_override = movement_override;
            g_npc_cache[form_id] = fresh;
        } else {
            // Round 9: shift current → prev BEFORE writing new current,
            // so the render thread can interpolate between the pair.
            it->second.prev_pos_x = it->second.pos_x;
            it->second.prev_pos_y = it->second.pos_y;
            it->second.prev_pos_z = it->second.pos_z;
            it->second.prev_yaw_deg_math = it->second.yaw_deg_math;
            it->second.prev_update_ms = it->second.last_update_ms;
            it->second.has_prev = true;

            it->second.pos_x = pos_x;
            it->second.pos_y = pos_y;
            it->second.pos_z = pos_z;
            it->second.yaw_deg_math = yaw_deg_math;
            it->second.anim_state = anim_state;
            it->second.last_update_ms = now_ms;
            it->second.package_form_id = package_form_id;
            it->second.combat_target_form_id = combat_target_form_id;
            it->second.velocity_x = velocity_x;
            it->second.velocity_y = velocity_y;
            it->second.velocity_z = velocity_z;
            it->second.movement_override = movement_override;
        }
        new_size = g_npc_cache.size();
    }
    if (inserted_now) {
        FW_LOG("dispatch: tracked NPC registered form_id=0x%X (cache size=%zu) — "
               "Ghost AI hooks will now consult server state for this form",
               form_id, new_size);
    }
}

bool get_cached_npc_state(std::uint32_t form_id, CachedNPCState* out) {
    if (form_id == 0) return false;
    std::lock_guard lk(g_npc_cache_mtx);
    auto it = g_npc_cache.find(form_id);
    if (it == g_npc_cache.end()) return false;
    if (out) {
        out->pos_x = it->second.pos_x;
        out->pos_y = it->second.pos_y;
        out->pos_z = it->second.pos_z;
        out->yaw_deg_math = it->second.yaw_deg_math;
        out->anim_state = it->second.anim_state;
        out->last_update_ms = it->second.last_update_ms;
        out->package_form_id = it->second.package_form_id;
        out->combat_target_form_id = it->second.combat_target_form_id;
        out->velocity_x = it->second.velocity_x;
        out->velocity_y = it->second.velocity_y;
        out->velocity_z = it->second.velocity_z;
        out->movement_override = it->second.movement_override;
    }
    return true;
}

std::size_t tracked_npc_count() {
    std::lock_guard lk(g_npc_cache_mtx);
    return g_npc_cache.size();
}

std::vector<std::pair<std::uint32_t, CachedNPCState>> get_all_cached_npcs() {
    std::vector<std::pair<std::uint32_t, CachedNPCState>> out;
    std::lock_guard lk(g_npc_cache_mtx);
    out.reserve(g_npc_cache.size());
    for (const auto& [fid, st] : g_npc_cache) {
        CachedNPCState s;
        s.pos_x = st.pos_x;
        s.pos_y = st.pos_y;
        s.pos_z = st.pos_z;
        s.yaw_deg_math = st.yaw_deg_math;
        s.anim_state = st.anim_state;
        s.last_update_ms = st.last_update_ms;
        s.package_form_id = st.package_form_id;
        s.combat_target_form_id = st.combat_target_form_id;
        s.velocity_x = st.velocity_x;
        s.velocity_y = st.velocity_y;
        s.velocity_z = st.velocity_z;
        s.movement_override = st.movement_override;
        out.emplace_back(fid, s);
    }
    return out;
}

bool get_interpolated_npc_state(std::uint32_t form_id,
                               std::uint64_t now_ms,
                               InterpolatedNPCState* out) {
    if (form_id == 0 || !out) return false;
    // Snapshot under lock then compute outside it.
    CachedNPCStateImpl snap{};
    {
        std::lock_guard lk(g_npc_cache_mtx);
        auto it = g_npc_cache.find(form_id);
        if (it == g_npc_cache.end()) return false;
        snap = it->second;
    }

    out->anim_state = snap.anim_state;

    if (!snap.has_prev) {
        // First BCAST — nothing to lerp from, use current as-is.
        out->pos_x = snap.pos_x;
        out->pos_y = snap.pos_y;
        out->pos_z = snap.pos_z;
        out->yaw_deg_math = snap.yaw_deg_math;
        return true;
    }

    const std::uint64_t dt_prev_cur_ms =
        (snap.last_update_ms > snap.prev_update_ms)
            ? (snap.last_update_ms - snap.prev_update_ms)
            : 1ull;  // avoid div-by-0; treat as 1ms

    // t goes from 0 (just got current snap) to 1 (one BCAST interval
    // has passed since current). Beyond 1, we EXTRAPOLATE — capped at
    // 1.5x interval to avoid runaway when server stalls or stops.
    const float dt_now_cur_ms_f =
        static_cast<float>(now_ms >= snap.last_update_ms
                              ? (now_ms - snap.last_update_ms)
                              : 0);
    const float dt_prev_cur_ms_f = static_cast<float>(dt_prev_cur_ms);
    float t = dt_now_cur_ms_f / dt_prev_cur_ms_f;
    constexpr float kMaxExtrapolation = 1.5f;
    if (t > kMaxExtrapolation) t = kMaxExtrapolation;

    // Linear extrapolation from current using prev→current velocity:
    //   pos(now) = current + (current - prev) * t
    const float vx = snap.pos_x - snap.prev_pos_x;
    const float vy = snap.pos_y - snap.prev_pos_y;
    const float vz = snap.pos_z - snap.prev_pos_z;
    out->pos_x = snap.pos_x + vx * t;
    out->pos_y = snap.pos_y + vy * t;
    out->pos_z = snap.pos_z + vz * t;

    // Yaw: same linear approach. Wrap-around fix: if diff > 180, take
    // the short way around (subtract 360). Avoids 359°→1° jumping
    // backwards through 358 intermediate degrees.
    float yaw_diff = snap.yaw_deg_math - snap.prev_yaw_deg_math;
    if (yaw_diff > 180.0f)  yaw_diff -= 360.0f;
    if (yaw_diff < -180.0f) yaw_diff += 360.0f;
    out->yaw_deg_math = snap.yaw_deg_math + yaw_diff * t;

    return true;
}

void drain_container_apply_queue() {
    std::deque<PendingContainerOp> local;
    {
        std::lock_guard lk(g_mtx);
        local.swap(g_queue);
    }
    if (local.empty()) {
        FW_DBG("dispatch: drain called with empty queue — no-op");
        return;
    }

    // We're on the main thread here (WndProc dispatch). Set the feedback-
    // loop guard so any vt[0x7A] / TransferItem re-entry triggered by
    // AddItem/RemoveItem internals does NOT re-emit to the network.
    fw::hooks::ApplyingRemoteGuard guard;

    std::size_t applied_ok = 0, failed = 0;
    for (const auto& op : local) {
        const bool ok = fw::engine::apply_container_op_to_engine(
            op.kind,
            op.container_form_id,
            op.container_base_id,
            op.container_cell_id,
            op.item_base_id,
            op.count);
        if (ok) ++applied_ok; else ++failed;
    }
    FW_LOG("dispatch: drained %zu container ops (applied=%zu failed=%zu)",
           local.size(), applied_ok, failed);
}

void set_target_hwnd(HWND hwnd) {
    g_hwnd.store(hwnd, std::memory_order_release);
    FW_LOG("dispatch: target hwnd set to %p", hwnd);
    // Flush whatever accumulated before the subclass was installed.
    std::size_t pending = 0;
    {
        std::lock_guard lk(g_mtx);
        pending = g_queue.size();
    }
    if (pending > 0) {
        FW_LOG("dispatch: flushing %zu pre-hwnd queued ops", pending);
        post_wakeup_container();
    }
    // B6.1: also flush any door ops accumulated pre-subclass.
    std::size_t pending_doors = 0;
    {
        std::lock_guard lk(g_door_mtx);
        pending_doors = g_door_queue.size();
    }
    if (pending_doors > 0) {
        FW_LOG("dispatch: flushing %zu pre-hwnd queued door ops", pending_doors);
        post_wakeup_door();
    }
    // M9 wedge 2: flush any equip ops accumulated pre-subclass.
    std::size_t pending_equips = 0;
    {
        std::lock_guard lk(g_equip_mtx);
        pending_equips = g_equip_queue.size();
    }
    if (pending_equips > 0) {
        FW_LOG("dispatch: flushing %zu pre-hwnd queued equip ops", pending_equips);
        post_wakeup_equip();
    }
    // M9 wedge 4 v9: flush any mesh blob ops accumulated pre-subclass.
    std::size_t pending_mesh_blobs = 0;
    {
        std::lock_guard lk(g_mesh_blob_mtx);
        pending_mesh_blobs = g_mesh_blob_queue.size();
    }
    if (pending_mesh_blobs > 0) {
        FW_LOG("dispatch: flushing %zu pre-hwnd queued mesh-blob ops",
               pending_mesh_blobs);
        post_wakeup_mesh_blob();
    }
    // B6.3 v0.5.3 (fix landed in v0.5.5 2026-05-09): flush any lock ops
    // accumulated pre-subclass. The original B6.3 ship forgot to add this
    // alongside the container/door/equip/mesh-blob flushes, so the
    // server's peer-join bootstrap LOCK_BCAST (which arrives within ~50 ms
    // of the net handshake, ~8 s before WndProc subclass install on a
    // typical FO4 NG boot) was silently swallowed. Symptom: receiver's
    // local engine never learned about previously-cracked container locks
    // and showed them as locked even after sender repeatedly sent
    // LOCK_OP — the runtime resends got dedup'd by the server because the
    // stored state already matched, but the receiver had never applied
    // the bootstrap, so its engine view stayed stale. With this flush
    // wired up, the bootstrap lock state is applied as soon as the
    // WndProc subclass is up and dispatching messages.
    std::size_t pending_locks = 0;
    {
        std::lock_guard lk(g_lock_mtx);
        pending_locks = g_lock_queue.size();
    }
    if (pending_locks > 0) {
        FW_LOG("dispatch: flushing %zu pre-hwnd queued lock ops",
               pending_locks);
        post_wakeup_lock();
    }
}

std::size_t pending_count() {
    std::lock_guard lk(g_mtx);
    return g_queue.size();
}

HWND get_target_hwnd() {
    return g_hwnd.load(std::memory_order_acquire);
}

// ---------------------------------------------------------------------------
// B6.6w1 — server-driven fire trigger
// ---------------------------------------------------------------------------

void enqueue_npc_fire(const PendingNPCFire& op) {
    std::size_t qsize;
    {
        std::lock_guard lk(g_npc_fire_mtx);
        g_npc_fire_queue.push_back(op);
        qsize = g_npc_fire_queue.size();
    }
    FW_DBG("dispatch: npc_fire enqueued raider=0x%X target=0x%X flags=0x%X "
           "kind=%u (qsize=%zu)",
           op.raider_form_id, op.target_form_id, op.flags,
           static_cast<unsigned>(op.target_kind), qsize);
    post_wakeup_npc_fire();
}

// =============================================================================
// Build 55a (2026-05-23) — Per-raider ghost-target window tracker.
//
// Map: form_id → expiry_ms (CLOCK_MONOTONIC). Entry added when an NPC_FIRE
// with target_kind=GHOST arrives (npc_fire_with_ghost_aim sets expiry =
// now + 5000ms). Entry expires lazily on lookup. ghost_ai_fire's
// should_silence_combat predicate consults this set and BAILS vanilla fire
// for any raider currently in the ghost-target window — which prevents
// engine vanilla AI's 60Hz rotation writes from competing with our
// puppet-fire's 1-2Hz writes (root cause of the dual-target flicker in
// Build 54 live test).
//
// Window size 5s is generous: NPC_FIRE arrives ~1-2Hz when raider is
// engaged, so the window typically refreshes well before expiry. If the
// server changes aggro target_kind to LOCAL, no more GHOST events come
// in → window expires → ghost_ai_fire stops BAILing → vanilla resumes.
// =============================================================================

namespace {
std::mutex g_ghost_targeted_mtx;
std::unordered_map<std::uint32_t, std::uint64_t> g_ghost_targeted;

// Build 55f — per-fid rotation override (yaw_rad + expiry_ms).
// Same mutex as g_ghost_targeted for simplicity (cheap to share).
struct GhostYawEntry {
    float        yaw_rad;
    std::uint64_t expiry_ms;
};
std::unordered_map<std::uint32_t, GhostYawEntry> g_ghost_targeted_yaw;

// Monotonic millisecond clock (GetTickCount64 — wraps every ~49 days,
// negligible for our windows).
inline std::uint64_t now_ms_monotonic() noexcept {
    return static_cast<std::uint64_t>(GetTickCount64());
}
}  // namespace

void mark_raider_ghost_targeted(std::uint32_t form_id,
                                std::uint64_t expiry_ms) {
    std::lock_guard lk(g_ghost_targeted_mtx);
    g_ghost_targeted[form_id] = expiry_ms;
}

bool is_raider_currently_ghost_targeted(std::uint32_t form_id) {
    if (form_id == 0 || form_id == 0xFFFFFFFFu) return false;
    const auto now = now_ms_monotonic();
    std::lock_guard lk(g_ghost_targeted_mtx);
    auto it = g_ghost_targeted.find(form_id);
    if (it == g_ghost_targeted.end()) return false;
    if (now >= it->second) {
        g_ghost_targeted.erase(it);
        return false;
    }
    return true;
}

std::size_t ghost_targeted_raiders_count() {
    std::lock_guard lk(g_ghost_targeted_mtx);
    return g_ghost_targeted.size();
}

void mark_raider_ghost_targeted_yaw(std::uint32_t form_id,
                                    float yaw_rad,
                                    std::uint64_t expiry_ms) {
    if (form_id == 0 || form_id == 0xFFFFFFFFu) return;
    std::lock_guard lk(g_ghost_targeted_mtx);
    g_ghost_targeted_yaw[form_id] = GhostYawEntry{yaw_rad, expiry_ms};
}

bool get_ghost_targeted_yaw(std::uint32_t form_id,
                            float* out_yaw_rad) {
    if (form_id == 0 || form_id == 0xFFFFFFFFu) return false;
    const auto now = now_ms_monotonic();
    std::lock_guard lk(g_ghost_targeted_mtx);
    auto it = g_ghost_targeted_yaw.find(form_id);
    if (it == g_ghost_targeted_yaw.end()) return false;
    if (now >= it->second.expiry_ms) {
        g_ghost_targeted_yaw.erase(it);
        return false;
    }
    if (out_yaw_rad) *out_yaw_rad = it->second.yaw_rad;
    return true;
}

// Build 53 (2026-05-23) — puppet-fire helper invoked per NPC_FIRE event.
//
// Why an out-of-line helper: drain_npc_fire_queue holds a std::deque local
// (non-trivial dtor) so MSVC forbids __try in its body (C2712). We extract
// the SEH-needing pos-read here as a separate noexcept fn.
//
// Logic:
//   1. Get current ghost actor via get_ghost_duplicate().
//   2. Read ghost.+0xD0 (POS_OFF) for current peer position (cell-sync
//      keeps this updated every PEER_POS broadcast).
//   3. Call fire_actor_at_target(refr, gx, gy, gz) — full puppet-fire:
//      a. set_actor_weapon_state_class(refr, slot, 15) — gate B refresh
//      b. aim_set_target(aim_ctrl, ghost.pos) — refreshes target_pos
//         + valid flag + timestamp every event (defeats engine's decay)
//      c. fire_actor_weapon(refr) — WeaponFireHandler emits projectile
//
// Fallback path (no ghost or SEH on pos read): bare fire_actor_weapon —
// projectile fires in whatever direction the raider's current aim
// controller has (Build 52 behavior).
//
// Build 52 symptom this fixes: "raider's weapon continues firing at the
// ground when raider goes idle". Root cause: class=15 + aim_set_target
// happened only once at synth time. Engine decay'd +0x34 valid flag +
// +0x38 timestamp; aim returned to weapon's default rest direction.
static void npc_fire_with_ghost_aim(void* refr) noexcept {
    void* ghost = fw::engine::get_ghost_duplicate();
    if (!ghost) {
        // No ghost yet — fall back to bare WeaponFireHandler.
        (void)fw::engine::fire_actor_weapon(refr);
        return;
    }
    float gx = 0.f, gy = 0.f, gz = 0.f;
    bool got_pos = false;
    __try {
        const auto* pos = reinterpret_cast<const float*>(
            reinterpret_cast<const std::uint8_t*>(ghost) +
            fw::offsets::POS_OFF);
        gx = pos[0];
        gy = pos[1];
        gz = pos[2];
        got_pos = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        got_pos = false;
    }
    if (got_pos) {
        // Build 61.2 (2026-05-24) — CALLER-SIDE defensive synth dedup.
        //
        // Build 61 added enter_combat+synth here to fix the 2/5 raiders
        // never getting AimController (their NPC_STATE_BCAST never carried
        // the combat_target flag). Build 61 unconditionally called both,
        // which created DUPLICATE ctrl_main entries in HP+0x98 BSTArray
        // for raiders ALREADY synth'd by the BCAST path. The duplicate
        // caused double-detach during engine cleanup → freelist marker
        // poisoning → AV cascade.
        //
        // Build 61.1 attempted to fix the duplicate inside synth body
        // (early return on re-entry) but BROKE the normal flow — synth
        // is normally called AFTER enter_combat allocates HighProcess,
        // and the early return skipped Steps B/C even on first call.
        //
        // Build 61.2 correct fix: dedup AT THE CALLER. Check if this
        // raider already has a ghost-engaged combat state (i.e., synth
        // already ran for it from any path). If yes → skip enter_combat
        // and synth entirely (cheap idempotent path). If no → run full
        // synth (Steps A+B+C produce HighProcess + ctrl_main).
        //
        // The is_ghost_engaged_raider_fid set is populated by
        // install_fixed_selector_on_raider (called by both Tier 1 success
        // path and the apply_npc_combat_target Build 55h fast-path).
        // So any raider that has been synth'd via BCAST → already in set.
        std::uint32_t raider_fid = 0;
        __try {
            raider_fid = *reinterpret_cast<std::uint32_t*>(
                reinterpret_cast<std::uint8_t*>(refr) +
                fw::offsets::FORMID_OFF);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            raider_fid = 0;
        }

        const bool already_synthd =
            (raider_fid != 0) &&
            fw::engine::is_ghost_engaged_raider_fid(raider_fid);

        if (!already_synthd) {
            // Build 65.c.33 — DISABLED. Completes the c.25.1 Fixed-Selector
            // rollback that this caller-side pair SURVIVED (the sibling
            // aim/fire calls below are already BUILD64_DISABLED; these two
            // were the last live path into install_fixed_selector_on_raider).
            //
            // ROOT CAUSE of the client-B COMBAT FREEZE (Agent1, stack-proven):
            // these two reached install_fixed_selector_on_raider, which injects
            // the ghost into the RAIDER's known_targets BSTArray and purges its
            // handles — corrupting the array header. When that array later grew,
            // BSTArray::Reallocate (sub_141659850) ran a garbage-size (~2.4 GB,
            // 0x97FFFF30) memmove → AV (rip in system memmove, src+size matches
            // the fault addr) → the AV unwound mid-realloc through the engine's
            // frame-SEH, leaving the global scrapheap allocator inconsistent →
            // the next main-thread allocation spins forever = FREEZE (log B
            // 01:12:45: POISON-BAIL storm on the fixed-sel'd raider ctrl, one AV,
            // then qsize 1→152 with no drain while the net thread lives).
            //
            // Obsolete in the owner-driven model (c.27+): raiders aggro their
            // OWNER's LOCAL player, NOT the ghost; cross-client visuals come
            // from the state relay (proven by the mosquito test — melee/no-fire,
            // so it never hit this path, and it synced correctly).
            // BUILD64_DISABLED (c.33) — (void)fw::engine::enter_combat_raider_vs_ghost(refr, ghost);
            // BUILD64_DISABLED (c.33) — (void)fw::engine::synthesize_combat_extension_for_ghost_target(refr, ghost, gx, gy, gz);
            (void)ghost;
        }
        // else: raider already synth'd. Skip to avoid duplicate ctrl_main.
        // Existing HighProcess + ctrl_main are still valid and registered.

        // Build 54 — rotate raider to face ghost + activate aim/attack
        // anim graph vars BEFORE firing. This makes the weapon node's
        // world forward (which Stage-4 reads) point toward the ghost.
        // Without this step, projectiles fly in the raider's natural
        // idle facing direction ("punti fissi ma diversi" per Build 53).
        // BUILD64_DISABLED — (void)fw::engine::aim_actor_at_target(refr, gx, gy, gz);

        // c.40a — RE-ENABLE the mirror muzzle/projectile. The relay + enqueue
        // worked all along (B receives the FIRE events) but the executor was
        // BUILD64-disabled, so the mirror only AIMED (via the c.23 relayed yaw)
        // and never discharged. fire_actor_at_target is self-contained (sets
        // weapon class firable=15, resolves the AimController, aims, fires) and
        // does NOT touch the known_targets BSTArray / fixed-selector path that
        // caused the c.33 freeze — only enter_combat/synthesize did (kept off).
        // Full puppet-fire: class=15 + aim_set_target refresh + WeaponFire.
        (void)fw::engine::fire_actor_at_target(refr, gx, gy, gz);
    } else {
        // SEH reading ghost.pos — bare fire in the relayed facing direction.
        (void)fw::engine::fire_actor_weapon(refr);
    }
    (void)refr;
}

void drain_npc_fire_queue() {
    std::deque<PendingNPCFire> local;
    {
        std::lock_guard lk(g_npc_fire_mtx);
        local.swap(g_npc_fire_queue);   // always drain to bound the queue
    }
    if (local.empty()) return;

    // Build 65.c.28 — TELEPORT FREEZE GUARD (same rationale as the owner-
    // state drain above). npc_fire_with_ghost_aim spawns a projectile +
    // muzzle flash and reads the ghost actor's transform; during a cell-
    // stream the raider and/or ghost can be in transient state → engine
    // fire path faults or hangs. Drop fire events while loading; a missed
    // muzzle flash during a teleport is invisible.
    if (fw::engine::recently_teleported()) {
        static std::atomic<std::uint64_t> s_fire_load_skips{0};
        const auto sk = s_fire_load_skips.fetch_add(
            1, std::memory_order_relaxed);
        if (sk < 10 || (sk % 200) == 0) {
            FW_DBG("dispatch: npc_fire drain SKIPPED — cell transition "
                   "(teleport guard, dropped %zu, skip#%llu)",
                   local.size(), static_cast<unsigned long long>(sk));
        }
        return;
    }

    static std::atomic<std::uint64_t> s_drain_count{0};
    const auto dc = s_drain_count.fetch_add(1, std::memory_order_relaxed);
    if (dc < 10) {
        FW_LOG("dispatch: drain_npc_fire_queue #%llu — %zu pending",
               static_cast<unsigned long long>(dc), local.size());
    }

    for (const auto& op : local) {
        // Look up the Actor* by form_id. Returns null if the raider
        // isn't loaded in our cell — common when the raider is on the
        // other client's side only. Skip silently.
        void* refr = fw::engine::lookup_by_form_id(op.raider_form_id);
        if (!refr) {
            static std::atomic<std::uint64_t> s_no_actor{0};
            const auto na = s_no_actor.fetch_add(
                1, std::memory_order_relaxed);
            if (na < 10) {
                FW_DBG("dispatch: npc_fire raider=0x%X — not loaded locally "
                       "(skip, na=%llu)",
                       op.raider_form_id,
                       static_cast<unsigned long long>(na));
            }
            continue;
        }

        // Build 55a (proto v15) — gate puppet-fire on target_kind.
        //
        // target_kind=LOCAL → the recipient peer's local player IS the
        //   aggro target. Vanilla engine AI fires at them naturally.
        //   We must NOT puppet-fire here (we'd compete with vanilla aim
        //   and produce the dual-target flicker observed in Build 54).
        //   Just skip; vanilla handles this raider's combat.
        //
        // target_kind=GHOST → the recipient's local GHOST proxy
        //   represents the aggro target (= the OTHER peer). Run puppet-
        //   fire path AND mark the raider in g_ghost_targeted so
        //   ghost_ai_fire BAILs the vanilla fire to prevent competition.
        if (op.target_kind == fw::net::NPC_FIRE_TARGET_LOCAL) {
            static std::atomic<std::uint64_t> s_local_skip{0};
            const auto ls = s_local_skip.fetch_add(
                1, std::memory_order_relaxed);
            if (ls < 10) {
                FW_DBG("dispatch: npc_fire raider=0x%X kind=LOCAL — "
                       "skipping puppet (vanilla AI handles, ls=%llu)",
                       op.raider_form_id,
                       static_cast<unsigned long long>(ls));
            }
            continue;
        }
        // target_kind == GHOST (or unknown — treat as GHOST for back-compat).
        // Mark raider in ghost-target set with 5s expiry. ghost_ai_fire
        // will BAIL vanilla fire for this raider while the entry is live.
        constexpr std::uint64_t kGhostWindowMs = 5000;
        mark_raider_ghost_targeted(
            op.raider_form_id, now_ms_monotonic() + kGhostWindowMs);

        // Build 53 — puppet-fire with ghost.pos as aim target.
        npc_fire_with_ghost_aim(refr);
    }
}

// ============================================================================
// Build 62 (2026-05-24) — NPC perception trigger dispatch.
//
// Per re/arena_synthesis/SUPERVISOR_SYNTHESIS.md. Replaces the
// synth/Tier1/Tier2/walker fragile pipeline with a single CCF810
// EnterCombat call. Server's proximity sphere detection emits one
// MSG_NPC_PERCEPTION_TRIGGER per (npc, peer) entrance event; this drain
// invokes engine::trigger_npc_perception which calls sub_140CCF810
// natively. Engine allocates HighProcess+CombatController+AddTarget in
// 1 frame.
//
// Threading: enqueue on net thread; drain runs on main thread (engine
// CombatController alloc reads TLS recursion counter).
// ============================================================================

namespace {
// Each client knows its own peer_id string (registered at PEER_HELLO).
// We hash it ONCE at startup and compare against the wire payload's
// peer_id_hash to decide if the perception target is the LOCAL PC (=
// peer_id == self → target = local_player) or another peer's ghost
// duplicate (peer_id != self → target = registered ghost).
//
// Hash function MUST match the server-side Python `hash(str)` truncated
// to 32 bits. Python's `hash` on a string is implementation-defined and
// NOT stable across runs — that's a real problem. To match deterministically
// we have to either (a) emit a numeric peer_id at PEER_HELLO time and
// thread it, or (b) use a stable hash (e.g. FNV-1a) on both sides.
//
// For Build 62 prototype we'll use a stable FNV-1a 32-bit hash on the
// peer_id string from both sides. Implementation in both Python server
// and C++ client.
std::atomic<std::uint32_t> g_local_peer_id_hash{0};

constexpr std::uint32_t fnv1a32(const char* s) noexcept {
    std::uint32_t h = 2166136261u;
    while (*s) {
        h ^= static_cast<std::uint8_t>(*s++);
        h *= 16777619u;
    }
    return h;
}
} // namespace

void register_local_peer_id_hash(const char* peer_id_str) noexcept {
    if (!peer_id_str) return;
    const auto h = fnv1a32(peer_id_str);
    g_local_peer_id_hash.store(h, std::memory_order_release);
    FW_LOG("dispatch: local_peer_id='%s' fnv1a32=0x%08X (Build 62)",
           peer_id_str, h);
}

void enqueue_npc_perception_trigger(const PendingNPCPerceptionTrigger& op) {
    std::size_t qsize;
    {
        std::lock_guard lk(g_npc_perception_trigger_mtx);
        g_npc_perception_trigger_queue.push_back(op);
        qsize = g_npc_perception_trigger_queue.size();
    }
    FW_DBG("dispatch: npc_perception_trigger enqueued npc=0x%X peer_hash=0x%08X "
           "(qsize=%zu)", op.npc_fid, op.peer_id_hash, qsize);
    post_wakeup_npc_perception();
}

void drain_npc_perception_trigger_queue() {
    std::deque<PendingNPCPerceptionTrigger> local;
    {
        std::lock_guard lk(g_npc_perception_trigger_mtx);
        local.swap(g_npc_perception_trigger_queue);
    }
    if (local.empty()) return;

    static std::atomic<std::uint64_t> s_drain_count{0};
    const auto dc = s_drain_count.fetch_add(1, std::memory_order_relaxed);
    if (dc < 20 || (dc % 100) == 0) {
        FW_LOG("dispatch: drain_npc_perception_trigger #%llu — %zu pending",
               static_cast<unsigned long long>(dc), local.size());
    }

    const std::uint32_t self_hash =
        g_local_peer_id_hash.load(std::memory_order_acquire);
    void* local_player = fw::engine::get_local_player();
    void* local_ghost  = fw::engine::get_ghost_duplicate();

    for (const auto& op : local) {
        // Resolve observer (NPC X) on this client.
        void* observer = fw::engine::lookup_by_form_id(op.npc_fid);
        if (!observer) {
            // NPC not loaded in our cell — drop silently. If both peers
            // far from NPC, this is normal: server broadcasts to all but
            // we only react when relevant.
            static std::atomic<std::uint64_t> s_no_obs{0};
            const auto na = s_no_obs.fetch_add(1, std::memory_order_relaxed);
            if (na < 10) {
                FW_DBG("dispatch: perception_trigger npc=0x%X — not loaded "
                       "locally (na=%llu)", op.npc_fid,
                       static_cast<unsigned long long>(na));
            }
            continue;
        }

        // Resolve target by peer_id_hash:
        //   self_hash == op.peer_id_hash → target is LOCAL PC (the peer
        //     is THIS client; NPC X should engage me)
        //   self_hash != op.peer_id_hash → target is OTHER peer's ghost
        //     duplicate registered locally
        void* target = nullptr;
        const char* target_kind = nullptr;
        if (self_hash != 0 && self_hash == op.peer_id_hash) {
            target = local_player;
            target_kind = "LOCAL_PC";
        } else {
            // For Build 62 MVP: assume single OTHER peer → use the global
            // registered ghost. Future multi-peer: maintain per-peer-hash
            // map of ghost pointers.
            target = local_ghost;
            target_kind = "GHOST";
        }
        if (!target) {
            static std::atomic<std::uint64_t> s_no_tgt{0};
            const auto nt = s_no_tgt.fetch_add(1, std::memory_order_relaxed);
            if (nt < 10) {
                FW_DBG("dispatch: perception_trigger npc=0x%X target_kind=%s "
                       "but ptr null (nt=%llu)", op.npc_fid, target_kind,
                       static_cast<unsigned long long>(nt));
            }
            continue;
        }

        // Build 64 — BUILD64_DISABLED. trigger_npc_perception calls
        // sub_140CCF810 which triggers the combat tier pipeline. With
        // AI-control hooks disabled, calling CCF810 still works but
        // produces unstable engagement that crashes within seconds.
        // Skip the call; agents will redesign the engagement strategy.
        const bool ok = false;  // Was: fw::engine::trigger_npc_perception(observer, target);

        FW_LOG("[perception] npc=0x%08X peer_hash=0x%08X target_kind=%s "
               "observer=%p target=%p rc=%d (BUILD64 — call DISABLED, "
               "vanilla AI runs unmolested)",
               op.npc_fid, op.peer_id_hash, target_kind,
               observer, target, ok ? 1 : 0);
    }
}

} // namespace fw::dispatch
