#include "inventory_restore.h"

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <map>
#include <set>
#include <mutex>
#include <utility>
#include <vector>

#include "../config.h"
#include "../engine/engine_calls.h"       // get_local_player, get_pc_parent_cell
#include "../engine/instance_writers.h"   // remove_instance, add_instance
#include "../hooks/container_hook.h"      // ApplyingRemoteGuard
#include "../log.h"
#include "../native/scene_inject.h"       // ghost_scene_settled
#include "../net/client.h"
#include "../net/protocol.h"
#include "../offsets.h"                   // is_pa_frame_wearable (2026-10-05)
#include "../hooks/equip_cycle.h"         // R2b: equip_form / unequip_form
#include "../render/chat_overlay.h"       // notice
#include "instance_fp.h"                  // fp_of_record
#include "inventory_capture.h"            // capture_now, last, last_state_seq
#include "lifecycle.h"                    // load_in_flight, stats
#include "player_stats.h"                 // R4: the numbers after the inventory

namespace fw::persist::restore {

namespace {

using Key = std::pair<std::uint32_t, std::uint64_t>;   // (base, fingerprint)
using Lines = std::map<Key, std::int64_t>;

constexpr std::uint64_t kAnswerRetryMs = 10000;   // no PLAYER_INV yet: ask again
constexpr std::uint64_t kNoLoadMs      = 90000;   // no load after the request: nothing to restore
constexpr std::uint64_t kGiveUpMs      = 30000;   // the load is over, the alignment could not run

std::atomic<bool> g_enabled{false};
std::atomic<bool> g_open{false};      // INV_STATE allowed
std::atomic<bool> g_due{false};       // a restore is owed
std::atomic<bool> g_curtain{false};

// The attempt in progress. Written by the net thread (the answer) and the
// main thread (everything else), always under g_mx; the engine is never
// called with it held.
struct Attempt {
    bool          requested       = false;
    std::uint8_t  reason          = 0;
    std::uint32_t last_seq        = 0;
    std::uint64_t jobs_at_request = 0;
    std::uint64_t requested_ms    = 0;
    std::uint64_t asked_ms        = 0;      // the last RESTORE_REQUEST sent
    std::uint64_t load_over_ms    = 0;      // the load after the request seen over
    // L5 realtime D1: the respawn of the death came without a load (the
    // resurrect): the alignment runs anyway.
    bool          no_load         = false;
    bool          no_load_said    = false;  // the closed wait of a death logged once
    // The answer.
    bool          answered        = false;
    std::uint8_t  status          = 0;
    std::uint32_t record_seq      = 0;
    std::uint16_t total           = 0;
    std::vector<std::uint8_t> got;
    std::vector<fw::net::InvStateEntry> lines;
    // R4: the numbers (PLAYER_STATS), sent by the server before the lines.
    std::uint32_t last_stats_seq   = 0;
    bool          stats_answered   = false;
    std::uint8_t  stats_status     = 0;
    std::uint16_t stats_total      = 0;
    std::uint32_t stats_seq        = 0;
    std::vector<std::uint8_t> stats_got;
    fw::persist::charstats::Snapshot stats;
};
std::mutex g_mx;
Attempt    g_a;

std::uint64_t now_ms() { return GetTickCount64(); }

const char* reason_name(std::uint8_t r) {
    switch (r) {
    case fw::net::kRestoreReasonBoot:  return "boot";
    case fw::net::kRestoreReasonDeath: return "death";
    default:                           return "retry";
    }
}

// Under g_mx.
void ask(std::uint8_t reason) {
    auto& c = fw::net::client();
    fw::net::RestoreRequestPayload r{};
    r.session        = c.capture_session();
    r.last_seq       = g_a.last_seq;
    r.last_stats_seq = g_a.last_stats_seq;
    r.reason         = reason;
    c.enqueue_restore_request(r);
    g_a.asked_ms = now_ms();
}

void begin(std::uint8_t reason, std::uint32_t last_seq, std::uint32_t last_stats_seq) {
    {
        std::lock_guard lk(g_mx);
        g_a = Attempt{};
        g_a.requested       = true;
        g_a.reason          = reason;
        g_a.last_seq        = last_seq;
        g_a.last_stats_seq  = last_stats_seq;
        g_a.jobs_at_request = fw::persist::stats().load_jobs;
        g_a.requested_ms    = now_ms();
        ask(reason);
    }
    g_open.store(false);
    g_curtain.store(false);
    g_due.store(true);
    FW_LOG("[restore] %s: the record is asked for (last capture sent #%u) and closed "
           "until the load is over and the player holds it again", reason_name(reason), last_seq);
}

void finish(std::uint8_t outcome, std::uint32_t record_seq, std::uint16_t removed,
            std::uint16_t added, std::uint16_t unresolved, std::uint64_t digest) {
    auto& c = fw::net::client();
    fw::net::RestoreDonePayload d{};
    d.session    = c.capture_session();
    d.record_seq = record_seq;
    d.outcome    = outcome;
    d.removed    = removed;
    d.added      = added;
    d.unresolved = unresolved;
    d.digest     = digest;
    c.enqueue_restore_done(d);
    {
        std::lock_guard lk(g_mx);
        g_a = Attempt{};
    }
    g_due.store(false);
    g_curtain.store(false);
    g_open.store(outcome != fw::net::kRestoreFailed);
}

void fail(const char* why, std::uint32_t record_seq) {
    FW_ERR("[restore] FAILED: %s. The record stays closed for this process: nothing of "
           "this session is written over it", why);
    fw::render::chat::notice("(your inventory could not be restored from the server: what "
                             "changes in this session will not be kept)");
    finish(fw::net::kRestoreFailed, record_seq, 0, 0, 0, 0);
}

// The capture's stacks as (base, fingerprint) lines.
Lines lines_of(const fw::persist::inventory::Manifest& m) {
    Lines out;
    for (std::uint32_t i = 0; i < m.stacks; ++i) {
        const auto& r = m.records[i];
        if (r.count <= 0 || r.base_id == 0) continue;
        // 2026-10-05: the frame's body armour (ArmorPoweredFrame*) is the
        // engine's while the player is inside a frame: left out of the
        // comparison then. On foot it is a leftover (a death inside a frame,
        // the exit of a frame while a second copy of it sat in the
        // inventory): it stays in, the record never names it, and the
        // alignment takes it off, Pip-Boy slot included.
        if (m.in_power_armor && fw::offsets::is_pa_frame_wearable(r.base_id)) continue;
        out[{r.base_id, fw::persist::instance::fp_of_record(r, nullptr)}] += r.count;
    }
    return out;
}

// What one line still differs by, after the unreadable lines of the same
// base absorbed what they can (see the header). `budget` maps a base to
// the units an unreadable line of the other side can still stand for.
std::int64_t absorb(std::map<std::uint32_t, std::int64_t>& budget, std::uint32_t base,
                    std::int64_t diff) {
    auto it = budget.find(base);
    if (it == budget.end() || it->second <= 0 || diff <= 0) return diff;
    const std::int64_t used = it->second < diff ? it->second : diff;
    it->second -= used;
    return diff - used;
}

// The lines of `have` that do not match `want`, unreadable lines absorbing.
std::uint32_t count_unresolved(const Lines& have, const Lines& want) {
    std::map<std::uint32_t, std::int64_t> have_unknown, want_unknown;
    for (const auto& [k, n] : have) {
        if (k.second != fw::net::kFpUnknown) continue;
        const auto w = want.find(k);
        const std::int64_t extra = n - (w == want.end() ? 0 : w->second);
        if (extra > 0) have_unknown[k.first] += extra;
    }
    for (const auto& [k, n] : want) {
        if (k.second != fw::net::kFpUnknown) continue;
        const auto h = have.find(k);
        const std::int64_t extra = n - (h == have.end() ? 0 : h->second);
        if (extra > 0) want_unknown[k.first] += extra;
    }
    std::uint32_t bad = 0;
    for (const auto& [k, n] : have) {
        if (k.second == fw::net::kFpUnknown) continue;
        const auto w = want.find(k);
        const std::int64_t surplus = n - (w == want.end() ? 0 : w->second);
        if (surplus > 0 && absorb(want_unknown, k.first, surplus) > 0) ++bad;
    }
    for (const auto& [k, n] : want) {
        if (k.second == fw::net::kFpUnknown) continue;
        const auto h = have.find(k);
        const std::int64_t shortfall = n - (h == have.end() ? 0 : h->second);
        if (shortfall > 0 && absorb(have_unknown, k.first, shortfall) > 0) ++bad;
    }
    return bad;
}

// R2b (2026-10-05) — what the record says is worn is worn. Runs after the
// lines are the record's: the engine's view is a fresh capture; the armour
// and weapons it wears that the record does not flag are taken off, the
// lines the record flags that the engine does not wear are put on, by the
// stack of the record's instance when the inventory holds it, the first
// stack of the base otherwise. A worn instance of the same base stands for
// the record's (the alignment kept it worn on purpose). Never touched: the
// Pip-Boy, the frame's body armour, anything that is not armour or a
// weapon (ammo is the weapon's business), and a player inside a frame.
// Every engine call is SEH-caged in equip_cycle; a fault is logged and the
// rest goes on: the worst case is the outfit of before, R2's own.
struct DressResult { std::uint16_t put_on = 0, taken_off = 0, failed = 0; };

bool dressable(std::uint8_t form_type, std::uint32_t base_id) {
    if (base_id == 0 || base_id == fw::offsets::PIPBOY_FORM_ID) return false;
    if (fw::offsets::is_pa_frame_wearable(base_id)) return false;
    return form_type == fw::offsets::FORMTYPE_ARMO || form_type == fw::offsets::FORMTYPE_WEAP;
}

DressResult redress(std::uintptr_t base, void* player, const std::set<Key>& want_equipped) {
    DressResult out;
    if (!fw::persist::inventory::capture_now(base, "restore dress")) {
        FW_WRN("[restore] no capture for the dressing: the outfit stays the checkpoint's");
        return out;
    }
    const auto& m = fw::persist::inventory::last();
    if (!m.complete) {
        FW_WRN("[restore] the dressing capture did not complete: the outfit stays the checkpoint's");
        return out;
    }
    if (m.in_power_armor) {
        FW_LOG("[restore] inside a frame: what is worn is the frame's, the outfit is not touched");
        return out;
    }
    std::set<std::uint32_t> record_worn;
    for (const auto& k : want_equipped) record_worn.insert(k.first);
    std::set<std::uint32_t> engine_worn;
    for (std::uint32_t i = 0; i < m.stacks; ++i) {
        const auto& r = m.records[i];
        if (r.count > 0 && r.base_id != 0 && (r.flags & fw::offsets::INV_STACK_FLAG_EQUIPPED)) {
            engine_worn.insert(r.base_id);
        }
    }
    // 1. Off: worn by the engine, not flagged by the record.
    std::set<std::uint32_t> done;
    for (std::uint32_t i = 0; i < m.stacks; ++i) {
        const auto& r = m.records[i];
        if (r.count <= 0 || !(r.flags & fw::offsets::INV_STACK_FLAG_EQUIPPED)) continue;
        if (!dressable(r.form_type, r.base_id) || record_worn.count(r.base_id)) continue;
        if (!done.insert(r.base_id).second) continue;
        const bool ok = fw::hooks::unequip_form(r.base_id);
        FW_LOG("[restore] 0x%08X worn by the game, not by the record: %s", r.base_id,
               ok ? "taken off" : "NOT taken off (the call faulted)");
        if (ok) ++out.taken_off; else ++out.failed;
    }
    // 2. On: flagged by the record, not worn by the engine (any instance of
    // the base worn stands for it).
    for (const auto& k : want_equipped) {
        if (engine_worn.count(k.first)) continue;
        if (k.first == 0 || k.first == fw::offsets::PIPBOY_FORM_ID
                || fw::offsets::is_pa_frame_wearable(k.first)) continue;
        fw::persist::inventory::ProbeStack stacks[16];
        std::uint32_t reasons = 0;
        const std::uint32_t n = fw::persist::inventory::probe_stacks(base, player, k.first, stacks,
                                                                     16, &reasons);
        int chosen = -1;
        int first = -1;
        std::uint8_t form_type = 0;
        for (std::uint32_t i = 0; i < n; ++i) {
            const auto& s = stacks[i];
            if (s.transient || s.r.count <= 0) continue;
            form_type = s.r.form_type;
            if (first < 0) first = static_cast<int>(i);
            if (k.second != fw::net::kFpUnknown
                    && fw::persist::instance::fp_of_record(s.r, nullptr) == k.second) {
                chosen = static_cast<int>(i);
                break;
            }
        }
        if (chosen < 0) chosen = first;
        if (chosen < 0) {
            FW_WRN("[restore] 0x%08X fp=%016llX flagged worn by the record: not in the inventory "
                   "(%u stack(s) read, reasons 0x%X), not put on", k.first,
                   static_cast<unsigned long long>(k.second), n, reasons);
            ++out.failed;
            continue;
        }
        if (!dressable(form_type, k.first)) continue;   // ammo, aid: the record's flag is the engine's
        const std::uint32_t stack_id = stacks[chosen].chain;
        const bool ok = fw::hooks::equip_form(k.first, stack_id);
        FW_LOG("[restore] 0x%08X fp=%016llX worn by the record, not by the game: %s (stack %u%s)",
               k.first, static_cast<unsigned long long>(k.second),
               ok ? "put on" : "NOT put on (the call faulted)", stack_id,
               chosen == first && fw::persist::instance::fp_of_record(stacks[chosen].r, nullptr) != k.second
                   ? ", the first of the base: the record's instance is not there" : "");
        if (ok) ++out.put_on; else ++out.failed;
    }
    return out;
}

// Aligns the player to `want`. Main thread, the capture complete and fresh.
// `want_equipped`: the lines the record flags as worn (R2b). `stats`
// non-null: the record's numbers, put back after the inventory (R4).
void align(std::uintptr_t base, const fw::persist::inventory::Manifest& m, const Lines& have,
           const Lines& want_in, const std::set<Key>& want_equipped, std::uint32_t record_seq,
           const fw::persist::charstats::Snapshot* stats) {
    void* player = fw::engine::get_local_player();
    if (!player) { fail("no player", record_seq); return; }

    // 2026-10-05 — a worn instance stands for the record's line of the same
    // base. The record names an item by its instance; after a load the
    // player may wear another instance of that base (the checkpoint's, a
    // twin from the crate), and taking the worn one off to build the
    // record's twin, unworn, left the player naked at every respawn (live
    // test: the Vault suit) and once hid the Pip-Boy. The worn instance is
    // kept and wanted instead, up to the record's count; the capture that
    // follows the restore makes the record say so.
    Lines want = want_in;
    for (std::uint32_t i = 0; i < m.stacks; ++i) {
        const auto& r = m.records[i];
        if (!(r.flags & fw::offsets::INV_STACK_FLAG_EQUIPPED) || r.count <= 0 || r.base_id == 0) continue;
        const Key k{r.base_id, fw::persist::instance::fp_of_record(r, nullptr)};
        if (k.second == fw::net::kFpUnknown) continue;
        const auto h = have.find(k);
        if (h == have.end()) continue;
        const auto w0 = want.find(k);
        std::int64_t surplus = h->second - (w0 == want.end() ? 0 : w0->second);
        if (surplus <= 0) continue;
        for (auto& [k2, n2] : want) {
            if (k2.first != k.first || k2 == k || k2.second == fw::net::kFpUnknown) continue;
            const auto h2 = have.find(k2);
            const std::int64_t shortfall = n2 - (h2 == have.end() ? 0 : h2->second);
            if (shortfall <= 0) continue;
            const std::int64_t take = surplus < shortfall ? surplus : shortfall;
            n2 -= take;
            want[k] += take;
            surplus -= take;
            FW_LOG("[restore] 0x%08X: the worn instance fp=%016llX stands for %lld of the "
                   "record's fp=%016llX: kept worn, the twin not built", k.first,
                   static_cast<unsigned long long>(k.second), static_cast<long long>(take),
                   static_cast<unsigned long long>(k2.second));
            if (surplus <= 0) break;
        }
    }

    std::map<std::uint32_t, std::int64_t> have_unknown, want_unknown;
    for (const auto& [k, n] : have) {
        if (k.second != fw::net::kFpUnknown) continue;
        const auto w = want.find(k);
        const std::int64_t extra = n - (w == want.end() ? 0 : w->second);
        if (extra > 0) have_unknown[k.first] += extra;
    }
    for (const auto& [k, n] : want) {
        if (k.second != fw::net::kFpUnknown) continue;
        const auto h = have.find(k);
        const std::int64_t extra = n - (h == have.end() ? 0 : h->second);
        if (extra > 0) want_unknown[k.first] += extra;
    }

    std::uint16_t removed = 0, added = 0, missing_desc = 0;
    {
        // The player's vt[0x7A] is the container hook's own target: what is
        // built here is not a take from a container.
        fw::hooks::ApplyingRemoteGuard guard;
        // The surplus first, then the shortfall.
        for (const auto& [k, n] : have) {
            if (k.second == fw::net::kFpUnknown) continue;   // never removed: nobody can read it
            const auto w = want.find(k);
            std::int64_t surplus = n - (w == want.end() ? 0 : w->second);
            surplus = absorb(want_unknown, k.first, surplus);
            if (surplus <= 0) continue;
            const int gone = fw::engine::instances::remove_instance(
                player, k.first, k.second, static_cast<int>(surplus > 0x7FFFFFFF ? 0x7FFFFFFF : surplus),
                nullptr);
            FW_LOG("[restore] 0x%08X fp=%016llX: %lld in the game, %lld in the record: %d removed",
                   k.first, static_cast<unsigned long long>(k.second),
                   static_cast<long long>(n),
                   static_cast<long long>(w == want.end() ? 0 : w->second), gone);
            if (gone > 0) ++removed;
        }
        for (const auto& [k, n] : want) {
            if (k.second == fw::net::kFpUnknown) continue;   // nothing to build it from
            const auto h = have.find(k);
            std::int64_t shortfall = n - (h == have.end() ? 0 : h->second);
            shortfall = absorb(have_unknown, k.first, shortfall);
            if (shortfall <= 0) continue;
            fw::net::InstanceDesc d{};
            if (k.second != fw::net::kFpPlain && !fw::net::client().instance_desc(k.second, &d)) {
                ++missing_desc;
                FW_WRN("[restore] 0x%08X fp=%016llX: %lld missing and no descriptor arrived: "
                       "not built", k.first, static_cast<unsigned long long>(k.second),
                       static_cast<long long>(shortfall));
                continue;
            }
            const int made = fw::engine::instances::add_instance(
                player, k.first, d, static_cast<int>(shortfall > 0x7FFFFFFF ? 0x7FFFFFFF : shortfall));
            FW_LOG("[restore] 0x%08X fp=%016llX: %lld in the game, %lld in the record: %d built",
                   k.first, static_cast<unsigned long long>(k.second),
                   static_cast<long long>(h == have.end() ? 0 : h->second),
                   static_cast<long long>(n), made);
            if (made > 0) ++added;
        }
    }

    // R2b: what the record says is worn is worn, now that the lines are the
    // record's.
    const DressResult dressed = redress(base, player, want_equipped);

    // What the game holds now, against the record.
    std::uint32_t unresolved = 0xFFFF;
    std::uint64_t digest = 0;
    if (fw::persist::inventory::capture_now(base, "restore check")) {
        const auto& m = fw::persist::inventory::last();
        if (m.complete) {
            unresolved = count_unresolved(lines_of(m), want);
            digest = m.digest;
        }
    }
    if (unresolved == 0xFFFF) {
        FW_WRN("[restore] the check capture did not complete: the alignment is reported partial");
    }
    // R4: the numbers, once the inventory is the record's.
    bool stats_short = false;
    if (stats) {
        const auto sr = fw::persist::charstats::apply(base, *stats);
        stats_short = !sr.ok || sr.perks_unresolved != 0;
    }
    const std::uint8_t outcome = (unresolved == 0 && !stats_short) ? fw::net::kRestoreAligned
                                                                   : fw::net::kRestorePartial;
    FW_LOG("[restore] %s to record #%u: %u line(s) with a surplus removed, %u built, "
           "%u without a descriptor, %u still differing; outfit: %u put on, %u taken off, "
           "%u failed",
           outcome == fw::net::kRestoreAligned ? "ALIGNED" : "PARTIAL", record_seq,
           unsigned(removed), unsigned(added), unsigned(missing_desc),
           unsigned(unresolved == 0xFFFF ? 0 : unresolved),
           unsigned(dressed.put_on), unsigned(dressed.taken_off), unsigned(dressed.failed));
    if (outcome != fw::net::kRestoreAligned) {
        char msg[160];
        std::snprintf(msg, sizeof(msg), "(inventory restored from the server, %u line(s) could "
                      "not be rebuilt)", unsigned(unresolved == 0xFFFF ? 0 : unresolved));
        fw::render::chat::notice(msg);
    }
    finish(outcome, record_seq, removed, added,
           static_cast<std::uint16_t>(unresolved > 0xFFFF ? 0xFFFF : unresolved), digest);
    // 2026-10-04: a boot inside a frame left the HUD of a player on foot, a
    // death in a frame left the Pip-Boy in its power armour mode.
    fw::engine::sync_power_armor_hud("the restore after the load");
}

} // namespace

void configure(const fw::config::Settings& cfg) {
    g_enabled.store(cfg.inventory_capture);
    FW_LOG("[restore] %s", cfg.inventory_capture
           ? "on: the player's record goes back into the game after every load"
           : "off (inventory_capture=false): no record, no restore");
}

void on_boot_word() {
    if (!g_enabled.load()) return;
    static std::atomic<bool> s_once{false};
    if (s_once.exchange(true)) return;
    begin(fw::net::kRestoreReasonBoot, 0, 0);
}

void on_death() {
    if (!g_enabled.load()) return;
    begin(fw::net::kRestoreReasonDeath, fw::persist::inventory::last_state_seq(),
          fw::persist::charstats::last_sent_seq());
}

void on_respawn_without_load() {
    if (!g_enabled.load()) return;
    std::lock_guard lk(g_mx);
    if (!g_a.requested || g_a.reason != fw::net::kRestoreReasonDeath) return;
    if (fw::persist::stats().load_jobs > g_a.jobs_at_request) return;   // the usual path
    g_a.no_load = true;
    FW_LOG("[restore] the respawn came without a load: the record goes into the game as "
           "it is (the death moved the inventory into the crate)");
}

void on_player_stats(const fw::net::PlayerStatsHeader& h, const fw::net::PerkRankEntry* perks,
                     std::size_t n) {
    if (!g_enabled.load()) return;
    if (h.session != fw::net::client().capture_session()) return;
    if (h.total_chunks == 0 || h.total_chunks > 64 || h.chunk_index >= h.total_chunks) return;
    std::lock_guard lk(g_mx);
    if (!g_a.requested || g_a.stats_answered) return;
    if (g_a.stats_total != h.total_chunks || g_a.stats_seq != h.seq || g_a.stats_status != h.status) {
        g_a.stats_total  = h.total_chunks;
        g_a.stats_seq    = h.seq;
        g_a.stats_status = h.status;
        g_a.stats_got.assign(h.total_chunks, 0);
        g_a.stats = fw::persist::charstats::Snapshot{};
        g_a.stats.level = h.level;
        g_a.stats.xp = h.xp;
        g_a.stats.perk_points = h.perk_points;
        for (int i = 0; i < 7; ++i) g_a.stats.special[i] = h.special[i];
        g_a.stats.health = h.health;
        g_a.stats.action_points = h.action_points;
        g_a.stats.rads = h.rads;
        g_a.stats.perks_read = true;
    }
    if (g_a.stats_got[h.chunk_index]) return;
    g_a.stats_got[h.chunk_index] = 1;
    for (std::size_t i = 0; perks && i < n; ++i) {
        g_a.stats.perks.emplace_back(perks[i].perk_form_id, perks[i].rank);
    }
    for (const auto c : g_a.stats_got) if (!c) return;
    std::sort(g_a.stats.perks.begin(), g_a.stats.perks.end());
    g_a.stats_answered = true;
    FW_LOG("[restore] stats #%u received (%s): level %u, XP %.0f, %zu perk(s)", h.seq,
           h.status == fw::net::kPlayerInvNone ? "none" : "record", unsigned(h.level), h.xp,
           g_a.stats.perks.size());
}

void on_player_inv(const fw::net::PlayerInvHeader& h, const fw::net::InvStateEntry* entries,
                   std::size_t n) {
    if (!g_enabled.load()) return;
    if (h.session != fw::net::client().capture_session()) return;
    if (h.total_chunks == 0 || h.total_chunks > 64 || h.chunk_index >= h.total_chunks) return;
    std::lock_guard lk(g_mx);
    if (!g_a.requested || g_a.answered) return;
    if (g_a.total != h.total_chunks || g_a.record_seq != h.record_seq || g_a.status != h.status) {
        // The first chunk of an answer (or of a newer one): start over.
        g_a.total      = h.total_chunks;
        g_a.record_seq = h.record_seq;
        g_a.status     = h.status;
        g_a.got.assign(h.total_chunks, 0);
        g_a.lines.clear();
    }
    if (g_a.got[h.chunk_index]) return;
    g_a.got[h.chunk_index] = 1;
    if (entries && n) g_a.lines.insert(g_a.lines.end(), entries, entries + n);
    for (const auto c : g_a.got) if (!c) return;
    g_a.answered = true;
    FW_LOG("[restore] record #%u received (%s): %zu line(s)", h.record_seq,
           h.status == fw::net::kPlayerInvNone ? "none: nothing to restore"
           : h.status == fw::net::kPlayerInvBehind ? "BEHIND: the last capture never reached it"
                                                   : "current",
           g_a.lines.size());
}

void tick(std::uintptr_t module_base) {
    if (!g_due.load()) return;
    const std::uint64_t now = now_ms();
    bool answered = false;
    bool late = false;
    bool have_stats = false;
    fw::persist::charstats::Snapshot stats;
    std::uint8_t status = 0;
    std::uint32_t record_seq = 0;
    std::vector<fw::net::InvStateEntry> lines;
    {
        std::lock_guard lk(g_mx);
        if (!g_a.requested) return;
        const bool loaded = g_a.no_load
                            || fw::persist::stats().load_jobs > g_a.jobs_at_request;
        if (!g_a.answered && now - g_a.asked_ms > kAnswerRetryMs) ask(fw::net::kRestoreReasonRetry);
        if (!loaded) {
            if (now - g_a.requested_ms > kNoLoadMs
                    && g_a.reason == fw::net::kRestoreReasonDeath) {
                // L5 realtime D1: the server moved the inventory into the
                // crate when it answered the death, so the game no longer
                // holds what the record holds: opening the record here would
                // write the lost inventory back over it, next to the crate.
                // It stays closed until a load or the respawn puts it back.
                if (!g_a.no_load_said) {
                    g_a.no_load_said = true;
                    FW_WRN("[restore] no load in %llu s after the death request: the record "
                           "stays closed until a load or the respawn brings it back",
                           static_cast<unsigned long long>(kNoLoadMs / 1000));
                }
                return;
            }
            if (now - g_a.requested_ms > kNoLoadMs) {
                // No load came (a death the engine did not reload): the game
                // still holds what the record holds.
                FW_WRN("[restore] no load in %llu s after the %s request: nothing to restore, "
                       "the record opens again", static_cast<unsigned long long>(kNoLoadMs / 1000),
                       reason_name(g_a.reason));
                g_a = Attempt{};
                g_due.store(false);
                g_curtain.store(false);
                g_open.store(true);
            }
            return;
        }
        if (fw::persist::load_in_flight()) return;
        if (g_a.load_over_ms == 0) {
            g_a.load_over_ms = now;
            g_curtain.store(true);
        }
        record_seq = g_a.record_seq;
        // Both answers: the numbers come first from the server, the channel
        // may still deliver them after the lines.
        answered   = g_a.answered && g_a.stats_answered;
        status     = g_a.status;
        if (answered) {
            lines = g_a.lines;
            if (g_a.stats_status != fw::net::kPlayerInvNone) {
                stats = g_a.stats;
                have_stats = true;
            }
        }
        late = now - g_a.load_over_ms > kGiveUpMs;
    }
    // Every wait below ends at kGiveUpMs after the load with a failure that
    // says which wait it was.
    if (!answered) {
        if (late) fail("no record from the server within 30 s of the load", record_seq);
        return;
    }
    if (!fw::native::ghost_scene_settled() || fw::engine::get_pc_parent_cell() == nullptr) {
        if (late) fail("the scene did not settle within 30 s of the load", record_seq);
        return;
    }
    if (!fw::persist::inventory::capture_now(module_base, "restore")) {   // gates: next tick
        if (late) fail("the inventory could not be read within 30 s of the load", record_seq);
        return;
    }
    const auto& m = fw::persist::inventory::last();
    if (!m.complete) {
        if (late) fail("no complete capture within 30 s of the load", record_seq);
        return;
    }
    if (status == fw::net::kPlayerInvNone) {
        FW_LOG("[restore] the server has no record to restore: the game is the record from now");
        finish(fw::net::kRestoreNothing, record_seq, 0, 0, 0, m.digest);
        fw::engine::sync_power_armor_hud("the load (no record)");
        return;
    }
    Lines want;
    std::set<Key> want_equipped;   // R2b: the lines the record flags as worn
    for (const auto& e : lines) {
        if (e.count <= 0 || e.item_base_id == 0) continue;
        if (fw::offsets::is_pa_frame_wearable(e.item_base_id)) continue;   // never inventory
        want[{e.item_base_id, e.item_fp}] += e.count;
        if (e.flags & fw::net::kInvEntryEquipped) want_equipped.insert({e.item_base_id, e.item_fp});
    }
    align(module_base, m, lines_of(m), want, want_equipped, record_seq,
          have_stats ? &stats : nullptr);
}

bool record_open() noexcept { return g_open.load(); }

bool curtain_active() noexcept { return g_curtain.load(); }

} // namespace fw::persist::restore
