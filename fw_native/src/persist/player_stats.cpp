#include "player_stats.h"

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstring>

#include "../config.h"
#include "../engine/engine_calls.h"       // get_local_player, get_pc_parent_cell, lookup_by_form_id
#include "../log.h"
#include "../native/scene_inject.h"       // ghost_scene_settled
#include "../net/client.h"
#include "../net/protocol.h"
#include "../offsets.h"
#include "inventory_restore.h"            // record_open
#include "lifecycle.h"                    // load_in_flight, exiting

namespace fw::persist::charstats {

namespace {

// Engine functions (offsets.h, L5 realtime R4). Integer parameters 64-bit,
// the project's rule; the values passed fit what the decomp shows.
using AvListFn    = void* (__fastcall*)();
using AvGetFn     = float (__fastcall*)(void* avo, void* info);
using AvFloatFn   = void  (__fastcall*)(void* avo, void* info, float value);
using GetLevelFn  = std::uint64_t (__fastcall*)(void* actor);
using HasPerkFn   = std::uint64_t (__fastcall*)(void* actor, void* perk);
using AddPerkFn   = std::uint64_t (__fastcall*)(void* actor, void* perk, std::uint64_t zero);
using SetPointsFn = std::uint64_t (__fastcall*)(void* player, std::uint64_t points);

constexpr std::size_t kSpecialOff[7] = {
    offsets::AV_LIST_STRENGTH_OFF, offsets::AV_LIST_PERCEPTION_OFF, offsets::AV_LIST_ENDURANCE_OFF,
    offsets::AV_LIST_CHARISMA_OFF, offsets::AV_LIST_INTELLIGENCE_OFF, offsets::AV_LIST_AGILITY_OFF,
    offsets::AV_LIST_LUCK_OFF,
};

std::atomic<bool> g_enabled{false};
std::uintptr_t g_base = 0;

// The actor value infos, resolved once the world is up (the engine builds
// the list itself at startup; calling the getter earlier would build it at
// a moment of our choosing).
bool  g_avs_tried = false;
bool  g_avs_ok    = false;
void* g_av_xp = nullptr;
void* g_av_health = nullptr;
void* g_av_ap = nullptr;
void* g_av_rads = nullptr;
void* g_av_special[7] = {};

Snapshot      g_sent{};          // the last numbers sent
bool          g_have_sent = false;
std::uint32_t g_seq = 0;         // STATS_STATE numbers of this process
std::uint32_t g_sent_seq = 0;
Snapshot      g_last{};          // the last capture (its perks reused between perk scans)
std::uint64_t g_last_capture_ms = 0;
std::uint64_t g_last_perks_ms = 0;

// 2026-10-15 — the SPECIAL of the record, checked AFTER the perks' own
// bumps have landed. The capture reads the base value, which the SPECIAL
// ranks of the perk chart (and the bobbleheads and the magazines: perks
// too) raise themselves a frame after AddPerk; raising it in apply() and
// then re-adding the perk counted every rank twice (live, 2026-10-15: Luck
// and Charisma +1 after each restore). Only what is still missing after
// the wait is raised: the console's and the scripts' doing.
bool          g_special_pending = false;
float         g_special_want[7] = {};
std::uint64_t g_special_set_ms = 0;
std::uint64_t g_special_due_ms = 0;
constexpr std::uint64_t kSpecialCheckDelayMs  = 2500;
constexpr std::uint64_t kSpecialCheckGiveUpMs = 15000;
constexpr const char* kSpecialShort[7] = {"S", "P", "E", "C", "I", "A", "L"};

template <class T> T fn_at(std::uintptr_t rva) { return reinterpret_cast<T>(g_base + rva); }

// ----------------------------------------------------------- SEH helpers
bool seh_ptr(const void* p, std::size_t off, void** out) noexcept {
    __try { *out = *reinterpret_cast<void* const*>(static_cast<const std::uint8_t*>(p) + off); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
bool seh_u8(const void* p, std::size_t off, std::uint8_t* out) noexcept {
    __try { *out = *(static_cast<const std::uint8_t*>(p) + off); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
bool seh_u32(const void* p, std::size_t off, std::uint32_t* out) noexcept {
    __try { *out = *reinterpret_cast<const std::uint32_t*>(static_cast<const std::uint8_t*>(p) + off); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
bool seh_f32x3(const void* p, std::size_t off, float* out) noexcept {
    __try {
        const float* f = reinterpret_cast<const float*>(static_cast<const std::uint8_t*>(p) + off);
        out[0] = f[0]; out[1] = f[1]; out[2] = f[2];
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool seh_av_list(void** out) noexcept {
    __try { *out = fn_at<AvListFn>(offsets::AV_LIST_RVA)(); return *out != nullptr; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
bool seh_av(void* avo, std::size_t slot, void* info, float* out) noexcept {
    __try {
        auto** vt = *reinterpret_cast<void***>(avo);
        *out = reinterpret_cast<AvGetFn>(vt[slot])(avo, info);
        return std::isfinite(*out);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
bool seh_av_write(void* avo, std::size_t slot, void* info, float value) noexcept {
    __try {
        auto** vt = *reinterpret_cast<void***>(avo);
        reinterpret_cast<AvFloatFn>(vt[slot])(avo, info, value);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
bool seh_level(void* actor, std::uint16_t* out) noexcept {
    __try { *out = static_cast<std::uint16_t>(fn_at<GetLevelFn>(offsets::ACTOR_GET_LEVEL_RVA)(actor) & 0xFFFF); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
bool seh_has_perk(void* actor, void* perk, std::uint8_t* rank) noexcept {
    __try { *rank = static_cast<std::uint8_t>(fn_at<HasPerkFn>(offsets::ACTOR_HAS_PERK_RVA)(actor, perk) & 0xFF); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
bool seh_add_perk(void* actor, void* perk) noexcept {
    __try { (void)fn_at<AddPerkFn>(offsets::ACTOR_ADD_PERK_RVA)(actor, perk, 0); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
bool seh_set_points(void* player, std::uint8_t points) noexcept {
    __try { (void)fn_at<SetPointsFn>(offsets::PLAYER_SET_PERK_POINTS_RVA)(player, points); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

std::uint64_t now_ms() { return GetTickCount64(); }

// An ActorValueInfo from the engine's list, checked to be one.
void* av_at(void* list, std::size_t off, const char* name) {
    void* info = nullptr;
    std::uint8_t type = 0;
    std::uint32_t id = 0;
    if (!seh_ptr(list, off, &info) || !info || !seh_u8(info, offsets::FORMTYPE_OFF, &type)
            || type != offsets::FORMTYPE_AVIF) {
        FW_ERR("[stats] the actor value '%s' at +%zu is not an ActorValueInfo (type 0x%02X)",
               name, off, unsigned(type));
        return nullptr;
    }
    (void)seh_u32(info, offsets::FORMID_OFF, &id);
    FW_DBG("[stats] actor value '%s' = form 0x%08X", name, id);
    return info;
}

bool resolve_avs() {
    if (g_avs_tried) return g_avs_ok;
    g_avs_tried = true;
    void* list = nullptr;
    if (!seh_av_list(&list)) {
        FW_ERR("[stats] the engine's actor value list could not be read: no stats this session");
        return false;
    }
    static const char* kSpecialName[7] = {"Strength", "Perception", "Endurance", "Charisma",
                                          "Intelligence", "Agility", "Luck"};
    g_av_xp     = av_at(list, offsets::AV_LIST_EXPERIENCE_OFF, "Experience");
    g_av_health = av_at(list, offsets::AV_LIST_HEALTH_OFF, "Health");
    g_av_ap     = av_at(list, offsets::AV_LIST_ACTION_POINTS_OFF, "ActionPoints");
    g_av_rads   = av_at(list, offsets::AV_LIST_RADS_OFF, "Rads");
    bool ok = g_av_xp && g_av_health && g_av_ap && g_av_rads;
    for (int i = 0; i < 7; ++i) {
        g_av_special[i] = av_at(list, kSpecialOff[i], kSpecialName[i]);
        ok = ok && g_av_special[i];
    }
    g_avs_ok = ok;
    FW_LOG("[stats] actor values %s", ok ? "resolved (Experience, Health, ActionPoints, Rads, "
                                           "the seven SPECIAL)"
                                         : "NOT all resolved: no stats this session");
    return ok;
}

// The perks the player holds, every PERK of the game asked for its rank.
bool read_perks(void* player, std::vector<std::pair<std::uint32_t, std::uint8_t>>* out) {
    void* dh = nullptr;
    if (!seh_ptr(reinterpret_cast<void*>(g_base), offsets::DATA_HANDLER_PTR_RVA, &dh) || !dh) return false;
    void* arr = nullptr;
    std::uint32_t n = 0;
    if (!seh_ptr(dh, offsets::DATA_HANDLER_PERKS_OFF, &arr) || !arr
            || !seh_u32(dh, offsets::DATA_HANDLER_PERKS_COUNT_OFF, &n) || n == 0 || n > 65536) {
        return false;
    }
    out->clear();
    for (std::uint32_t i = 0; i < n; ++i) {
        void* perk = nullptr;
        if (!seh_ptr(arr, static_cast<std::size_t>(i) * sizeof(void*), &perk)) return false;
        if (!perk) continue;
        std::uint8_t type = 0;
        if (!seh_u8(perk, offsets::FORMTYPE_OFF, &type) || type != offsets::FORMTYPE_PERK) {
            FW_ERR("[stats] entry %u of the data handler's perk array is not a PERK (type 0x%02X): "
                   "the perks are not read", i, unsigned(type));
            return false;
        }
        std::uint8_t rank = 0;
        if (!seh_has_perk(player, perk, &rank)) return false;
        if (rank == 0) continue;
        std::uint32_t id = 0;
        if (!seh_u32(perk, offsets::FORMID_OFF, &id) || id == 0) return false;
        out->emplace_back(id, rank);
    }
    std::sort(out->begin(), out->end());
    return true;
}

// One capture; false when any read failed (nothing is then sent).
bool capture(Snapshot* s, bool with_perks) {
    void* player = fw::engine::get_local_player();
    if (!player || !resolve_avs()) return false;
    void* avo = static_cast<std::uint8_t*>(player) + offsets::ACTOR_AV_OWNER_OFF;
    if (!seh_level(player, &s->level)) return false;
    if (!seh_av(avo, offsets::AVO_VT_GET_VALUE, g_av_xp, &s->xp)) return false;
    for (int i = 0; i < 7; ++i) {
        if (!seh_av(avo, offsets::AVO_VT_GET_BASE_VALUE, g_av_special[i], &s->special[i])) return false;
    }
    if (!seh_av(avo, offsets::AVO_VT_GET_VALUE, g_av_health, &s->health)) return false;
    if (!seh_av(avo, offsets::AVO_VT_GET_VALUE, g_av_ap, &s->action_points)) return false;
    if (!seh_av(avo, offsets::AVO_VT_GET_VALUE, g_av_rads, &s->rads)) return false;
    if (!seh_u8(player, offsets::PLAYER_PERK_POINTS_OFF, &s->perk_points)) return false;
    s->perks_read = false;
    if (with_perks) {
        if (!read_perks(player, &s->perks)) return false;
        s->perks_read = true;
    }
    return true;
}

// What is restored differs: it is sent at once. Health and rads (the
// vitals the server is to know, R4b 2026-10-16) trigger a send of their own
// when they moved by kVitalsStep since the last send, at most every
// kVitalsEveryMs: a fight changes them at every hit. AP only rides along
// (it moves every second while sprinting and nobody reads it).
bool differs(const Snapshot& a, const Snapshot& b) {
    if (a.level != b.level || a.perk_points != b.perk_points) return true;
    if (std::fabs(a.xp - b.xp) > 0.25f) return true;
    for (int i = 0; i < 7; ++i) if (std::fabs(a.special[i] - b.special[i]) > 0.001f) return true;
    return a.perks != b.perks;
}

constexpr float         kVitalsStep    = 10.0f;
constexpr std::uint64_t kVitalsEveryMs = 5000;
std::uint64_t g_last_vitals_ms = 0;

bool vitals_differ(const Snapshot& a, const Snapshot& b) {
    return std::fabs(a.health - b.health) >= kVitalsStep || std::fabs(a.rads - b.rads) >= kVitalsStep;
}

void send(const Snapshot& s) {
    auto& c = fw::net::client();
    fw::net::PlayerStatsHeader h{};
    h.session       = c.capture_session();
    h.seq           = ++g_seq;
    h.flags         = fw::net::kStatsFlagComplete;
    h.level         = s.level;
    h.xp            = s.xp;
    h.perk_points   = s.perk_points;
    for (int i = 0; i < 7; ++i) h.special[i] = s.special[i];
    h.health        = s.health;
    h.action_points = s.action_points;
    h.rads          = s.rads;
    std::vector<fw::net::PerkRankEntry> perks;
    perks.reserve(s.perks.size());
    for (const auto& [id, rank] : s.perks) perks.push_back({id, rank});
    c.enqueue_stats_state(h, perks.data(), perks.size());
    g_sent_seq = h.seq;
    FW_LOG("[stats] #%u sent: level %u, XP %.0f, %u perk point(s), %zu perk(s), SPECIAL "
           "%.0f/%.0f/%.0f/%.0f/%.0f/%.0f/%.0f, health %.0f, AP %.0f, rads %.0f", h.seq,
           unsigned(s.level), s.xp, unsigned(s.perk_points), s.perks.size(), s.special[0],
           s.special[1], s.special[2], s.special[3], s.special[4], s.special[5], s.special[6],
           s.health, s.action_points, s.rads);
}

// The deferred SPECIAL check (see g_special_pending). Main thread, from the
// tick, once due; a capture that fails is retried next pass, for a while.
void special_check(std::uint64_t now) {
    if (!g_special_pending || now < g_special_due_ms) return;
    Snapshot have;
    if (!capture(&have, false)) {
        if (now - g_special_set_ms > kSpecialCheckGiveUpMs) {
            g_special_pending = false;
            FW_WRN("[stats] SPECIAL not checked: the player's numbers could not be read for "
                   "%llu s after the restore; what the perks gave is there, the rest is not",
                   static_cast<unsigned long long>(kSpecialCheckGiveUpMs / 1000));
        }
        return;
    }
    g_special_pending = false;
    void* player = fw::engine::get_local_player();
    if (!player) return;
    void* avo = static_cast<std::uint8_t*>(player) + offsets::ACTOR_AV_OWNER_OFF;
    unsigned raised = 0, failed = 0;
    for (int i = 0; i < 7; ++i) {
        if (g_special_want[i] <= have.special[i] + 0.001f) continue;
        if (seh_av_write(avo, offsets::AVO_VT_SET_VALUE, g_av_special[i], g_special_want[i])) {
            ++raised;
            FW_LOG("[stats] %s %.0f -> %.0f: raised to the record's (not a perk's doing: the "
                   "console or a script)", kSpecialShort[i], have.special[i], g_special_want[i]);
        } else {
            ++failed;
        }
    }
    FW_LOG("[stats] SPECIAL checked %llu ms after the restore: %u raised, %u failed, the perks' "
           "own bumps counted (now %.0f/%.0f/%.0f/%.0f/%.0f/%.0f/%.0f, the record "
           "%.0f/%.0f/%.0f/%.0f/%.0f/%.0f/%.0f)",
           static_cast<unsigned long long>(now - g_special_set_ms), raised, failed,
           have.special[0], have.special[1], have.special[2], have.special[3], have.special[4],
           have.special[5], have.special[6], g_special_want[0], g_special_want[1],
           g_special_want[2], g_special_want[3], g_special_want[4], g_special_want[5],
           g_special_want[6]);
}

} // namespace

void configure(const fw::config::Settings& cfg) {
    g_enabled.store(cfg.inventory_capture);
}

void tick(std::uintptr_t module_base) {
    if (!g_enabled.load() || !module_base) return;
    g_base = module_base;
    if (!fw::persist::restore::record_open()) return;
    if (fw::persist::exiting() || fw::persist::load_in_flight()) return;
    if (!fw::native::ghost_scene_settled() || fw::engine::get_pc_parent_cell() == nullptr) return;
    const std::uint64_t now = now_ms();
    special_check(now);   // 2026-10-15: the record's SPECIAL, after the perks' bumps
    // R6 (2026-10-16): where the player stands, every five seconds, for the
    // crash campaign (tools/crash_campaign.py compares the last line before
    // a kill with the first after the relaunch).
    static std::uint64_t s_last_pos_ms = 0;
    if (now - s_last_pos_ms >= 5000) {
        s_last_pos_ms = now;
        float pos[3] = {0.0f, 0.0f, 0.0f};
        std::uint32_t cell = 0;
        void* player = fw::engine::get_local_player();
        void* pcell = fw::engine::get_pc_parent_cell();
        if (player && seh_f32x3(player, offsets::POS_OFF, pos)) {
            if (pcell) (void)seh_u32(pcell, offsets::FORMID_OFF, &cell);
            FW_LOG("[stats] position (%.1f, %.1f, %.1f) cell 0x%08X", pos[0], pos[1], pos[2], cell);
        }
    }
    if (now - g_last_capture_ms < 1000) return;
    g_last_capture_ms = now;
    Snapshot s;
    // The perks every five seconds, or at once when the level or the perk
    // points moved (a perk taken spends a point).
    const bool perks_due = now - g_last_perks_ms >= 5000 || !g_last.perks_read;
    if (!capture(&s, perks_due)) {
        // A failed perk scan or read is retried at the next pass.
        return;
    }
    if (!perks_due && (s.level != g_last.level || s.perk_points != g_last.perk_points)) {
        if (!capture(&s, true)) return;
    }
    if (s.perks_read) {
        g_last_perks_ms = now;
    } else {
        s.perks = g_last.perks;
        s.perks_read = g_last.perks_read;
    }
    g_last = s;
    const bool core = !g_have_sent || differs(s, g_sent);
    const bool vitals = !core && vitals_differ(s, g_sent) && now - g_last_vitals_ms >= kVitalsEveryMs;
    if (!core && !vitals) return;
    send(s);
    g_sent = s;
    g_have_sent = true;
    if (vitals) g_last_vitals_ms = now;
}

std::uint32_t last_sent_seq() { return g_sent_seq; }

ApplyResult apply(std::uintptr_t module_base, const Snapshot& want) {
    ApplyResult r;
    g_base = module_base;
    Snapshot have;
    if (!capture(&have, true)) {
        FW_ERR("[stats] the player's numbers could not be read: the record's are not put back");
        return r;
    }
    void* player = fw::engine::get_local_player();
    void* avo = static_cast<std::uint8_t*>(player) + offsets::ACTOR_AV_OWNER_OFF;
    r.level_before = have.level;
    // XP first: the engine runs the level-ups (and gives their perk points).
    if (want.xp > have.xp + 0.5f) {
        const float missing = want.xp - have.xp;
        if (seh_av_write(avo, offsets::AVO_VT_MOD_BASE_VALUE, g_av_xp, missing)) r.xp_awarded = missing;
    }
    // The SPECIAL: not now. The ranks re-added below raise the base value
    // themselves a frame later; the tick checks the record's values after
    // that (special_check) and raises only what the perks did not.
    unsigned special_short = 0;
    for (int i = 0; i < 7; ++i) {
        g_special_want[i] = want.special[i];
        if (want.special[i] > have.special[i] + 0.001f) ++special_short;
    }
    g_special_set_ms = now_ms();
    g_special_due_ms = g_special_set_ms + kSpecialCheckDelayMs;
    g_special_pending = true;
    for (const auto& [id, rank] : want.perks) {
        void* perk = fw::engine::lookup_by_form_id(id);
        std::uint8_t type = 0;
        if (!perk || !seh_u8(perk, offsets::FORMTYPE_OFF, &type) || type != offsets::FORMTYPE_PERK) {
            ++r.perks_unresolved;
            FW_WRN("[stats] perk 0x%08X of the record is not a PERK here: not added", id);
            continue;
        }
        std::uint8_t now_rank = 0;
        if (!seh_has_perk(player, perk, &now_rank)) { ++r.perks_unresolved; continue; }
        for (int guard = 0; now_rank < rank && guard < 8; ++guard) {
            if (!seh_add_perk(player, perk)) break;
            std::uint8_t after = 0;
            if (!seh_has_perk(player, perk, &after) || after <= now_rank) break;
            r.perks_added += after - now_rank;
            now_rank = after;
        }
        if (now_rank < rank) {
            ++r.perks_unresolved;
            FW_WRN("[stats] perk 0x%08X: rank %u in the record, %u reached", id, unsigned(rank),
                   unsigned(now_rank));
        }
    }
    // The perk points last, the level-ups above gave some of their own.
    std::uint8_t points = 0;
    if (seh_u8(player, offsets::PLAYER_PERK_POINTS_OFF, &points) && points != want.perk_points) {
        r.points_set = seh_set_points(player, want.perk_points);
    }
    Snapshot after;
    if (capture(&after, false)) r.level_after = after.level;
    r.ok = true;
    FW_LOG("[stats] put back: XP +%.0f (level %u -> %u), %u perk rank(s) added, %u perk(s) not "
           "reached, perk points %s %u; the SPECIAL %s", r.xp_awarded,
           unsigned(r.level_before), unsigned(r.level_after), r.perks_added,
           r.perks_unresolved, r.points_set ? "set to" : "already", unsigned(want.perk_points),
           special_short ? "checked in 2.5 s (short now, the perks' own bumps first)"
                         : "already the record's (checked in 2.5 s anyway)");
    return r;
}

} // namespace fw::persist::charstats
