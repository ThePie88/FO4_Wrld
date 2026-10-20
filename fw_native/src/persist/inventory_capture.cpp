#include "inventory_capture.h"

#include <windows.h>

#include <cmath>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "../config.h"
#include "../engine/engine_calls.h"     // get_local_player
#include "../hooks/workbench_hook.h"    // pa_mod_menu_open
#include "../log.h"
#include "../main_thread_dispatch.h"    // pending_count: undos not applied yet
#include "../native/scene_inject.h"     // ghost_scene_settled
#include "../net/client.h"              // enqueue_inv_digest
#include "../net/protocol.h"            // PaPieceEntry: the wire descriptor of a dropped item
#include "../offsets.h"
#include "../ref_identity.h"            // read_ref_identity
#include "inventory_tap.h"              // the boundary events since the last capture
#include "instance_fp.h"                // fp_of_record: the line of a stack
#include "instance_probe.h"             // stage 4a: the records at info, in the probe's format
#include "inventory_restore.h"          // R2: INV_STATE only while the game holds the record
#include "lifecycle.h"                  // load_in_flight

namespace fw::persist::inventory {

namespace {

// ---------------------------------------------------------------- engine
using LockFn        = void (__fastcall*)(void* lock);           // sub_141658FE0 / sub_1416592B0
using EntryCountFn  = std::int64_t (__fastcall*)(void* entry);  // sub_140349B30
using QuestItemFn   = std::uint64_t (__fastcall*)(void* xlist); // sub_14028F070 (second arg is scratch)
using HealthFn      = float (__fastcall*)(void* xlist);         // sub_14027FDA0 (second arg is scratch)
using CStrFn        = const char* (__fastcall*)(void* field);   // sub_14167CA00
using GetByTypeFn   = void* (__fastcall*)(void* xlist, std::uint64_t type); // sub_1402A0030
using MenuNameFn    = const void* (*)();
using MenuIsOpenFn  = bool (*)(void* ui, const void* name);

std::uintptr_t g_base = 0;
LockFn        g_read_lock   = nullptr;
LockFn        g_read_unlock = nullptr;
EntryCountFn  g_entry_count = nullptr;
QuestItemFn   g_quest_item  = nullptr;
HealthFn      g_health      = nullptr;
CStrFn        g_cstr        = nullptr;
GetByTypeFn   g_get_by_type = nullptr;

// The 24 persisted types, in the bit order of StackRecord::extra_mask.
constexpr std::uint8_t TYPE_ORDER[24] = {
    offsets::EXTRA_TYPE_REFERENCE_HANDLES, offsets::EXTRA_TYPE_OWNERSHIP,
    offsets::EXTRA_TYPE_GLOBAL, offsets::EXTRA_TYPE_RANK, offsets::EXTRA_TYPE_COUNT,
    offsets::EXTRA_TYPE_HEALTH, offsets::EXTRA_TYPE_TIME_LEFT, offsets::EXTRA_TYPE_CHARGE,
    offsets::EXTRA_TYPE_LEVELED_ITEM, offsets::EXTRA_TYPE_SCALE, offsets::EXTRA_TYPE_OIE,
    offsets::EXTRA_TYPE_CANNOT_WEAR, offsets::EXTRA_TYPE_POISON,
    offsets::EXTRA_TYPE_STARTING_WORLD, offsets::EXTRA_TYPE_FAVORITE,
    offsets::EXTRA_TYPE_ALIAS_INSTANCES, offsets::EXTRA_TYPE_OUTFIT_ITEM,
    offsets::EXTRA_TYPE_FROM_ALIAS, offsets::EXTRA_TYPE_TEXT_DISPLAY,
    offsets::EXTRA_TYPE_ENCHANTMENT, offsets::EXTRA_TYPE_SOUL, offsets::EXTRA_TYPE_UNIQUE_ID,
    offsets::EXTRA_TYPE_FLAGS, offsets::EXTRA_TYPE_MOD_RANK,
};

int type_bit(std::uint8_t type) noexcept {
    for (int i = 0; i < 24; ++i) if (TYPE_ORDER[i] == type) return i;
    return -1;
}

// The vtable that proves a node's type byte; 0 = no check known.
std::uintptr_t vtable_for(std::uint8_t type) noexcept {
    switch (type) {
    case offsets::EXTRA_TYPE_HEALTH:          return offsets::EXTRA_VT_HEALTH_RVA;
    case offsets::EXTRA_TYPE_CHARGE:          return offsets::EXTRA_VT_CHARGE_RVA;
    case offsets::EXTRA_TYPE_OIE:             return offsets::EXTRA_VT_OIE_RVA;
    case offsets::EXTRA_TYPE_FAVORITE:        return offsets::EXTRA_VT_FAVORITE_RVA;
    case offsets::EXTRA_TYPE_TEXT_DISPLAY:    return offsets::EXTRA_VT_TEXT_DISPLAY_RVA;
    case offsets::EXTRA_TYPE_UNIQUE_ID:       return offsets::EXTRA_VT_UNIQUE_ID_RVA;
    case offsets::EXTRA_TYPE_ALIAS_INSTANCES: return offsets::EXTRA_VT_ALIAS_INSTANCES_RVA;
    case offsets::EXTRA_TYPE_ENCHANTMENT:     return offsets::EXTRA_VT_ENCHANTMENT_RVA;
    case offsets::EXTRA_TYPE_POISON:          return offsets::EXTRA_VT_POISON_RVA;
    case offsets::EXTRA_TYPE_OWNERSHIP:       return offsets::EXTRA_VT_OWNERSHIP_RVA;
    case offsets::EXTRA_TYPE_COUNT:           return offsets::EXTRA_VT_COUNT_RVA;
    case offsets::EXTRA_TYPE_TIME_LEFT:       return offsets::EXTRA_VT_TIME_LEFT_RVA;
    case offsets::EXTRA_TYPE_FLAGS:           return offsets::EXTRA_VT_FLAGS_RVA;
    case offsets::EXTRA_TYPE_CANNOT_WEAR:     return offsets::EXTRA_VT_CANNOT_WEAR_RVA;
    case offsets::EXTRA_TYPE_SCALE:           return offsets::EXTRA_VT_SCALE_RVA;
    default: return 0;
    }
}

// ---------------------------------------------------------------- state
Manifest g_last{};
Manifest g_work{};
std::uint64_t g_last_digest = 0;
std::uint64_t g_last_tick_ms = 0;
std::uint32_t g_seq = 0;
std::uint32_t g_skips_writer = 0;
std::uint32_t g_skips_gate = 0;
std::uint32_t g_max_us = 0;
std::uint64_t g_last_stats_ms = 0;
bool g_resolved = false;
bool g_logged_no_list = false;
bool g_enabled = true;
std::wstring g_out_dir;

std::uint64_t wall_ms() noexcept;   // defined with the other clocks below

// INV_DIGEST bookkeeping: what was sent last, and when.
std::uint64_t g_sent_digest = 0;
std::uint64_t g_sent_at_ms  = 0;
std::uint32_t g_sent_count  = 0;
constexpr std::uint64_t kDigestMinIntervalMs = 10000;   // the dossier's cadence

// L5 realtime R1 (2026-10-03): INV_STATE bookkeeping. The digest of the last
// capture sent as the player's record, and the tap's count at the last
// capture: when it moved, the next capture comes after kEventCaptureMs
// instead of the second (and so does a retry of a capture not sent yet).
std::uint64_t g_state_digest = 0;
bool          g_state_sent   = false;
std::uint32_t g_state_seq    = 0;
std::uint64_t g_tap_seen     = 0;
constexpr std::uint64_t kEventCaptureMs = 250;

std::uint32_t total_items(const Manifest& m) noexcept {
    std::uint64_t n = 0;
    for (std::uint32_t i = 0; i < m.stacks; ++i) {
        if (m.records[i].count > 0) n += static_cast<std::uint64_t>(m.records[i].count);
    }
    return n > 0xFFFFFFFFull ? 0xFFFFFFFFu : static_cast<std::uint32_t>(n);
}

// Sends `m` as INV_DIGEST. Not forced: only a new digest, and not within
// 10 s of the previous send (the tick asks again a second later). Forced:
// now, whatever the cadence (checkpoint, exit). Never an incomplete one.
void send_digest(const Manifest& m, std::uint8_t why, bool force) {
    if (m.seq == 0 || !m.complete) return;
    const std::uint64_t now = wall_ms();
    if (!force) {
        if (m.digest == g_sent_digest && g_sent_count > 0) return;
        if (g_sent_count > 0 && now - g_sent_at_ms < kDigestMinIntervalMs) return;
    }
    fw::net::InvDigestPayload p{};
    p.seq     = m.seq;
    p.wall_ms = m.wall_ms;
    p.digest  = m.digest;
    p.entries = m.entries;
    p.stacks  = m.stacks;
    p.items   = total_items(m);
    p.reasons = m.reasons;
    p.flags   = static_cast<std::uint8_t>(fw::net::kInvDigestFlagComplete
                | (m.in_power_armor ? fw::net::kInvDigestFlagInPowerArmor : 0));
    p.why     = (g_sent_count == 0 && why == fw::net::kInvDigestWhyChange)
              ? fw::net::kInvDigestWhyFirst : why;
    fw::net::client().enqueue_inv_digest(p);
    g_sent_digest = m.digest;
    g_sent_at_ms  = now;
    ++g_sent_count;
    static const char* const kWhy[] = {"changed", "checkpoint", "exit", "first"};
    FW_LOG("[inv] INV_DIGEST #%u sent (%s): capture #%u digest=%016llX, %u stacks, %u items%s",
           g_sent_count, p.why < 4 ? kWhy[p.why] : "?", m.seq,
           static_cast<unsigned long long>(m.digest), m.stacks, p.items,
           m.in_power_armor ? ", in power armor" : "");
}

void json_escape(const char* s, char* out, std::size_t n) {
    std::size_t j = 0;
    for (const char* c = s; *c && j + 2 < n; ++c) {
        if (*c == '"' || *c == '\\') { out[j++] = '\\'; out[j++] = *c; }
        else if (static_cast<unsigned char>(*c) < 0x20) { out[j++] = ' '; }
        else out[j++] = *c;
    }
    out[j] = '\0';
}

bool write_json(const Manifest& m, const wchar_t* path) {
    FILE* f = nullptr;
    if (_wfopen_s(&f, path, L"wb") != 0 || !f) return false;
    std::fprintf(f, "{\n  \"seq\": %u,\n  \"wall_ms\": %llu,\n  \"complete\": %s,\n"
                    "  \"reasons\": %u,\n  \"digest\": \"%016llX\",\n  \"entries\": %u,\n"
                    "  \"stacks\": %u,\n  \"transient\": %u,\n  \"in_power_armor\": %s,\n"
                    "  \"records\": [\n",
                 m.seq, static_cast<unsigned long long>(m.wall_ms), m.complete ? "true" : "false",
                 m.reasons, static_cast<unsigned long long>(m.digest), m.entries, m.stacks,
                 m.transient, m.in_power_armor ? "true" : "false");
    for (std::uint32_t i = 0; i < m.stacks; ++i) {
        const StackRecord& r = m.records[i];
        char name[MAX_NAME * 2 + 4];
        json_escape(r.name, name, sizeof(name));
        std::fprintf(f, "    {\"base\": %u, \"form_type\": %u, \"count\": %d, \"flags\": %u, "
                        "\"extra_mask\": %u, \"quest_item\": %s, \"health\": ",
                     r.base_id, unsigned(r.form_type), r.count, unsigned(r.flags), r.extra_mask,
                     r.quest_item ? "true" : "false");
        if (std::isnan(r.health)) std::fprintf(f, "null"); else std::fprintf(f, "%.6g", r.health);
        std::fprintf(f, ", \"charge\": ");
        if (std::isnan(r.charge)) std::fprintf(f, "null"); else std::fprintf(f, "%.6g", r.charge);
        std::fprintf(f, ", \"favorite\": ");
        if (r.favorite == 0xFF) std::fprintf(f, "null"); else std::fprintf(f, "%u", unsigned(r.favorite));
        std::fprintf(f, ", \"uid\": ");
        if (r.extra_mask & (1u << 21)) std::fprintf(f, "%u", unsigned(r.uid)); else std::fprintf(f, "null");
        std::fprintf(f, ", \"template\": ");
        if (r.extra_mask & (1u << 10)) std::fprintf(f, "%u", unsigned(r.oie_template)); else std::fprintf(f, "null");
        std::fprintf(f, ", \"mods\": [");
        for (std::uint32_t k = 0; k < r.oie_count; ++k) {
            std::fprintf(f, "%s[%u, %u, %u, %u]", k ? ", " : "", r.oie[k].mod_form_id,
                         unsigned(r.oie[k].attach_index), unsigned(r.oie[k].rank), unsigned(r.oie[k].flag));
        }
        std::fprintf(f, "], \"name\": ");
        if (r.name[0]) std::fprintf(f, "\"%s\"", name); else std::fprintf(f, "null");
        std::fprintf(f, ", \"text_owner\": %d, \"opaque\": %u, \"unverified\": %u}%s\n",
                     r.text_owner, r.opaque_types, r.unverified_types,
                     (i + 1 < m.stacks) ? "," : "");
    }
    std::fprintf(f, "  ]\n}\n");
    std::fclose(f);
    return true;
}

// Per-base totals of the previous complete capture, sorted by base, and the
// tapped deltas since it: the reconciliation compares the two.
struct BaseCount { std::uint32_t base; std::int64_t count; };
BaseCount g_prev_totals[MAX_STACKS];
std::uint32_t g_prev_n = 0;
bool g_prev_valid = false;
BaseCount g_tapped[MAX_STACKS];
std::uint32_t g_tapped_n = 0;
std::uint32_t g_unexplained_total = 0;

void tapped_add(std::uint32_t base, std::int64_t delta) {
    for (std::uint32_t i = 0; i < g_tapped_n; ++i) {
        if (g_tapped[i].base == base) { g_tapped[i].count += delta; return; }
    }
    if (g_tapped_n < MAX_STACKS) {
        g_tapped[g_tapped_n].base = base;
        g_tapped[g_tapped_n].count = delta;
        ++g_tapped_n;
    }
}

std::int64_t tapped_for(std::uint32_t base) {
    for (std::uint32_t i = 0; i < g_tapped_n; ++i) if (g_tapped[i].base == base) return g_tapped[i].count;
    return 0;
}

// Drain the tap: log each event (adds during a load are the save's own
// inventory and are only counted), accumulate per base for the reconcile.
void drain_tap() {
    static fw::persist::tap::Event events[fw::persist::tap::RING];
    std::uint32_t dropped = 0;
    const std::size_t n = fw::persist::tap::drain(events, fw::persist::tap::RING, &dropped);
    if (dropped) FW_WRN("[inv-tap] %u event(s) lost to a full ring", dropped);
    std::uint32_t in_load = 0;
    for (std::size_t i = 0; i < n; ++i) {
        const auto& e = events[i];
        if (e.during_load) { ++in_load; continue; }
        tapped_add(e.base_id, e.delta);
        const char* name = fw::persist::tap::cause_name(e.cause);
        FW_LOG("[inv-tap] %+d x 0x%06X %s (cause 0x%X, other 0x%X, tid %u)", e.delta, e.base_id,
               name ? name : "cause unknown", e.cause, e.other, e.tid);
    }
    if (in_load) FW_DBG("[inv-tap] %u event(s) during a load counted, not listed", in_load);
}

// Per-base totals of a canonical manifest (records sorted by base).
std::uint32_t totals_of(const Manifest& m, BaseCount* out) {
    std::uint32_t n = 0;
    for (std::uint32_t i = 0; i < m.stacks; ++i) {
        const auto& r = m.records[i];
        if (n > 0 && out[n - 1].base == r.base_id) out[n - 1].count += r.count;
        else if (n < MAX_STACKS) { out[n].base = r.base_id; out[n].count = r.count; ++n; }
    }
    return n;
}

// Compare the new totals with the previous ones and with the tapped
// deltas; every base whose change the tap did not see is a flow the
// stage must still cover, and is logged as such.
void reconcile(const Manifest& m) {
    static BaseCount now_totals[MAX_STACKS];
    const std::uint32_t now_n = totals_of(m, now_totals);
    if (g_prev_valid && m.complete) {
        std::uint32_t i = 0, j = 0, unexplained = 0, explained = 0;
        while (i < g_prev_n || j < now_n) {
            std::uint32_t base;
            std::int64_t before = 0, after = 0;
            if (j >= now_n || (i < g_prev_n && g_prev_totals[i].base < now_totals[j].base)) {
                base = g_prev_totals[i].base; before = g_prev_totals[i].count; ++i;
            } else if (i >= g_prev_n || now_totals[j].base < g_prev_totals[i].base) {
                base = now_totals[j].base; after = now_totals[j].count; ++j;
            } else {
                base = now_totals[j].base; before = g_prev_totals[i].count;
                after = now_totals[j].count; ++i; ++j;
            }
            const std::int64_t delta = after - before;
            if (delta == 0) continue;
            const std::int64_t seen = tapped_for(base);
            if (seen == delta) { ++explained; continue; }
            ++unexplained;
            FW_LOG("[inv] UNEXPLAINED change: 0x%06X %+lld (the tap saw %+lld): a flow the "
                   "tap does not cover", base, static_cast<long long>(delta),
                   static_cast<long long>(seen));
        }
        if (unexplained) g_unexplained_total += unexplained;
        if (explained || unexplained) {
            FW_DBG("[inv] reconcile: %u change(s) explained by the tap, %u not", explained, unexplained);
        }
    }
    if (m.complete) {
        std::memcpy(g_prev_totals, now_totals, sizeof(BaseCount) * now_n);
        g_prev_n = now_n;
        g_prev_valid = true;
        g_tapped_n = 0;
    }
}

std::uint64_t wall_ms() noexcept {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    const std::uint64_t t = (static_cast<std::uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    return (t - 116444736000000000ull) / 10000ull;   // FILETIME epoch to Unix ms
}

std::uint64_t qpc_us() noexcept {
    static LARGE_INTEGER freq{};
    if (freq.QuadPart == 0) QueryPerformanceFrequency(&freq);
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    return static_cast<std::uint64_t>(now.QuadPart) * 1000000ull / static_cast<std::uint64_t>(freq.QuadPart);
}

// ---------------------------------------------------------------- SEH readers
void* rd_ptr(const void* p, std::size_t off) noexcept {
    if (!p) return nullptr;
    __try { return *reinterpret_cast<void* const*>(static_cast<const std::uint8_t*>(p) + off); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}
bool rd_u32(const void* p, std::size_t off, std::uint32_t* out) noexcept {
    if (!p) return false;
    __try { *out = *reinterpret_cast<const std::uint32_t*>(static_cast<const std::uint8_t*>(p) + off); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
bool rd_u16(const void* p, std::size_t off, std::uint16_t* out) noexcept {
    if (!p) return false;
    __try { *out = *reinterpret_cast<const std::uint16_t*>(static_cast<const std::uint8_t*>(p) + off); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
bool rd_u8(const void* p, std::size_t off, std::uint8_t* out) noexcept {
    if (!p) return false;
    __try { *out = *(static_cast<const std::uint8_t*>(p) + off); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
bool rd_f32(const void* p, std::size_t off, float* out) noexcept {
    if (!p) return false;
    __try { *out = *reinterpret_cast<const float*>(static_cast<const std::uint8_t*>(p) + off); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
std::uintptr_t rd_vtable(const void* p) noexcept {
    if (!p) return 0;
    __try { return *reinterpret_cast<const std::uintptr_t*>(p); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}
bool copy_cstr(const char* s, char* out, std::size_t n) noexcept {
    if (!out || n == 0) return false;
    out[0] = '\0';
    if (!s) return false;
    __try {
        std::size_t i = 0;
        for (; i + 1 < n; ++i) { const char c = s[i]; if (!c) break; out[i] = c; }
        out[i] = '\0';
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { out[0] = '\0'; return false; }
}
std::uint32_t form_id_of(const void* form) noexcept {
    std::uint32_t id = 0;
    if (!form) return 0;
    if (!rd_u32(form, offsets::FORMID_OFF, &id)) return 0;
    return id;
}

// Engine calls, each in its own SEH cage.
bool call_lock(LockFn fn, void* lock) noexcept {
    if (!fn || !lock) return false;
    __try { fn(lock); return true; } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
std::int64_t call_entry_count(void* entry) noexcept {
    if (!g_entry_count || !entry) return -1;
    __try { return g_entry_count(entry); } __except (EXCEPTION_EXECUTE_HANDLER) { return -1; }
}
int call_quest_item(void* xlist) noexcept {
    if (!g_quest_item || !xlist) return -1;
    __try { return g_quest_item(xlist) ? 1 : 0; } __except (EXCEPTION_EXECUTE_HANDLER) { return -1; }
}
bool call_health(void* xlist, float* out) noexcept {
    if (!g_health || !xlist) return false;
    __try { *out = g_health(xlist); return true; } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
const char* call_cstr(void* field) noexcept {
    if (!g_cstr || !field) return nullptr;
    __try { return g_cstr(field); } __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}
void* call_get_by_type(void* xlist, std::uint8_t type) noexcept {
    if (!g_get_by_type || !xlist) return nullptr;
    __try { return g_get_by_type(xlist, type); } __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}
bool container_menu_open() noexcept {
    __try {
        void* ui = *reinterpret_cast<void**>(g_base + offsets::UI_SINGLETON_RVA);
        if (!ui) return false;
        const void* name = reinterpret_cast<MenuNameFn>(g_base + offsets::CONTAINER_MENU_NAME_RVA)();
        if (!name) return false;
        return reinterpret_cast<MenuIsOpenFn>(g_base + offsets::UI_MENU_IS_OPEN_RVA)(ui, name);
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// ---------------------------------------------------------------- decoding
//
// One extra node into the record. The node's type byte was already read
// and its vtable checked (or unknown, in which case the type is counted as
// opaque and nothing is decoded). Returns false on a faulted read.
bool decode_extra(void* node, std::uint8_t type, StackRecord* r) noexcept {
    switch (type) {
    case offsets::EXTRA_TYPE_HEALTH:
        return rd_f32(node, offsets::EXTRA_PAYLOAD_OFF, &r->health);
    case offsets::EXTRA_TYPE_CHARGE:
        return rd_f32(node, offsets::EXTRA_PAYLOAD_OFF, &r->charge);
    case offsets::EXTRA_TYPE_FAVORITE:
        return rd_u8(node, offsets::EXTRA_PAYLOAD_OFF, &r->favorite);
    case offsets::EXTRA_TYPE_UNIQUE_ID:
        return rd_u16(node, offsets::EXTRA_PAYLOAD_OFF, &r->uid)
            && rd_u32(node, offsets::EXTRA_UNIQUE_ID_OWNER_OFF, &r->uid_owner);
    case offsets::EXTRA_TYPE_MOD_RANK:
        return rd_u32(node, offsets::EXTRA_PAYLOAD_OFF, &r->mod_rank);
    case offsets::EXTRA_TYPE_COUNT:
        // Only ever seen on a WORLD REFR's list (a dropped stack); an
        // inventory stack keeps its count in the Stack itself.
        return rd_u16(node, offsets::EXTRA_PAYLOAD_OFF, &r->extra_count);
    case offsets::EXTRA_TYPE_ENCHANTMENT:
        r->enchantment = form_id_of(rd_ptr(node, offsets::EXTRA_ENCHANT_FORM_OFF));
        return true;
    case offsets::EXTRA_TYPE_TEXT_DISPLAY: {
        std::uint32_t owner = 0;
        if (!rd_u32(node, offsets::EXTRA_TEXT_OWNER_OFF, &owner)) return false;
        r->text_owner   = static_cast<std::int32_t>(owner);
        r->text_message = form_id_of(rd_ptr(node, offsets::EXTRA_TEXT_MESSAGE_OFF));
        r->text_quest   = form_id_of(rd_ptr(node, offsets::EXTRA_TEXT_QUEST_OFF));
        std::uint16_t hdr = 0;
        if (rd_u16(node, offsets::BSEXTRADATA_FLAGS_OFF, &hdr)) r->name_is_rename = (hdr & 1) ? 1 : 0;
        // The save writes the literal only under this condition; so do we.
        if (r->text_owner == -2 && r->text_message == 0 && r->text_quest == 0) {
            void* field = static_cast<std::uint8_t*>(node) + offsets::EXTRA_TEXT_NAME_OFF;
            copy_cstr(call_cstr(field), r->name, sizeof(r->name));
        }
        return true;
    }
    case offsets::EXTRA_TYPE_OIE: {
        rd_u16(node, offsets::OIE_TEMPLATE_INDEX_OFF, &r->oie_template);
        // +0x18 holds a POINTER to the {data*, byte length} pair, not the
        // pair itself: the engine's own creation path (sub_140248F40) zeroes
        // that slot on a fresh node and fills it with the first mod. The
        // first live capture (2026-09-27) read the slot as if it were inline
        // and reported every modded weapon as mods=0.
        void* inner = rd_ptr(node, offsets::BGSOBJECTINSTANCEEXTRA_INNER_OFF);
        if (!inner) return true;   // a fresh node: no mods yet
        void* data = rd_ptr(inner, offsets::OIE_INNER_DATA_OFF);
        std::uint32_t dir_off = 0;
        if (!rd_u32(inner, offsets::OIE_INNER_DATA_BYTELEN_OFF, &dir_off)) return false;
        if (!data || dir_off < offsets::OBJMOD_RECORD_STRIDE || dir_off > 65536) return true;
        // The engine's own count: the directory entry at data+dir_off,
        // tagged 0; the flat count bounds it.
        std::uint32_t n = dir_off / offsets::OBJMOD_RECORD_STRIDE;
        std::uint32_t dir = 0;
        if (rd_u32(data, dir_off, &dir)) {
            const std::uint8_t tag = static_cast<std::uint8_t>(dir >> 24);
            if (tag == 0) { const std::uint32_t c = (dir & 0xFFFFFFu) >> 3; if (c < n) n = c; }
            else if (tag == 0xFF) n = 0;
        }
        std::uint32_t kept = 0;
        for (std::uint32_t i = 0; i < n; ++i) {
            if (kept >= MAX_OIE_RECORDS) { r->oie_truncated = 1; break; }
            const std::size_t off = static_cast<std::size_t>(i) * offsets::OBJMOD_RECORD_STRIDE;
            std::uint32_t mod = 0;
            std::uint8_t a = 0, rk = 0, fl = 0;
            if (!rd_u32(data, off, &mod) || !rd_u8(data, off + 4, &a)
                    || !rd_u8(data, off + 5, &rk) || !rd_u8(data, off + 6, &fl)) return false;
            r->oie[kept].mod_form_id = mod; r->oie[kept].attach_index = a;
            r->oie[kept].rank = rk; r->oie[kept].flag = fl; r->oie[kept].pad = 0;
            ++kept;
        }
        r->oie_count = static_cast<std::uint8_t>(kept);
        return true;
    }
    default:
        return true;   // present, no payload decoded (its presence bit is enough)
    }
}

// Walk one extra list into the record. `reasons` collects what went
// wrong. Takes and releases the list's read lock around the walk.
void read_extras(void* xlist, StackRecord* r, std::uint32_t* reasons) noexcept {
    std::uint32_t counter = 0;
    if (!rd_u32(xlist, offsets::EXTRALIST_LOCK_COUNTER_OFF, &counter)) { *reasons |= REASON_SEH; return; }
    if (counter & 0x80000000u) { *reasons |= REASON_EXTRAS_UNREAD; return; }
    void* lock = static_cast<std::uint8_t*>(xlist) + offsets::EXTRALIST_LOCK_OFF;
    if (!call_lock(g_read_lock, lock)) { *reasons |= REASON_SEH; return; }

    void* node = rd_ptr(xlist, offsets::BSEXTRADATALIST_HEAD_OFF);
    int guard = 0;
    while (node) {
        if (++guard > 64) { *reasons |= REASON_CAPS; break; }
        std::uint8_t type = 0;
        if (!rd_u8(node, offsets::BSEXTRADATA_TYPE_BYTE_OFF, &type)) { *reasons |= REASON_SEH; break; }
        const int bit = type_bit(type);
        if (bit < 0) {
            ++r->opaque_types;
        } else {
            const std::uintptr_t want = vtable_for(type);
            if (want != 0 && rd_vtable(node) != g_base + want) {
                ++r->unverified_types;
            } else {
                r->extra_mask |= (1u << bit);
                if (!decode_extra(node, type, r)) *reasons |= REASON_SEH;
            }
        }
        node = rd_ptr(node, offsets::BSEXTRADATA_NEXT_OFF);
    }
    call_lock(g_read_unlock, lock);

    // Two engine opinions on what was just read, cheap and on the main
    // thread: the quest-item test (follows 0x1C, tests 0x88) and the
    // health accessor (0x25 or -1).
    const int q = call_quest_item(xlist);
    r->quest_item = q > 0 ? 1 : 0;
    float h = 0.0f;
    if (call_health(xlist, &h)) {
        const bool have = !std::isnan(r->health);
        if ((have && h != r->health) || (!have && h != -1.0f)) *reasons |= REASON_HEALTH_CHECK;
    }
}

// The locked walk. POD only, __finally releases the list lock.
void walk_locked(void* list, Manifest* m, std::uint32_t* reasons) noexcept {
    void* lock = static_cast<std::uint8_t*>(list) + offsets::INVLIST_MUTEX_OFF;
    if (!call_lock(g_read_lock, lock)) { *reasons |= REASON_SEH; return; }
    __try {
        std::uint32_t entry_count = 0;
        void* entries = rd_ptr(list, offsets::INVLIST_ENTRIES_OFF);
        if (!rd_u32(list, offsets::INVLIST_COUNT_OFF, &entry_count) || !entries) { *reasons |= REASON_SEH; return; }
        if (entry_count > 4096) { *reasons |= REASON_CAPS; entry_count = 4096; }
        m->entries = entry_count;
        for (std::uint32_t i = 0; i < entry_count; ++i) {
            void* entry = static_cast<std::uint8_t*>(entries) + static_cast<std::size_t>(i) * offsets::INVENTORY_ITEM_STRIDE;
            void* obj = rd_ptr(entry, offsets::INVENTORY_ITEM_OBJ_OFF);
            if (!obj) continue;
            const std::uint32_t base_id = form_id_of(obj);
            std::uint8_t form_type = 0;
            rd_u8(obj, offsets::FORMTYPE_OFF, &form_type);
            std::int64_t sum = 0;
            int si = 0;
            for (void* s = rd_ptr(entry, 0x08); s; s = rd_ptr(s, offsets::INV_STACK_NEXT_OFF)) {
                if (++si > 256) { *reasons |= REASON_CAPS; break; }
                if (rd_vtable(s) != g_base + offsets::INV_STACK_VTABLE_RVA) { *reasons |= REASON_STACK_VTABLE; break; }
                std::uint32_t cnt = 0;
                std::uint16_t flags = 0;
                if (!rd_u32(s, offsets::INV_STACK_COUNT_OFF, &cnt) || !rd_u16(s, offsets::INV_STACK_FLAGS_OFF, &flags)) {
                    *reasons |= REASON_SEH; break;
                }
                sum += static_cast<std::int32_t>(cnt);
                if (flags & offsets::INV_STACK_FLAG_TRANSIENT) { ++m->transient; continue; }
                if (m->stacks >= MAX_STACKS) { *reasons |= REASON_CAPS; break; }
                StackRecord* r = &m->records[m->stacks];
                std::memset(r, 0, sizeof(*r));
                r->base_id = base_id; r->form_type = form_type; r->flags = flags;
                r->count = static_cast<std::int32_t>(cnt);
                r->health = NAN; r->charge = NAN; r->favorite = 0xFF; r->oie_template = 0xFFFF;
                void* xlist = rd_ptr(s, offsets::INV_STACK_EXTRAS_OFF);
                if (xlist) read_extras(xlist, r, reasons);
                ++m->stacks;
            }
            // The engine's own count for the entry, against the stacks read.
            const std::int64_t engine = call_entry_count(entry);
            if (engine >= 0 && engine != sum) *reasons |= REASON_COUNT_MISMATCH;
        }
    } __finally {
        call_lock(g_read_unlock, lock);
    }
}

// Stage 4a: the probe's locked walk. The capture's, on any REFR's list,
// for one base or all, transient stacks included, each stack with its
// position in the chain and its base's flags. POD only, __finally
// releases the list lock.
void probe_walk_locked(void* list, std::uint32_t base, ProbeStack* out, std::uint32_t max,
                       std::uint32_t* n_out, std::uint32_t* reasons) noexcept {
    void* lock = static_cast<std::uint8_t*>(list) + offsets::INVLIST_MUTEX_OFF;
    if (!call_lock(g_read_lock, lock)) { *reasons |= REASON_SEH; return; }
    __try {
        std::uint32_t entry_count = 0;
        void* entries = rd_ptr(list, offsets::INVLIST_ENTRIES_OFF);
        if (!rd_u32(list, offsets::INVLIST_COUNT_OFF, &entry_count) || !entries) { *reasons |= REASON_SEH; return; }
        if (entry_count > 4096) { *reasons |= REASON_CAPS; entry_count = 4096; }
        for (std::uint32_t i = 0; i < entry_count; ++i) {
            void* entry = static_cast<std::uint8_t*>(entries) + static_cast<std::size_t>(i) * offsets::INVENTORY_ITEM_STRIDE;
            void* obj = rd_ptr(entry, offsets::INVENTORY_ITEM_OBJ_OFF);
            if (!obj) continue;
            const std::uint32_t base_id = form_id_of(obj);
            if (base != 0 && base_id != base) continue;
            std::uint8_t form_type = 0;
            rd_u8(obj, offsets::FORMTYPE_OFF, &form_type);
            std::uint32_t base_flags = 0;
            rd_u32(obj, offsets::TESFORM_FLAGS_OFF, &base_flags);
            std::uint16_t chain = 0;
            for (void* s = rd_ptr(entry, 0x08); s; s = rd_ptr(s, offsets::INV_STACK_NEXT_OFF), ++chain) {
                if (chain >= 256) { *reasons |= REASON_CAPS; break; }
                if (rd_vtable(s) != g_base + offsets::INV_STACK_VTABLE_RVA) { *reasons |= REASON_STACK_VTABLE; break; }
                std::uint32_t cnt = 0;
                std::uint16_t flags = 0;
                if (!rd_u32(s, offsets::INV_STACK_COUNT_OFF, &cnt) || !rd_u16(s, offsets::INV_STACK_FLAGS_OFF, &flags)) {
                    *reasons |= REASON_SEH; break;
                }
                if (*n_out >= max) { *reasons |= REASON_CAPS; return; }
                ProbeStack* p = &out[*n_out];
                std::memset(p, 0, sizeof(*p));
                StackRecord* r = &p->r;
                r->base_id = base_id; r->form_type = form_type; r->flags = flags;
                r->count = static_cast<std::int32_t>(cnt);
                r->health = NAN; r->charge = NAN; r->favorite = 0xFF; r->oie_template = 0xFFFF;
                p->chain = chain;
                p->transient = (flags & offsets::INV_STACK_FLAG_TRANSIENT) ? 1 : 0;
                p->base_flags = base_flags;
                void* xlist = rd_ptr(s, offsets::INV_STACK_EXTRAS_OFF);
                if (xlist) read_extras(xlist, r, reasons);
                ++*n_out;
            }
        }
    } __finally {
        call_lock(g_read_unlock, lock);
    }
}

// ---------------------------------------------------------------- digest
std::uint64_t fnv1a(std::uint64_t h, const void* data, std::size_t n) noexcept {
    const auto* p = static_cast<const std::uint8_t*>(data);
    for (std::size_t i = 0; i < n; ++i) { h ^= p[i]; h *= 1099511628211ull; }
    return h;
}

// Canonical: the records sorted by base, then by their own bytes, so the
// digest does not depend on the order the engine keeps the chain in.
void canonicalize(Manifest* m) noexcept {
    // Insertion sort on a POD array: at most 1024 records, once a second.
    for (std::uint32_t i = 1; i < m->stacks; ++i) {
        StackRecord key = m->records[i];
        std::uint32_t j = i;
        while (j > 0) {
            const StackRecord& prev = m->records[j - 1];
            int cmp = 0;
            if (prev.base_id != key.base_id) cmp = prev.base_id > key.base_id ? 1 : -1;
            else cmp = std::memcmp(&prev, &key, sizeof(StackRecord));
            if (cmp <= 0) break;
            m->records[j] = m->records[j - 1];
            --j;
        }
        m->records[j] = key;
    }
    std::uint64_t h = 14695981039346656037ull;
    for (std::uint32_t i = 0; i < m->stacks; ++i) h = fnv1a(h, &m->records[i], sizeof(StackRecord));
    m->digest = h;
}

bool resolve(std::uintptr_t base) noexcept {
    if (g_resolved) return true;
    g_base = base;
    g_read_lock   = reinterpret_cast<LockFn>(base + offsets::EXTRALIST_READ_LOCK_RVA);
    g_read_unlock = reinterpret_cast<LockFn>(base + offsets::EXTRALIST_READ_UNLOCK_RVA);
    g_entry_count = reinterpret_cast<EntryCountFn>(base + offsets::INVITEM_GET_COUNT_RVA);
    g_quest_item  = reinterpret_cast<QuestItemFn>(base + offsets::XLIST_IS_QUEST_ITEM_RVA);
    g_health      = reinterpret_cast<HealthFn>(base + offsets::XLIST_GET_HEALTH_RVA);
    g_cstr        = reinterpret_cast<CStrFn>(base + offsets::BSFIXEDSTRING_CSTR_RVA);
    g_get_by_type = reinterpret_cast<GetByTypeFn>(base + offsets::EXTRA_GET_BY_TYPE_RVA);
    g_resolved = true;
    return true;
}

const char* type_name(std::uint8_t t) noexcept {
    switch (t) {
    case 0x1D: return "ARMO"; case 0x2B: return "WEAP"; case 0x2A: return "AMMO";
    case 0x1E: return "BOOK"; case 0x2C: return "MISC"; case 0x20: return "ALCH";
    case 0x2D: return "NPC_"; case 0x32: return "NOTE"; case 0x1F: return "KEYM";
    default: return "?";
    }
}

void log_records(const Manifest& m) {
    // Stage 4a: with the instance probe on, every record goes out at info in
    // the probe's format (the uid with its owner, the base's flags, the two
    // fingerprints), the same lines the probe writes around a transfer.
    if (fw::persist::probe::enabled()) {
        char tag[24];
        std::snprintf(tag, sizeof(tag), "capture#%u", m.seq);
        for (std::uint32_t i = 0; i < m.stacks; ++i) {
            fw::persist::probe::log_stack(tag, m.records[i], -1, false,
                                          base_flags_of(m.records[i].base_id));
        }
        return;
    }
    if (fw::log::get_level() < fw::log::Level::Debug) return;
    for (std::uint32_t i = 0; i < m.stacks; ++i) {
        const StackRecord& r = m.records[i];
        char mods[MAX_OIE_RECORDS * 10 + 8];
        mods[0] = '\0';
        std::size_t p = 0;
        for (std::uint32_t k = 0; k < r.oie_count && p + 12 < sizeof(mods); ++k) {
            p += static_cast<std::size_t>(std::snprintf(mods + p, sizeof(mods) - p, "%s%X", k ? "," : "", r.oie[k].mod_form_id));
        }
        FW_DBG("[inv]   0x%06X %s x%d flags=0x%04X extras=0x%06X%s%s hp=%.3f chg=%.1f fav=%u uid=%u"
               " mods=%u[%s]%s tmpl=0x%X txt=%d/%X/%X%s '%s' ench=%X rank=%u%s%s",
               r.base_id, type_name(r.form_type), r.count, r.flags, r.extra_mask,
               r.quest_item ? " QUEST" : "", (r.flags & offsets::INV_STACK_FLAG_EQUIPPED) ? " EQUIPPED" : "",
               r.health, r.charge, unsigned(r.favorite), unsigned(r.uid),
               unsigned(r.oie_count), mods, r.oie_truncated ? "+" : "", unsigned(r.oie_template),
               r.text_owner, r.text_message, r.text_quest, r.name_is_rename ? " renamed" : "", r.name,
               r.enchantment, r.mod_rank,
               r.opaque_types ? " opaque" : "", r.unverified_types ? " UNVERIFIED" : "");
    }
}

bool gates_open(std::uintptr_t base, const char** why) noexcept {
    if (fw::persist::exiting()) { *why = "exiting"; return false; }
    if (!fw::native::ghost_scene_settled()) { *why = "scene not settled"; return false; }
    if (fw::persist::load_in_flight()) { *why = "load in flight"; return false; }
    if (container_menu_open()) { *why = "ContainerMenu open"; return false; }
    if (fw::hooks::pa_mod_menu_open()) { *why = "PA station open"; return false; }
    (void)base;
    return true;
}

bool do_capture(std::uintptr_t base, const char* why) {
    resolve(base);
    void* player = fw::engine::get_local_player();
    if (!player) return false;

    Manifest* m = &g_work;
    m->seq = ++g_seq;
    m->reasons = 0;
    m->wall_ms = wall_ms();
    m->entries = 0; m->stacks = 0; m->transient = 0;
    m->in_power_armor = 0;
    m->digest = 0; m->capture_us = 0; m->complete = 0;

    void* list = rd_ptr(player, offsets::REFR_INV_LIST_OFF);
    if (!list) {
        m->reasons |= REASON_NO_LIST;
        if (!g_logged_no_list) {
            g_logged_no_list = true;
            FW_LOG("[inv] capture #%u (%s): the player has no inventory list yet; "
                   "reported as 'no list', never as empty", m->seq, why);
        }
        g_last = *m;
        return true;
    }
    std::uint32_t counter = 0;
    if (!rd_u32(list, offsets::INVLIST_LOCK_COUNTER_OFF, &counter)) { m->reasons |= REASON_SEH; g_last = *m; return true; }
    if (counter & 0x80000000u) {
        ++g_skips_writer;
        m->reasons |= REASON_WRITER_HELD;
        return false;   // not a capture: try again next tick
    }
    void* refr_xlist = rd_ptr(player, offsets::REFR_EXTRA_LIST_OFF);
    if (refr_xlist && call_get_by_type(refr_xlist, offsets::EXTRA_TYPE_POWER_ARMOR)) m->in_power_armor = 1;

    const std::uint64_t t0 = qpc_us();
    walk_locked(list, m, &m->reasons);
    const std::uint64_t t1 = qpc_us();
    m->capture_us = static_cast<std::uint32_t>(t1 - t0);
    if (m->capture_us > g_max_us) g_max_us = m->capture_us;
    canonicalize(m);
    m->complete = (m->reasons == 0) ? 1 : 0;
    drain_tap();
    reconcile(*m);

    const bool changed = (m->digest != g_last_digest) || (m->complete != g_last.complete);
    g_last = *m;
    if (changed) {
        g_last_digest = m->digest;
        if (!g_out_dir.empty()) {
            const std::wstring p = g_out_dir + L"\\fw_inventory.json";
            write_json(*m, p.c_str());
        }
        FW_LOG("[inv] capture #%u (%s): %u entries, %u stacks (%u transient skipped), "
               "digest=%016llX, %s%s%s%s%s%s%s%s%s, %u us%s",
               m->seq, why, m->entries, m->stacks, m->transient,
               static_cast<unsigned long long>(m->digest),
               m->complete ? "COMPLETE" : "INCOMPLETE:",
               (m->reasons & REASON_SEH) ? " seh" : "",
               (m->reasons & REASON_CAPS) ? " caps" : "",
               (m->reasons & REASON_COUNT_MISMATCH) ? " count-mismatch" : "",
               (m->reasons & REASON_EXTRAS_UNREAD) ? " extras-unread" : "",
               (m->reasons & REASON_STACK_VTABLE) ? " stack-vtable" : "",
               (m->reasons & REASON_HEALTH_CHECK) ? " health-check" : "",
               (m->reasons & REASON_WRITER_HELD) ? " writer" : "",
               (m->reasons & REASON_NO_LIST) ? " no-list" : "",
               m->capture_us, m->in_power_armor ? ", in power armor" : "");
        log_records(*m);
    }
    return true;
}

// L5 realtime R1 (2026-10-03) - the capture `m` as the player's record on
// the server (INV_STATE), when its digest is not the last one sent. Only a
// complete capture, and only when no container op of ours was in flight
// across it: `quiet_before` is the check made before the capture ran, this
// function makes the one after (an op refused in between would otherwise
// travel inside the record with its effect undone a moment later; the next
// change sends the capture again). The descriptors of its named instances go
// first. Main thread.
void send_state(const Manifest& m, bool quiet_before) {
    if (m.seq == 0 || !m.complete) return;
    // R2: after a load, until the record is back in the game, a capture is
    // the old checkpoint's inventory and must not reach the record.
    if (!fw::persist::restore::record_open()) return;
    if (g_state_sent && m.digest == g_state_digest) return;
    auto& c = fw::net::client();
    if (!quiet_before || c.container_ops_in_flight() || fw::dispatch::pending_count() != 0) return;

    std::map<std::pair<std::uint32_t, std::uint64_t>, std::pair<std::int64_t, std::uint8_t>> lines;
    std::vector<fw::net::InstanceDefEntry> defs;
    std::uint32_t unknown = 0;
    for (std::uint32_t i = 0; i < m.stacks; ++i) {
        const StackRecord& r = m.records[i];
        if (r.count <= 0 || r.base_id == 0) continue;
        // 2026-10-05: the frame's body armour is the engine's, never inventory
        // (offsets::PA_FRAME_WEARABLE_FORMIDS).
        if (offsets::is_pa_frame_wearable(r.base_id)) continue;
        fw::net::InstanceDesc d{};
        const std::uint64_t fp = fw::persist::instance::fp_of_record(r, &d);
        auto& slot = lines[{r.base_id, fp}];
        slot.first += r.count;
        if (r.flags & offsets::INV_STACK_FLAG_EQUIPPED) slot.second |= fw::net::kInvEntryEquipped;
        if (fp == fw::net::kFpUnknown) {
            ++unknown;
        } else if (fp != fw::net::kFpPlain) {
            fw::net::InstanceDefEntry e{};
            e.base_id  = r.base_id;
            e.fp       = fp;
            e.instance = d;
            defs.push_back(e);
        }
    }
    std::vector<fw::net::InvStateEntry> out;
    out.reserve(lines.size());
    std::uint64_t items = 0;
    std::uint32_t equipped = 0;
    for (const auto& [k, v] : lines) {
        fw::net::InvStateEntry e{};
        e.item_base_id = k.first;
        e.item_fp      = k.second;
        e.count        = static_cast<std::int32_t>(v.first > 0x7FFFFFFF ? 0x7FFFFFFF : v.first);
        e.flags        = v.second;
        items += static_cast<std::uint64_t>(e.count);
        if (e.flags & fw::net::kInvEntryEquipped) ++equipped;
        out.push_back(e);
    }
    c.enqueue_player_instance_defs(defs.data(), defs.size());
    fw::net::InvStateHeader h{};
    h.session   = c.capture_session();
    h.seq       = m.seq;
    h.watermark = c.last_op_id();
    h.op_epoch  = c.op_epoch();
    h.flags     = static_cast<std::uint8_t>(fw::net::kInvStateFlagComplete |
                  (m.in_power_armor ? fw::net::kInvStateFlagInPowerArmor : 0));
    h.digest    = m.digest;
    c.enqueue_inv_state(h, out.data(), out.size());
    g_state_digest = m.digest;
    g_state_sent   = true;
    g_state_seq    = m.seq;
    FW_LOG("[inv] state #%u sent: %zu line(s), %llu item(s), %u equipped, %u unreadable, "
           "watermark %08X, digest %016llX", m.seq, out.size(),
           static_cast<unsigned long long>(items), equipped, unknown, h.watermark,
           static_cast<unsigned long long>(m.digest));
}

} // namespace

// ---------------------------------------------------------------- public

bool container_menu_is_open() noexcept { return container_menu_open(); }

void set_output_dir(const wchar_t* dir) { g_out_dir = dir ? dir : L""; }

bool dump_json(const wchar_t* path) { return path && g_last.seq != 0 && write_json(g_last, path); }

void configure(const fw::config::Settings& cfg) {
    g_enabled = cfg.inventory_capture;
    FW_LOG("[inv] inventory capture %s", g_enabled ? "on: once a second, observe-only"
                                                    : "off (inventory_capture=false)");
}

void tick(std::uintptr_t module_base) {
    if (!g_enabled) return;
    const std::uint64_t now = wall_ms();
    // L5 realtime R1: an add or a remove on the player since the last
    // capture, or a capture the record has not had yet, brings the next
    // capture forward from the second to kEventCaptureMs.
    const std::uint64_t events = fw::persist::tap::events_seen();
    const bool moved = events != g_tap_seen;
    const bool behind = g_last.seq != 0 && g_last.complete &&
                        !(g_state_sent && g_last.digest == g_state_digest);
    if (now - g_last_tick_ms < ((moved || behind) ? kEventCaptureMs : 1000)) return;
    g_last_tick_ms = now;
    const char* why = nullptr;
    if (!gates_open(module_base, &why)) { ++g_skips_gate; return; }
    auto& c = fw::net::client();
    const bool quiet_before = !c.container_ops_in_flight() && fw::dispatch::pending_count() == 0;
    g_tap_seen = events;
    do_capture(module_base, moved ? "event" : "tick");
    send_digest(g_last, fw::net::kInvDigestWhyChange, /*force=*/false);
    send_state(g_last, quiet_before);
    if (now - g_last_stats_ms >= 60000) {
        g_last_stats_ms = now;
        FW_DBG("[inv] stats: %u captures, %u passes skipped by a writer, %u by gates, "
               "slowest %u us, %u unexplained change(s) so far",
               g_seq, g_skips_writer, g_skips_gate, g_max_us, g_unexplained_total);
    }
}

bool capture_now(std::uintptr_t module_base, const char* why) {
    const char* blocked = nullptr;
    if (!gates_open(module_base, &blocked)) {
        FW_DBG("[inv] capture on demand (%s) not run: %s", why, blocked);
        return false;
    }
    return do_capture(module_base, why);
}

const Manifest& last() { return g_last; }

std::uint32_t last_state_seq() { return g_state_seq; }

void send_digest_now(std::uint8_t why) {
    if (!g_enabled) return;
    send_digest(g_last, why, /*force=*/true);
}

bool read_refr_record(std::uintptr_t module_base, void* refr, StackRecord* out) {
    if (!out) return false;
    std::memset(out, 0, sizeof(*out));
    out->health = NAN; out->charge = NAN; out->favorite = 0xFF; out->oie_template = 0xFFFF;
    out->count = 1;
    if (!refr || !module_base) return false;
    resolve(module_base);
    const fw::RefIdentity id = fw::read_ref_identity(refr);
    out->base_id = id.base_id;
    if (id.base_id == 0) return false;
    // A REFR without an extra list is a bare object: one of the base, no
    // condition, no mods, a complete answer.
    void* xlist = rd_ptr(refr, offsets::REFR_EXTRA_LIST_OFF);
    if (!xlist) return true;
    std::uint32_t reasons = 0;
    read_extras(xlist, out, &reasons);
    if (reasons & (REASON_SEH | REASON_EXTRAS_UNREAD | REASON_CAPS)) return false;
    if (out->extra_count > 0) out->count = out->extra_count;
    return true;
}

bool read_refr_instance(std::uintptr_t module_base, void* refr, fw::net::PaPieceEntry* out) {
    if (!out) return false;
    std::memset(out, 0, sizeof(*out));
    out->count  = 1;
    out->health = -1.0f;
    if (!refr || !module_base) return false;
    resolve(module_base);
    const fw::RefIdentity id = fw::read_ref_identity(refr);
    out->form_id = id.base_id;
    if (id.base_id == 0) return false;
    // TESObjectREFR::extraList is a pointer; a REFR without one is a bare
    // object (count 1, no condition, no mods), which is a complete answer.
    void* xlist = rd_ptr(refr, offsets::REFR_EXTRA_LIST_OFF);
    if (!xlist) return true;
    StackRecord r;
    std::memset(&r, 0, sizeof(r));
    r.health = NAN; r.charge = NAN; r.favorite = 0xFF; r.oie_template = 0xFFFF;
    std::uint32_t reasons = 0;
    read_extras(xlist, &r, &reasons);
    // The health cross-check is an opinion about the record; the other
    // reasons mean the walk did not finish. Partial is reported as partial.
    if (reasons & (REASON_SEH | REASON_EXTRAS_UNREAD | REASON_CAPS)) return false;
    if (r.extra_count > 0) out->count = r.extra_count;
    if (!std::isnan(r.health)) out->health = r.health;
    const std::uint32_t n = (r.oie_count < fw::net::kMaxPieceMods)
                          ? r.oie_count : static_cast<std::uint32_t>(fw::net::kMaxPieceMods);
    for (std::uint32_t i = 0; i < n; ++i) out->mods[i] = r.oie[i].mod_form_id;
    out->mod_n = static_cast<std::uint8_t>(n);
    if (r.oie_count > n || r.oie_truncated) {
        FW_WRN("[inv] instance of 0x%08X (fid 0x%08X) carries %u%s mods, the wire takes %u: "
               "the rest is not replicated", id.base_id, id.form_id, unsigned(r.oie_count),
               r.oie_truncated ? "+" : "", unsigned(n));
    }
    return true;
}

std::uint32_t probe_stacks(std::uintptr_t module_base, void* refr, std::uint32_t base,
                           ProbeStack* out, std::uint32_t max, std::uint32_t* reasons) {
    std::uint32_t scratch = 0;
    if (!reasons) reasons = &scratch;
    *reasons = 0;
    if (!refr || !out || max == 0 || !module_base) return 0;
    resolve(module_base);
    void* list = rd_ptr(refr, offsets::REFR_INV_LIST_OFF);
    if (!list) { *reasons |= REASON_NO_LIST; return 0; }
    // As in the capture: a list whose writer bit is set is not walked. The
    // writer may be this very thread (a probe called from inside a transfer
    // the engine is making), and its lock does not let a reader in.
    std::uint32_t counter = 0;
    if (!rd_u32(list, offsets::INVLIST_LOCK_COUNTER_OFF, &counter)) { *reasons |= REASON_SEH; return 0; }
    if (counter & 0x80000000u) { *reasons |= REASON_WRITER_HELD; return 0; }
    std::uint32_t n = 0;
    probe_walk_locked(list, base, out, max, &n, reasons);
    return n;
}

std::uint64_t fingerprint(const StackRecord& r, bool with_template) noexcept {
    std::uint64_t h = 14695981039346656037ull;
    h = fnv1a(h, &r.base_id, sizeof(r.base_id));
    const std::uint8_t has_oie = (r.extra_mask & MASK_OIE) ? 1 : 0;
    h = fnv1a(h, &has_oie, sizeof(has_oie));
    if (with_template) h = fnv1a(h, &r.oie_template, sizeof(r.oie_template));
    // The records sorted by (mod, attach, rank): the engine's order of the
    // OIE array is not part of what the instance is.
    ModRecord recs[MAX_OIE_RECORDS];
    const std::uint32_t n = r.oie_count < MAX_OIE_RECORDS ? r.oie_count : MAX_OIE_RECORDS;
    for (std::uint32_t i = 0; i < n; ++i) recs[i] = r.oie[i];
    for (std::uint32_t i = 1; i < n; ++i) {
        const ModRecord key = recs[i];
        std::uint32_t j = i;
        while (j > 0) {
            const ModRecord& prev = recs[j - 1];
            const bool after = prev.mod_form_id != key.mod_form_id ? prev.mod_form_id > key.mod_form_id
                             : prev.attach_index != key.attach_index ? prev.attach_index > key.attach_index
                             : prev.rank > key.rank;
            if (!after) break;
            recs[j] = recs[j - 1];
            --j;
        }
        recs[j] = key;
    }
    for (std::uint32_t i = 0; i < n; ++i) {
        h = fnv1a(h, &recs[i].mod_form_id, sizeof(recs[i].mod_form_id));
        h = fnv1a(h, &recs[i].attach_index, sizeof(recs[i].attach_index));
        h = fnv1a(h, &recs[i].rank, sizeof(recs[i].rank));
    }
    const std::int32_t hp = std::isnan(r.health)
        ? INT32_MIN
        : static_cast<std::int32_t>(std::lround(static_cast<double>(r.health) * 1000.0));
    h = fnv1a(h, &hp, sizeof(hp));
    std::size_t len = 0;
    while (len < MAX_NAME && r.name[len]) ++len;
    h = fnv1a(h, r.name, len);
    return h;
}

std::uint32_t base_flags_of(std::uint32_t base_form_id) noexcept {
    if (base_form_id == 0) return 0;
    void* form = fw::engine::lookup_by_form_id(base_form_id);
    std::uint32_t flags = 0;
    return (form && rd_u32(form, offsets::TESFORM_FLAGS_OFF, &flags)) ? flags : 0;
}

bool read_list_record(std::uintptr_t module_base, void* xlist, std::uint32_t base_id,
                      StackRecord* out) {
    if (!out || !module_base) return false;
    resolve(module_base);
    std::memset(out, 0, sizeof(*out));
    out->base_id = base_id;
    out->health = NAN; out->charge = NAN; out->favorite = 0xFF; out->oie_template = 0xFFFF;
    if (!xlist) return true;   // no extras: a plain stack, completely known
    std::uint32_t reasons = 0;
    read_extras(xlist, out, &reasons);
    // The health cross-check is an opinion; anything else means the walk
    // did not finish.
    return (reasons & (REASON_SEH | REASON_EXTRAS_UNREAD | REASON_CAPS)) == 0;
}

} // namespace fw::persist::inventory
