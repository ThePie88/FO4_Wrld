#include "chargen_selftest.h"

#include <windows.h>

#include <atomic>
#include <cstdio>
#include <string>

#include "../engine/engine_calls.h"
#include "appearance_recipe.h"
#include "../log.h"
#include "ni_offsets.h"

namespace fw::native::chargen_selftest {

namespace {

std::atomic<std::uint32_t> g_form_id{0};
std::atomic<std::uint32_t> g_delay_s{0};
std::atomic<std::uint32_t> g_donor{0};
std::atomic<bool>          g_done{false};
DWORD                      g_first_seen = 0;   // main thread only

// Both verified by 108 / 186 observed chain-throughs, not by reading a
// prototype. See the header on why arity is treated as a safety property.
using SetHairColorFn = void(__fastcall*)(void*, void*);
using AddHeadPartFn  = void(__fastcall*)(void*, void*, bool, bool, bool);

constexpr std::uintptr_t SET_HAIRCOLOR_RVA = 0x00654DF0;
constexpr std::uintptr_t ADD_HEADPART_RVA  = 0x00655010;

constexpr std::size_t  FORM_ID_OFF   = 0x14;
constexpr std::size_t  FORM_TYPE_OFF = 0x1A;
constexpr std::size_t  ACTOR_NPC_OFF = 0xE0;   // Actor -> TESNPC
constexpr std::uint8_t FORMTYPE_HDPT = 15;
constexpr std::uint8_t FORMTYPE_CLFM = 137;
constexpr std::uint8_t FORMTYPE_NPC  = 45;

void* seh_ptr(const void* addr) noexcept {
    if (!addr) return nullptr;
    __try { return *reinterpret_cast<void* const*>(addr); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

std::uint8_t seh_u8(const void* addr) noexcept {
    if (!addr) return 0;
    __try { return *reinterpret_cast<const std::uint8_t*>(addr); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

std::uint32_t seh_u32(const void* addr) noexcept {
    if (!addr) return 0;
    __try { return *reinterpret_cast<const std::uint32_t*>(addr); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

// The player's TESNPC. Actor+0xE0 is the base form; for the player that is
// the NPC_ record with form id 7, which every HEAD-BUILD record confirmed.
void* player_npc(std::uintptr_t base) noexcept {
    void* player = seh_ptr(reinterpret_cast<void*>(base + PLAYER_SINGLETON_RVA));
    if (!player) return nullptr;
    return seh_ptr(reinterpret_cast<std::uint8_t*>(player) + ACTOR_NPC_OFF);
}

// std::string and std::vector cannot coexist with __try in one function
// (C2712, object unwinding), and maybe_run is full of SEH cages. So the
// round-trip lives here, on its own, where no guarded read is needed: every
// engine access it makes is already inside appearance_recipe.
// ===========================================================================
// Actor::Reset3D — the rebuild trigger. RVA 0xC73DD0, FIVE arguments.
//
// This is what the engine itself uses to make an appearance change visible:
// the Papyrus native Actor.ChangeHeadPart calls it, the chargen menu calls it
// (from sub_140BC0690 — the same function whose OTHER call, sub_1406DFB00, was
// the route being chased and turned out to be BSFaceGenManager's tint/texture
// queue, provably unable to reach the head builder), and Actor::LoadGame calls
// it, which is why dying and respawning worked.
//
// The tuple below is exactly ChangeHeadPart's: (actor, 0, 0, 1, 0).
//   reloadAll = 0     skips the player biped/camera refcount branch
//   addFlags  = 0     the callee ORs 0x17 itself; 0x17 & 0xC = 0x04 = head bit
//   queueReset = 1    lets the engine marshal to the main thread
//   excludeFlags = 0  applied as ~a5 & (addFlags|0x17); passing 4 or 0xC here
//                     STRIPS the head bit — that is literally how the chargen
//                     cancel path suppresses a rebuild.
//
// The fifth argument is a STACK argument. Declaring four does not crash — it
// feeds stack garbage as excludeFlags and silently kills the head bit, which
// would look exactly like "the trigger does not work". Hence five.
//
// Asynchronous: this kicks a load, and sub_1406E03E0 runs a frame or more
// later. Do not expect a same-frame change.
constexpr std::uintptr_t ACTOR_RESET3D_RVA = 0x00C73DD0;

using ActorReset3DFn = char(__fastcall*)(void*, std::uint8_t, std::uint32_t,
                                        std::uint8_t, std::uint32_t);

std::uint16_t seh_u16(const void* addr) noexcept {
    if (!addr) return 0;
    __try { return *reinterpret_cast<const std::uint16_t*>(addr); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

// Every gate in the Reset3D chain is a SILENT early return — no assert, no
// log. So check them all first and print the lot on failure, otherwise a
// no-op is indistinguishable from a wrong trigger.
bool can_reset_3d(void* actor, void* expected_npc) noexcept {
    if (!actor) { FW_WRN("[reset3d] no player actor"); return false; }

    const std::uint8_t  form_type  = seh_u8 (reinterpret_cast<std::uint8_t*>(actor) + 0x1A);
    const std::uint8_t  mid_load   = seh_u8 (reinterpret_cast<std::uint8_t*>(actor) + 0x10A);
    void* const         npc        = seh_ptr(reinterpret_cast<std::uint8_t*>(actor) + 0xE0);
    void* const         loaded     = seh_ptr(reinterpret_cast<std::uint8_t*>(actor) + 0xF0);
    void* const         got3d      = loaded ? seh_ptr(reinterpret_cast<std::uint8_t*>(loaded) + 0x08) : nullptr;
    void* const         proc       = seh_ptr(reinterpret_cast<std::uint8_t*>(actor) + 0x300);
    void* const         mid        = proc ? seh_ptr(reinterpret_cast<std::uint8_t*>(proc) + 0x08) : nullptr;
    void* const         high       = proc ? seh_ptr(reinterpret_cast<std::uint8_t*>(proc) + 0x10) : nullptr;
    const std::uint8_t  escalate   = proc ? seh_u8(reinterpret_cast<std::uint8_t*>(proc) + 0xE4) : 0;
    const std::uint16_t pending    = mid ? seh_u16(reinterpret_cast<std::uint8_t*>(mid) + 0x496) : 0;

    const bool ok = form_type == 65 && mid_load != 1 && npc == expected_npc &&
                    loaded && got3d && proc && mid && high &&
                    escalate == 0 && (pending & 0x20) == 0;

    if (!ok) {
        FW_WRN("[reset3d] precondition FAILED — type=%u(want 65) midLoad=%u"
               "(want !=1) npc=%p(want %p) loaded=%p got3d=%p proc=%p mid=%p "
               "high=%p escalate=%u(want 0) pending=0x%04X(bit 0x20 must be 0)",
               form_type, mid_load, npc, expected_npc, loaded, got3d, proc,
               mid, high, escalate, pending);
    } else {
        FW_LOG("[reset3d] preconditions OK (pending=0x%04X)", pending);
    }
    return ok;
}

// MAIN THREAD ONLY: the chain writes engine TLS and reads a TLS cell cache,
// so a DLL-spawned thread faults on the null TLS slot.
void force_head_rebuild(std::uintptr_t module_base, void* expected_npc) {
    void* actor = seh_ptr(reinterpret_cast<void*>(module_base
                                                 + PLAYER_SINGLETON_RVA));
    if (!can_reset_3d(actor, expected_npc)) {
        FW_WRN("[reset3d] not calling Reset3D — a precondition would have made "
               "it a silent no-op");
        return;
    }

    auto fn = reinterpret_cast<ActorReset3DFn>(module_base + ACTOR_RESET3D_RVA);
    FW_LOG("[reset3d] calling Actor::Reset3D(actor=%p, 0, 0, 1, 0) — the tuple "
           "Papyrus ChangeHeadPart and Actor::LoadGame use", actor);
    char rc = 0;
    __try {
        rc = fn(actor, 0, 0, 1, 0);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[reset3d] SEH inside Actor::Reset3D — aborted");
        return;
    }
    FW_LOG("[reset3d] returned %d. It is ASYNCHRONOUS: the head builder runs a "
           "frame or more later, so watch for HEAD-BUILD records after this "
           "line, not on the same tick.", static_cast<int>(rc));
}

// Walk TESDataHandler's NPC_ array and hand the recipe to the first N human
// records. Picking a form id by hand did not survive contact: 0x0020593F
// (LCharWorkshopNPC) is a LEVELLED list, not an NPC_, and the lookup returned
// nothing. Rather than guess again, let the data choose — filter on the race
// the player actually is, so the subjects are humans that can wear a human
// face, and log every name so the result is checkable.
constexpr std::uintptr_t DATAHANDLER_RVA = 0x030DC000;
constexpr std::size_t    DH_ARRAYS_OFF   = 0x68;
constexpr std::size_t    DH_ARRAY_STRIDE = 0x18;
constexpr std::size_t    NPC_RACE_OFF    = 0x1B8;
constexpr std::size_t    NPC_FULLNAME    = 0x28;
constexpr std::uintptr_t BSFIXEDSTR_CSTR_RVA = 0x0167C070;
constexpr std::uint32_t  MAX_DONORS      = 8;

using CStrFn = const char*(__fastcall*)(const void*);

std::uint32_t donate_to_humans(std::uintptr_t module_base,
                               const fw::native::appearance::Recipe& rec) {
    auto* dh = reinterpret_cast<std::uint8_t*>(
        seh_ptr(reinterpret_cast<void*>(module_base + DATAHANDLER_RVA)));
    if (!dh) return 0;
    auto* arr = dh + DH_ARRAYS_OFF + DH_ARRAY_STRIDE * FORMTYPE_NPC;
    auto** data = reinterpret_cast<void**>(seh_ptr(arr));
    const std::uint32_t size = seh_u32(arr + 0x10);
    if (!data || size == 0 || size > 200000) return 0;

    const auto cstr = reinterpret_cast<CStrFn>(module_base
                                               + BSFIXEDSTR_CSTR_RVA);
    std::uint32_t done = 0;
    for (std::uint32_t i = 0; i < size && done < MAX_DONORS; ++i) {
        void* npc = seh_ptr(data + i);
        if (!npc) continue;
        auto* n = reinterpret_cast<std::uint8_t*>(npc);
        void* race = seh_ptr(n + NPC_RACE_OFF);
        if (!race) continue;
        if (seh_u32(reinterpret_cast<std::uint8_t*>(race) + FORM_ID_OFF)
            != rec.race_form_id) {
            continue;
        }
        const char* name = "?";
        __try {
            if (*reinterpret_cast<void**>(n + NPC_FULLNAME)) {
                name = cstr(n + NPC_FULLNAME);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) { name = "?"; }

        const std::uint32_t applied =
            fw::native::appearance::apply_to_npc(module_base, npc, rec);
        FW_LOG("[donor] gave 0x%08X '%s' the player's face (%u field(s))",
               seh_u32(n + FORM_ID_OFF), name, applied);
        ++done;
    }
    return done;
}

// Read the player's recipe and write it onto another NPC record. This is the
// donor, minus the synthetic form: a real NPC_ takes the player's appearance
// and its engine builds the head from it.
void run_donor(std::uintptr_t module_base, std::uint32_t npc_form_id) {
    const auto rec0 = fw::native::appearance::read_from_player(module_base);
    if (rec0.head_parts.empty()) {
        FW_WRN("[donor] the player's recipe is empty — nothing to give");
        return;
    }
    FW_LOG("[donor] player's recipe: %s",
           fw::native::appearance::to_line(rec0).c_str());

    void* donor = fw::engine::lookup_by_form_id(npc_form_id);
    if (!donor) {
        // Not a resolvable form — fall back to letting the data pick.
        const std::uint32_t n = donate_to_humans(module_base, rec0);
        FW_LOG("[donor] 0x%08X did not resolve to a form; gave the recipe to "
               "%u human NPC record(s) instead. Their NEXT 3D build shows it "
               "— the apply does not redraw an already-built head (§15), so "
               "leave the area and come back, or find one not yet loaded.",
               npc_form_id, n);
        return;
    }
    const std::uint8_t type = seh_u8(
        reinterpret_cast<std::uint8_t*>(donor) + FORM_TYPE_OFF);
    if (type != FORMTYPE_NPC) {
        FW_WRN("[donor] form 0x%08X has type %u, expected %u (NPC_) — "
               "refusing", npc_form_id, type, FORMTYPE_NPC);
        return;
    }

    const auto rec = fw::native::appearance::read_from_player(module_base);
    if (rec.head_parts.empty()) {
        FW_WRN("[donor] the player's recipe is empty — nothing to give");
        return;
    }
    FW_LOG("[donor] giving NPC 0x%08X the player's recipe: %s",
           npc_form_id,
           fw::native::appearance::to_line(rec).c_str());

    const std::uint32_t n =
        fw::native::appearance::apply_to_npc(module_base, donor, rec);
    FW_LOG("[donor] %u field(s) written onto 0x%08X. Its NEXT 3D build shows "
           "it — the apply does not redraw an existing head (see §15), so go "
           "and find one that has not been built yet, or leave the area and "
           "come back.", n, npc_form_id);
}

// The strongest check available without a human eye: read the player's
// appearance, write it straight back, read it again. An exact writer is
// IDEMPOTENT — the second read must equal the first. Anything that
// accumulates, drops, reorders or substitutes shows up here as a diff,
// which is how the doubled hairlines were caught (they were visible as a
// hair tower on screen, but this catches them in one log line).
void verify_engine_round_trip(std::uintptr_t module_base) {
    const auto before = fw::native::appearance::read_from_player(module_base);
    if (before.head_parts.empty()) {
        FW_WRN("[recipe-rt] player's recipe is empty — nothing to verify");
        return;
    }
    FW_LOG("[recipe-rt] before: %s",
           fw::native::appearance::to_line(before).c_str());

    fw::native::appearance::apply_to_player(module_base, before);

    const auto after = fw::native::appearance::read_from_player(module_base);
    FW_LOG("[recipe-rt] after : %s",
           fw::native::appearance::to_line(after).c_str());

    const bool same = after.race_form_id == before.race_form_id &&
                      after.female == before.female &&
                      after.hair_colour == before.hair_colour &&
                      after.head_parts == before.head_parts;
    if (same) {
        FW_LOG("[recipe-rt] IDEMPOTENT — %zu part(s) written back and the "
               "record is byte-identical. The writer reproduces exactly, "
               "which is what a donor needs.", before.head_parts.size());
    } else {
        FW_ERR("[recipe-rt] NOT idempotent — %zu part(s) in, %zu out. The "
               "writer is changing the character it was asked to reproduce.",
               before.head_parts.size(), after.head_parts.size());
    }
}

void log_recipe_round_trip(std::uintptr_t module_base) {
    const auto rec = fw::native::appearance::read_from_player(module_base);
    const std::string line = fw::native::appearance::to_line(rec);
    FW_LOG("[chargen-test] recipe: %s", line.c_str());

    fw::native::appearance::Recipe back;
    if (!fw::native::appearance::from_line(line, &back)) {
        FW_ERR("[chargen-test] recipe round-trip FAILED to parse");
    } else if (back.race_form_id != rec.race_form_id ||
               back.female != rec.female ||
               back.hair_colour != rec.hair_colour ||
               back.head_parts != rec.head_parts) {
        FW_ERR("[chargen-test] recipe round-trip MISMATCH");
    } else {
        FW_LOG("[chargen-test] recipe round-trip OK — %zu part(s), "
               "%zu bytes on the wire",
               rec.head_parts.size(), line.size());
    }
}

}  // namespace

void init(std::uint32_t form_id, std::uint32_t delay_s) {
    g_form_id.store(form_id, std::memory_order_relaxed);
    g_delay_s.store(delay_s, std::memory_order_relaxed);
    if (form_id) {
        FW_LOG("[chargen-test] ARMED with form 0x%08X, delay %us — it will be "
               "applied to the player's TESNPC once, from our own code. Watch "
               "the character; the log says what was called.",
               form_id, delay_s);
    }
}

void init_donor(std::uint32_t npc_form_id) {
    g_donor.store(npc_form_id, std::memory_order_relaxed);
    if (npc_form_id) {
        FW_LOG("[donor] ARMED: NPC 0x%08X will receive the local player's "
               "recipe. Shared base record — every actor using it is "
               "affected, and a restart undoes it.", npc_form_id);
    }
}

bool enabled() noexcept {
    return (g_form_id.load(std::memory_order_relaxed) != 0 ||
            g_donor.load(std::memory_order_relaxed) != 0) &&
           !g_done.load(std::memory_order_relaxed);
}

void maybe_run(std::uintptr_t module_base) noexcept {
    if (!enabled() || !module_base) return;

    // RETIRED 2026-08-11, and armed configs are disarmed on sight.
    //
    // This existed to recolour side B's hair to Golden Blond so the two test
    // clients were tellable apart before real per-identity faces existed. They
    // exist now, and the aid turned actively harmful: it recolours the LIVE
    // player a few seconds after join, the publisher sees a change and ships
    // it, and the server's stored character -- which is authoritative -- gets
    // overwritten with "the save's default plus blond hair". That is one of
    // the two ways both custom test characters were lost on 2026-08-11.
    //
    // Not removed from the config surface so old fw_config.ini files stay
    // parseable; armed values land here and die with one log line.
    {
        static std::atomic<bool> s_told{false};
        if (!s_told.exchange(true, std::memory_order_relaxed)) {
            FW_LOG("[chargen-test] RETIRED - chargen_selftest is armed in the "
                   "config but no longer runs: it would repaint the live "
                   "player and the publisher would overwrite the server's "
                   "authoritative character with it");
        }
        g_done.store(true, std::memory_order_relaxed);
        return;
    }

    void* npc = player_npc(module_base);
    if (!npc) return;   // not loaded yet — try again next tick

    // Hold off, so the apply lands on a head the engine has certainly already
    // built. Without this the test cannot tell an update apart from good
    // timing.
    const DWORD now = GetTickCount();
    if (g_first_seen == 0) {
        g_first_seen = now;
        FW_LOG("[chargen-test] player available; holding the apply for %us",
               g_delay_s.load(std::memory_order_relaxed));
    }
    if (now - g_first_seen <
        g_delay_s.load(std::memory_order_relaxed) * 1000u) {
        return;
    }

    const std::uint32_t npc_fid = seh_u32(
        reinterpret_cast<std::uint8_t*>(npc) + FORM_ID_OFF);
    if (npc_fid != 0x00000007) {
        FW_WRN("[chargen-test] player base form is 0x%08X, expected 0x7 — "
               "refusing to touch it", npc_fid);
        g_done.store(true, std::memory_order_relaxed);
        return;
    }

    const std::uint32_t want = g_form_id.load(std::memory_order_relaxed);
    void* form = want ? fw::engine::lookup_by_form_id(want) : nullptr;
    if (want && !form) {
        FW_ERR("[chargen-test] form 0x%08X not found — nothing applied", want);
        g_done.store(true, std::memory_order_relaxed);
        return;
    }

    const std::uint8_t type = form
        ? seh_u8(reinterpret_cast<std::uint8_t*>(form) + FORM_TYPE_OFF)
        : 0;

    // Type-check before handing anything to the engine. A typo in the ini
    // must not become a wild pointer in an engine function.
    if (type == FORMTYPE_CLFM) {
        auto fn = reinterpret_cast<SetHairColorFn>(module_base
                                                   + SET_HAIRCOLOR_RVA);
        FW_LOG("[chargen-test] calling set-haircolor(npc=%p, colour=0x%08X) "
               "from our own code", npc, want);
        __try {
            fn(npc, form);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            FW_ERR("[chargen-test] SEH inside set-haircolor — aborted");
            g_done.store(true, std::memory_order_relaxed);
            return;
        }
        FW_LOG("[chargen-test] set-haircolor returned cleanly. If the hair "
               "colour did NOT change on screen, the apply alone is not "
               "enough and the rebuild trigger is the next target.");
    } else if (type == FORMTYPE_HDPT) {
        auto fn = reinterpret_cast<AddHeadPartFn>(module_base
                                                  + ADD_HEADPART_RVA);
        // Flags per the pseudo-C (see appearance_recipe.cpp): replace the
        // same-type part, validate against race/sex, and DO apply extras —
        // a single manual part is the one case where auto-attaching its
        // hairline is what you want, since no recipe lists them.
        FW_LOG("[chargen-test] calling add-headpart(npc=%p, part=0x%08X, "
               "replace=1, validate=1, extras=1) from our own code",
               npc, want);
        __try {
            fn(npc, form, true, true, true);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            FW_ERR("[chargen-test] SEH inside add-headpart — aborted");
            g_done.store(true, std::memory_order_relaxed);
            return;
        }
        FW_LOG("[chargen-test] add-headpart returned cleanly. If nothing "
               "changed on screen, the rebuild trigger is required.");
    } else if (want) {
        FW_WRN("[chargen-test] form 0x%08X has type %u — expected 137 "
               "(colour) or 15 (head part). Nothing applied.", want, type);
    }

    // The whole point of tonight: make the change visible WITHOUT dying.
    // One Reset3D in the codebase, in appearance_recipe. This used to be a
    // private copy here; two copies of a five-argument engine call is two
    // places to get the arity wrong.
    (void)npc;
    fw::native::appearance::rebuild_player_head(module_base);

    verify_engine_round_trip(module_base);

    log_recipe_round_trip(module_base);

    if (const std::uint32_t d = g_donor.load(std::memory_order_relaxed)) {
        run_donor(module_base, d);
    }

    g_done.store(true, std::memory_order_relaxed);
}

}  // namespace fw::native::chargen_selftest
