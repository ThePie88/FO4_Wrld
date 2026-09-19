#include "appearance_recipe.h"

#include "scene_inject.h"  // ghost_note_local_3d_reset

#include <windows.h>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>

#include <algorithm>

#include "../engine/engine_calls.h"
#include "../net/client.h"
#include "face_borrow.h"
#include "../log.h"
#include "ni_offsets.h"

namespace fw::native::appearance {

namespace {

// Located empirically — see CHARGEN_PLAN §16. Every one of these was
// confirmed by applying a known value through the engine's own function and
// watching which slot took it.
constexpr std::size_t NPC_HEADDATA_OFF   = 0x248;  // -> sub-object
constexpr std::size_t HEADDATA_HAIRCOL   = 0x00;   // BGSColorForm*
constexpr std::size_t NPC_HEADPARTS_OFF  = 0x2D0;  // BGSHeadPart** array data
// The COUNT, located 2026-08-08 by byte-diffing the record across a known
// head-part apply: exactly one non-pointer byte moved, +0x2E8, from 12 to 13.
// Before this the reader walked to the first null and OVERRAN, returning 65
// parts including female ones for a male player — which would have handed a
// donor a monster. Never trust a null terminator you have not proven.
constexpr std::size_t NPC_HEADPART_COUNT = 0x2E8;
constexpr std::size_t NPC_RACE_OFF       = 0x1B8;  // TESRace*
constexpr std::size_t NPC_FLAGS_OFF      = 0x70;   // bit 0 = female
constexpr std::size_t FORM_ID_OFF        = 0x14;
constexpr std::size_t ACTOR_NPC_OFF      = 0xE0;

// TINTS — eyebrows, skin tone, scars, freckles, war paint.
//
// §26 corrected a wrong belief here that had survived several sections: tints do
// NOT go through the keyed-float map at TESNPC+0x2F8. That map is MORPHS only.
// The mistake came from misattributing a call site — the `*(_DWORD*)(v22 + 28)`
// argument quoted as a tint template's key actually lives in sub_140BBE9A0,
// which is menu-side morph code.
//
// Tints live in their own array: TESNPC+0x300 is a POINTER to a 0x18-byte
// BSTArray object {data, capacity, size} of Entry*. Each entry is 0x20 bytes and
// only three of its fields matter to a recipe.
//
// The array is a SPARSE DIFF against the race defaults — the engine deletes an
// entry that equals its default — so reading it yields exactly what the player
// changed, and a recipe carries only that.
constexpr std::size_t NPC_TINTS_OFF      = 0x300;
constexpr std::size_t TINTARR_DATA       = 0x00;
constexpr std::size_t TINTARR_SIZE       = 0x10;
constexpr std::size_t TINTENT_ID         = 0x10;  // uint16
constexpr std::size_t TINTENT_INTENSITY  = 0x12;  // uint8, 0..100
// +0x18 EXISTS ONLY ON A PaletteEntry, and reading it on any other entry class
// is a read past the end of the allocation.
//
// The factory sub_1403FF3A0 picks the class from the template type and allocates
// accordingly: MaskEntry 0x18 bytes, TextureSetEntry 0x18 bytes, PaletteEntry
// 0x20. All three write only +0x08 (template back-pointer), +0x10 (u16 id) and
// +0x12 (u8 intensity); PaletteEntry alone adds +0x18 (rgb, initialised to
// 0xFFFFFFFF) and +0x1C (palette colour id, initialised to 0xFFFF).
//
// This was shipped wrong for a few hours on 2026-08-08: the reader took +0x18
// unconditionally, so for every mask and texture-set tint it returned one byte
// past a 0x18-byte heap block. SEH-guarded, so it never faulted — and stable
// within a session, so the byte-identical round-trip test passed — but the value
// changed between launches, which made the recipe a function of the appearance
// AND the heap. Two of fifteen tints moved across two runs of the same save.
//
// So the discriminator is the entry's own vtable, the same one chargen_dump uses
// to name these classes.
constexpr std::size_t TINTENT_RGB        = 0x18;  // uint32, 0x00BBGGRR
constexpr std::uintptr_t VT_PALETTE_ENTRY = 0x0247FC88;
// Vanilla offers ~150 tint templates per sex; the cap is a runaway guard.
constexpr std::uint32_t MAX_TINTS        = 256;

// A head has ~13 parts; the cap is a runaway guard, not a real limit.
constexpr std::uint32_t MAX_HEAD_PARTS   = 64;

// Every read of engine memory goes through a guarded helper. Three separate
// faults on 2026-08-07/08 came from unguarded or layout-assumed reads; this
// is the rule that came out of them.
void* seh_ptr(const void* addr) noexcept {
    if (!addr) return nullptr;
    __try { return *reinterpret_cast<void* const*>(addr); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

std::uint32_t seh_u32(const void* addr) noexcept {
    if (!addr) return 0;
    __try { return *reinterpret_cast<const std::uint32_t*>(addr); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

bool plausible(const void* p) noexcept {
    const auto v = reinterpret_cast<std::uintptr_t>(p);
    return v > 0x10000 && v < 0x00007FFFFFFFFFFFULL && (v & 7) == 0;
}

std::uint32_t form_id_of(const void* form) noexcept {
    if (!plausible(form)) return 0;
    return seh_u32(reinterpret_cast<const std::uint8_t*>(form) + FORM_ID_OFF);
}

// The engine's own apply functions. Both signatures are validated
// empirically — the capture detours chained through them hundreds of times
// across several sessions without a fault — not read off a prototype. A
// wrong arity crashed New Game on 2026-08-08, so arity is treated as a
// safety property here.
constexpr std::uintptr_t SET_HAIRCOLOR_RVA    = 0x00654DF0;
constexpr std::uintptr_t ADD_HEADPART_RVA     = 0x00655010;
// sub_140655260(npc, part, removeExtras) — THREE arguments, per its
// pseudo-C declaration. It rebuilds the part array excluding `part`
// ("if (a2 != *v11)") and writes the new count back. Needed because
// add-headpart only replaces EXCLUSIVE types: re-applying a Misc part
// appends a duplicate, so a read/write round-trip grew 12 parts into 17.
constexpr std::uintptr_t REMOVE_HEADPART_RVA  = 0x00655260;
constexpr std::size_t    FORM_TYPE_OFF     = 0x1A;
constexpr std::uint8_t   FORMTYPE_HDPT     = 15;
constexpr std::uint8_t   FORMTYPE_CLFM     = 137;
// BGSHeadPart's extra-parts list (the HNAM subrecord): hairlines and the like,
// separate HDPT records carrying the IsExtraPart flag. Read off sub_140655010's
// own applyExtras branch, which recurses over `*(part+0x78)[0 .. *(part+0x88)-1]`.
constexpr std::size_t    HDPT_EXTRAS_DATA  = 0x78;
constexpr std::size_t    HDPT_EXTRAS_COUNT = 0x88;

// DELIBERATELY NOT USED HERE: sub_140659C60, the engine's own ValidateHeadParts.
//
// It looks like exactly the sanity pass this function should end with — it walks
// the array and strips any part carrying the OPPOSITE sex's flag bit, optionally
// substituting the race default. That is right for tidying the local player's own
// appearance, and wrong for what apply_to_npc is for.
//
// The borrow writes a PEER's recipe onto OUR TESNPC. If the peer is female and we
// are male, ValidateHeadParts would strip every female part and replace it with
// our race defaults — destroying the face the borrow exists to build, and doing it
// quietly. Cross-sex peers are a known gap (a recipe carries `sex`, but this
// function cannot safely change ours); it should fail visibly, not be papered
// over by a validator that produces a plausible wrong face.

// sub_14065DAB0(TESNPC*, uint16 tintId, float intensity, uint32 rgb) — FOUR
// arguments, read off the function itself: it takes npc+0x1B8 (the race), walks
// race + 0x698 + 8*sex, and lazily allocates the 0x18-byte array into
// *(npc + 0x300). Intensity is 0..1; the engine stores it as a 0..100 byte.
constexpr std::uintptr_t SET_TINT_RVA         = 0x0065DAB0;

// THE SECOND CALL, without which a tint changes nothing on screen.
//
// sub_14065DAB0 writes the TESNPC record. That is all it does. The vanilla menu
// follows every single call to it with a second one, and only when the record
// being edited belongs to the player:
//
//   sub_14065DAB0(npc, tintId, value, rgb);
//   if ( GetPlayerNPC() == npc )
//       sub_140D759E0(playerActor, tintId, value, rgb);
//
// sub_140D759E0 walks playerActor+0xD10 (the race) to the per-sex CharGenData and
// hands playerActor+0xD00 to sub_1403FE900, which is what actually restains the
// live character. Reset3D is NOT a substitute: it was called after all eight of
// the first attempt's tint writes and not one of them appeared, because rebuilding
// the head re-reads a record whose tints were already correct while the composited
// result was never regenerated.
constexpr std::uintptr_t SET_TINT_LIVE_RVA    = 0x00D759E0;
using SetTintLiveFn = void(__fastcall*)(void*, std::uint16_t, float,
                                        std::uint32_t);

// Resolving a tint's TEMPLATE DEFAULTS, which is what a correct "clear" applies.
//
// sub_1403FE900's delete rule is explicit: an entry is REMOVED only when the
// applied value equals template->GetDefaultValue() (and, for a positive value,
// the colour equals the template's default colour); anything else is WRITTEN,
// husks included. Mask templates default to 0.0, so clearing them with
// {0, no-colour} deletes cleanly — which is why tattoos and scars restored
// correctly. Palette templates (skin tone) default to a POSITIVE value, so the
// same clear wrote a husk instead of deleting, the sparse diff never returned
// to the race default, and every downstream consumer — the face composite, the
// body material, the cached skin RGB at TESNPC+0x2EA — kept showing the LAST
// skin ever applied. That is exactly "client B's skin overrides everything".
//
// So a clear resolves the template and applies ITS defaults, and the engine
// turns that into a deletion on whichever array the call targets. The resolver
// functions are the engine's own: sub_1403FFE70(container, id) is the exact
// lookup sub_1403FE900 itself uses, and sub_140400600 is the palette
// default-colour reader its delete rule compares against.
constexpr std::uintptr_t FIND_TINT_TEMPLATE_RVA = 0x003FFE70;
constexpr std::uintptr_t PAL_DEFAULT_RGB_RVA    = 0x00400600;
constexpr std::size_t    RACE_TINT_SLOT         = 0x698;   // + 8*sex, two derefs
constexpr std::size_t    TPL_TYPE_OFF           = 0x18;    // 7..20 = palette
using FindTintTemplateFn = void*(__fastcall*)(void*, std::uint16_t);
using TplDefaultValueFn  = float(__fastcall*)(void*);
using PalDefaultRgbFn    = std::uint32_t(__fastcall*)(void*);

// POD + SEH; returns false when anything along the chain is unreadable, and the
// caller falls back to the mask-style {0, no-colour} clear.
bool resolve_tint_default(std::uintptr_t base, void* npc, std::uint16_t id,
                          float* out_value, std::uint32_t* out_rgb) noexcept {
    *out_value = 0.0f;
    *out_rgb   = 0xFFFFFFFFu;
    __try {
        auto* n = reinterpret_cast<std::uint8_t*>(npc);
        void* race = *reinterpret_cast<void**>(n + NPC_RACE_OFF);
        if (!race) return false;
        const std::uint32_t sex = *reinterpret_cast<std::uint32_t*>(
                                      n + NPC_FLAGS_OFF) & 1u;
        void* slot = *reinterpret_cast<void**>(
            reinterpret_cast<std::uint8_t*>(race) + RACE_TINT_SLOT + 8u * sex);
        if (!slot) return false;
        void* cgd = *reinterpret_cast<void**>(slot);
        if (!cgd) return false;
        auto find = reinterpret_cast<FindTintTemplateFn>(
            base + FIND_TINT_TEMPLATE_RVA);
        void* tpl = find(cgd, id);
        if (!tpl) return false;
        auto value_fn = *reinterpret_cast<TplDefaultValueFn*>(
            *reinterpret_cast<std::uint8_t**>(tpl) + 8);
        *out_value = value_fn(tpl);
        const auto type = *reinterpret_cast<std::int32_t*>(
            reinterpret_cast<std::uint8_t*>(tpl) + TPL_TYPE_OFF);
        if (type >= 7 && type < 21) {
            auto rgb_fn = reinterpret_cast<PalDefaultRgbFn>(
                base + PAL_DEFAULT_RGB_RVA);
            *out_rgb = rgb_fn(tpl);
        }
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// The engine's "no colour" sentinel for a tint, and it is NOT zero.
//
// In sub_140BBFDC0 the rgb argument starts life as -1 and is only replaced by a
// real colour inside the palette branch, so every mask template is applied with
// 0xFFFFFFFF. Passing 0 instead means passing BLACK, which is a legitimate colour
// -- and since sub_1403FE900 deletes an entry whose value and colour match the
// template defaults, the wrong sentinel changes whether the entry survives at all.
constexpr std::uint32_t TINT_NO_COLOUR = 0xFFFFFFFFu;

using SetHairColorFn   = void(__fastcall*)(void*, void*);
using AddHeadPartFn    = void(__fastcall*)(void*, void*, bool, bool, bool);
using RemoveHeadPartFn = void(__fastcall*)(void*, void*, std::uint64_t);
using SetTintFn        = void(__fastcall*)(void*, std::uint16_t, float,
                                          std::uint32_t);

std::uint8_t seh_u8(const void* addr) noexcept {
    if (!addr) return 0;
    __try { return *reinterpret_cast<const std::uint8_t*>(addr); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

// Resolve a form id and refuse it unless it is the type we are about to
// hand to the engine. A stale or mistyped id in a recipe must not become a
// wild pointer inside an engine function.
void* resolve_typed(std::uint32_t form_id, std::uint8_t want_type) noexcept {
    if (!form_id) return nullptr;
    void* f = fw::engine::lookup_by_form_id(form_id);
    if (!plausible(f)) return nullptr;
    if (seh_u8(reinterpret_cast<std::uint8_t*>(f) + FORM_TYPE_OFF) != want_type) {
        return nullptr;
    }
    return f;
}

// sub_140655010(npc, part, replaceSameType, validate, applyExtras)
//
// All three flags read off the pseudo-C, not guessed:
//   a3 replaceSameType — the copy loop skips existing entries whose PNAM
//      (part+0x74) matches the incoming part, for types sub_14061C9A0 calls
//      exclusive. TRUE, or a second hair stacks on the first.
//   a4 validate — FALSE, because that is what the engine's own call site
//      passes (sub_140BBD500 does "xor r9d, r9d"). Setting it TRUE on the
//      strength of the pseudo-C looked righter and was wrong: the guard is
//      "if (sub_14068B950(race, sex, part)) return 0", and with it on every
//      EXCLUSIVE type was refused — hair, face, eyes, teeth, head-rear and
//      neck all vanished while the non-exclusive Misc parts went through,
//      12 parts in and 6 out. An observed argument beats an inferred one.
//   a5 applyExtras — recurses over part+0x78 / part+0x88 (the extra-part
//      array) and applies each. FALSE, deliberately: a recipe already lists
//      the extras as their own entries, so recursing applied every hairline
//      TWICE and produced the stacked-geometry hair tower seen on screen.
//      Applying exactly what the list says reproduces the source exactly.
//
// The same function also reads *(u8*)(npc+744) = npc+0x2E8 as the part count,
// independently confirming the offset found by byte-diffing.
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
// The same gates as can_reset_3d, without the log. Duplicated deliberately
// rather than adding a "quiet" flag: the loud version's whole value is that it
// prints all ten values when a committed call is refused, and threading a flag
// through it would make that path conditional and easy to break.
bool can_reset_3d_quiet(void* actor, void* expected_npc) noexcept {
    if (!actor) return false;
    if (seh_u8(reinterpret_cast<std::uint8_t*>(actor) + 0x1A) != 65) return false;
    if (seh_u8(reinterpret_cast<std::uint8_t*>(actor) + 0x10A) == 1) return false;
    if (seh_ptr(reinterpret_cast<std::uint8_t*>(actor) + 0xE0) != expected_npc)
        return false;
    void* loaded = seh_ptr(reinterpret_cast<std::uint8_t*>(actor) + 0xF0);
    if (!loaded) return false;
    if (!seh_ptr(reinterpret_cast<std::uint8_t*>(loaded) + 0x08)) return false;
    void* proc = seh_ptr(reinterpret_cast<std::uint8_t*>(actor) + 0x300);
    if (!proc) return false;
    void* mid = seh_ptr(reinterpret_cast<std::uint8_t*>(proc) + 0x08);
    if (!mid) return false;
    if (!seh_ptr(reinterpret_cast<std::uint8_t*>(proc) + 0x10)) return false;
    if (seh_u8(reinterpret_cast<std::uint8_t*>(proc) + 0xE4)) return false;
    if (seh_u16(reinterpret_cast<std::uint8_t*>(mid) + 0x496) & 0x20) return false;
    return true;
}

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
}  // namespace

bool can_rebuild_player_head(std::uintptr_t module_base) noexcept {
    if (!module_base) return false;
    void* actor = seh_ptr(reinterpret_cast<void*>(module_base
                                                 + PLAYER_SINGLETON_RVA));
    if (!actor) return false;
    void* npc = seh_ptr(reinterpret_cast<std::uint8_t*>(actor) + ACTOR_NPC_OFF);
    // Silent on purpose: this is a poll, and the noisy version already exists
    // inside rebuild_player_head for when a caller has committed.
    return can_reset_3d_quiet(actor, npc);
}

bool rebuild_player_head(std::uintptr_t module_base) noexcept {
    void* actor = seh_ptr(reinterpret_cast<void*>(module_base
                                                 + PLAYER_SINGLETON_RVA));
    void* npc = actor
        ? seh_ptr(reinterpret_cast<std::uint8_t*>(actor) + ACTOR_NPC_OFF)
        : nullptr;
    if (!can_reset_3d(actor, npc)) {
        FW_WRN("[reset3d] not calling Reset3D — a precondition would have made "
               "it a silent no-op");
        return false;
    }

    auto fn = reinterpret_cast<ActorReset3DFn>(module_base + ACTOR_RESET3D_RVA);
    FW_LOG("[reset3d] calling Actor::Reset3D(actor=%p, 0, 0, 1, 0) — the tuple "
           "Papyrus ChangeHeadPart and Actor::LoadGame use", actor);
    char rc = 0;
    __try {
        rc = fn(actor, 0, 0, 1, 0);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[reset3d] SEH inside Actor::Reset3D — aborted");
        return false;
    }
    FW_LOG("[reset3d] returned %d. It is ASYNCHRONOUS: the head builder runs a "
           "frame or more later, so watch for HEAD-BUILD records after this "
           "line, not on the same tick.", static_cast<int>(rc));
    // Il ghost si costruisce copiando questo corpo: finche' si sta rifacendo
    // non c'e' niente di buono da copiare. Vedi ghost_scene_is_stable.
    fw::native::ghost_note_local_3d_reset();
    return true;
}

namespace {


bool call_add_headpart(std::uintptr_t base, void* npc, void* part) noexcept {
    auto fn = reinterpret_cast<AddHeadPartFn>(base + ADD_HEADPART_RVA);
    __try {
        fn(npc, part, /*replaceSameType=*/true, /*validate=*/false,
           /*applyExtras=*/false);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

bool call_remove_headpart(std::uintptr_t base, void* npc, void* part) noexcept {
    auto fn = reinterpret_cast<RemoveHeadPartFn>(base + REMOVE_HEADPART_RVA);
    // removeExtras = 0: every part is removed explicitly from a snapshot, so
    // letting it recurse would remove entries twice and fight the snapshot.
    __try { fn(npc, part, 0); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

bool call_set_haircolor(std::uintptr_t base, void* npc, void* col) noexcept {
    auto fn = reinterpret_cast<SetHairColorFn>(base + SET_HAIRCOLOR_RVA);
    __try { fn(npc, col); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// Same reason as the three helpers above: the SEH has to live in a function that
// owns no unwindable object, or MSVC rejects the whole enclosing function with
// C2712. apply_to_npc now holds a std::vector, so this had to move out of it.
//
// The engine takes intensity as 0..1 and stores a 0..100 byte; handing it the
// percentage directly would clamp every tint to full.
bool call_set_tint(std::uintptr_t base, void* npc, const Tint& t) noexcept {
    auto fn = reinterpret_cast<SetTintFn>(base + SET_TINT_RVA);
    const float value = static_cast<float>(t.intensity_pct) / 100.0f;
    __try { fn(npc, t.tint_id, value, t.rgb); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// Raw-value variants, for the one caller that must NOT quantise: the clear.
// The engine's delete rule compares the value against the template default with
// EXACT float equality, so a default of, say, 0.578 pushed through the 0..100
// byte and back would come out 0.58, miss the comparison, and write a husk --
// the very failure the default-clear exists to end.
bool call_set_tint_raw(std::uintptr_t base, void* npc, std::uint16_t id,
                       float value, std::uint32_t rgb) noexcept {
    auto fn = reinterpret_cast<SetTintFn>(base + SET_TINT_RVA);
    __try { fn(npc, id, value, rgb); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

bool call_set_tint_live_raw(std::uintptr_t base, void* actor, std::uint16_t id,
                            float value, std::uint32_t rgb) noexcept {
    auto fn = reinterpret_cast<SetTintLiveFn>(base + SET_TINT_LIVE_RVA);
    __try { fn(actor, id, value, rgb); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

// The live half. Takes the ACTOR, not the NPC.
bool call_set_tint_live(std::uintptr_t base, void* actor, std::uint16_t id,
                        std::uint8_t pct, std::uint32_t rgb) noexcept {
    auto fn = reinterpret_cast<SetTintLiveFn>(base + SET_TINT_LIVE_RVA);
    const float value = static_cast<float>(pct) / 100.0f;
    __try { fn(actor, id, value, rgb); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

}  // namespace

Recipe read_from_npc(std::uintptr_t module_base, void* npc) noexcept {
    Recipe r;
    (void)module_base;
    if (!plausible(npc)) return r;
    auto* n = reinterpret_cast<std::uint8_t*>(npc);

    r.race_form_id = form_id_of(seh_ptr(n + NPC_RACE_OFF));
    r.female       = (seh_u32(n + NPC_FLAGS_OFF) & 1u) != 0;

    if (void* head_data = seh_ptr(n + NPC_HEADDATA_OFF)) {
        r.hair_colour = form_id_of(seh_ptr(
            reinterpret_cast<std::uint8_t*>(head_data) + HEADDATA_HAIRCOL));
    }

    // Counted walk. The count is a single byte at +0x2E8 (see above); the null
    // check stays as a belt-and-braces stop, and the cap keeps a corrupt count
    // from becoming a long read.
    const std::uint32_t count = seh_u32(n + NPC_HEADPART_COUNT) & 0xFFu;
    if (count > MAX_HEAD_PARTS) {
        FW_WRN("[recipe] head-part count %u exceeds the %u cap — reading none "
               "rather than reading garbage", count, MAX_HEAD_PARTS);
        return r;
    }
    if (void* data = seh_ptr(n + NPC_HEADPARTS_OFF)) {
        for (std::uint32_t i = 0; i < count; ++i) {
            void* part = seh_ptr(reinterpret_cast<std::uint8_t*>(data) + 8u * i);
            if (!plausible(part)) break;
            const std::uint32_t fid = form_id_of(part);
            if (fid == 0) break;
            r.head_parts.push_back(fid);
        }
        if (r.head_parts.size() != count) {
            FW_WRN("[recipe] count says %u head part(s) but only %zu were "
                   "readable", count, r.head_parts.size());
        }
    }

    // CANONICAL ORDER. A recipe is a SET of parts, one per slot — the array's
    // order is an artefact of the order they were applied in, and the engine
    // prepends, so writing a recipe back yields the same parts reversed. Left
    // unsorted, the same character serialises to different lines depending on
    // history, which would make the wire format and the server's per-identity
    // store non-comparable and every diff a false positive. Sorting here makes
    // the recipe a function of the appearance and nothing else.
    std::sort(r.head_parts.begin(), r.head_parts.end());

    // TINTS. A pointer to a 0x18-byte array object, absent until the character
    // has changed at least one tint away from its race default — so a null here
    // is normal and means "wearing the defaults", not "failed to read".
    if (void* arr = seh_ptr(n + NPC_TINTS_OFF)) {
        auto* a = reinterpret_cast<std::uint8_t*>(arr);
        const std::uint32_t tcount = seh_u32(a + TINTARR_SIZE);
        void* tdata = seh_ptr(a + TINTARR_DATA);
        if (tcount > MAX_TINTS) {
            FW_WRN("[recipe] tint count %u exceeds the %u cap — reading none "
                   "rather than reading garbage", tcount, MAX_TINTS);
        } else if (tdata && tcount) {
            for (std::uint32_t i = 0; i < tcount; ++i) {
                void* e = seh_ptr(reinterpret_cast<std::uint8_t*>(tdata)
                                  + 8u * i);
                if (!plausible(e)) break;
                auto* eb = reinterpret_cast<std::uint8_t*>(e);
                Tint t;
                t.tint_id       = seh_u16(eb + TINTENT_ID);
                t.intensity_pct = seh_u8 (eb + TINTENT_INTENSITY);
                // Only a PaletteEntry has an rgb. On a MaskEntry or a
                // TextureSetEntry the object ends at 0x18 and this offset is
                // adjacent heap — see the note on TINTENT_RGB above.
                t.rgb = 0;
                const void* vt = seh_ptr(eb);
                if (vt && reinterpret_cast<std::uintptr_t>(vt) > module_base &&
                    reinterpret_cast<std::uintptr_t>(vt) - module_base
                        == VT_PALETTE_ENTRY) {
                    t.rgb = seh_u32(eb + TINTENT_RGB);
                }
                // A zero id is not a tint. A zero INTENSITY is the engine's
                // "same as the race default" — and this comment always said so
                // while the code below it only checked the id. The gap cost a
                // two-client run: clearing a PALETTE tint with intensity 0 and
                // colour 0xFFFFFFFF leaves a zero-intensity husk in the array
                // (the engine's delete-if-default wants value AND colour to
                // match the template default, and a palette's default colour is
                // a real colour — masks delete cleanly, palettes do not). The
                // reader shipped the husk, so a restore that saved 15 tints
                // read 16 back and wedged; and side A published
                // 0484:0:FFFFFFFF to the server — a skin tone that says "no
                // skin tone", carried as data.
                //
                // An intensity-0 entry is invisible by definition; skipping it
                // loses nothing and makes recipes comparable again.
                if (t.tint_id == 0) continue;
                if (t.intensity_pct == 0) continue;
                r.tints.push_back(t);
            }
            if (r.tints.size() != tcount) {
                FW_WRN("[recipe] tint array says %u entr(ies) but %zu were "
                       "usable", tcount, r.tints.size());
            }
        }
    }

    // Same canonical-order argument as the parts above: the array's order is an
    // artefact of application order, so sort by id to make the line a function
    // of the appearance.
    std::sort(r.tints.begin(), r.tints.end(),
              [](const Tint& a, const Tint& b) {
                  return a.tint_id < b.tint_id;
              });
    return r;
}

Recipe read_from_player(std::uintptr_t module_base) noexcept {
    Recipe r;
    if (!module_base) return r;
    void* player = seh_ptr(reinterpret_cast<void*>(module_base
                                                   + PLAYER_SINGLETON_RVA));
    if (!player) return r;
    void* npc = seh_ptr(reinterpret_cast<std::uint8_t*>(player) + ACTOR_NPC_OFF);
    if (!npc) return r;
    return read_from_npc(module_base, npc);
}

void* player_npc(std::uintptr_t module_base) noexcept {
    if (!module_base) return nullptr;
    void* actor = seh_ptr(reinterpret_cast<void*>(module_base
                                                  + PLAYER_SINGLETON_RVA));
    if (!actor) return nullptr;
    return seh_ptr(reinterpret_cast<std::uint8_t*>(actor) + ACTOR_NPC_OFF);
}

void* npc_race(void* npc) noexcept {
    if (!plausible(npc)) return nullptr;
    return seh_ptr(reinterpret_cast<std::uint8_t*>(npc) + NPC_RACE_OFF);
}

bool npc_is_female(void* npc) noexcept {
    if (!plausible(npc)) return false;
    return (seh_u32(reinterpret_cast<std::uint8_t*>(npc) + NPC_FLAGS_OFF) & 1u)
           != 0;
}

std::uint32_t apply_to_npc(std::uintptr_t module_base, void* npc,
                           const Recipe& r) noexcept {
    if (!module_base || !plausible(npc)) return 0;
    std::uint32_t applied = 0;

    // CLEAR FIRST, then apply. Without this the writer is additive, not
    // reproductive: add-headpart replaces only types the engine considers
    // exclusive, so every Misc part (hairlines, lashes, AO, wet, mouth
    // shadow) appended a duplicate. Measured: 12 parts in, 17 out, and the
    // stacked geometry showed up in game as a tower of hair.
    //
    // The removals work off a SNAPSHOT of the pointers, because each removal
    // rebuilds the array and invalidates any live iteration over it.
    {
        auto* n = reinterpret_cast<std::uint8_t*>(npc);
        const std::uint32_t have = seh_u32(n + NPC_HEADPART_COUNT) & 0xFFu;
        void* snapshot[MAX_HEAD_PARTS] = {};
        std::uint32_t taken = 0;
        if (void* data = seh_ptr(n + NPC_HEADPARTS_OFF)) {
            const std::uint32_t lim = have > MAX_HEAD_PARTS ? 0u : have;
            for (std::uint32_t i = 0; i < lim; ++i) {
                void* part = seh_ptr(reinterpret_cast<std::uint8_t*>(data)
                                     + 8u * i);
                if (plausible(part)) snapshot[taken++] = part;
            }
        }
        std::uint32_t removed = 0;
        for (std::uint32_t i = 0; i < taken; ++i) {
            if (call_remove_headpart(module_base, npc, snapshot[i])) ++removed;
        }
        const std::uint32_t left = seh_u32(n + NPC_HEADPART_COUNT) & 0xFFu;
        FW_LOG("[recipe] cleared %u of %u existing part(s), %u left",
               removed, taken, left);
    }

    // EXPAND EXTRA PARTS before applying.
    //
    // A hair like HairFemale35 owns hairlines as separate HDPT records carrying
    // IsExtraPart, listed in a BSTArray at BGSHeadPart+0x78 with its count at
    // +0x88. A recipe read off a live player already contains them — that is why
    // the reader returns twelve parts and not five — but a recipe the EDITOR
    // builds from a selection will name parents only. Expanding here makes both
    // shapes apply identically, so the editor never has to know about hairlines.
    //
    // Why not the engine's own `applyExtras` argument: it recurses with
    // replaceSameType set, and the same-type purge only fires for EXCLUSIVE
    // types (sub_14061C9A0 = {1 Face, 2 Eyes, 3 Hair, 4 FacialHair, 6 Eyebrows,
    // 8 Teeth, 9 HeadRear}). Hairlines are type 0 Misc, so the purge is a no-op
    // for them and every pre-existing hairline survives — that is the tower of
    // hair seen on screen on 2026-08-08. Expanding into a deduplicated set and
    // adding each part exactly once, after a full clear, cannot double anything.
    std::vector<std::uint32_t> want = r.head_parts;
    for (const std::uint32_t fid : r.head_parts) {
        void* part = resolve_typed(fid, FORMTYPE_HDPT);
        if (!part) continue;
        auto* pb = reinterpret_cast<std::uint8_t*>(part);
        const std::uint32_t n_extra = seh_u32(pb + HDPT_EXTRAS_COUNT);
        void* edata = seh_ptr(pb + HDPT_EXTRAS_DATA);
        if (!edata || n_extra == 0 || n_extra > MAX_HEAD_PARTS) continue;
        for (std::uint32_t i = 0; i < n_extra; ++i) {
            void* ex = seh_ptr(reinterpret_cast<std::uint8_t*>(edata) + 8u * i);
            if (!plausible(ex)) continue;
            const std::uint32_t exf = form_id_of(ex);
            if (exf == 0) continue;
            if (std::find(want.begin(), want.end(), exf) == want.end()) {
                want.push_back(exf);
            }
        }
    }
    if (want.size() != r.head_parts.size()) {
        FW_LOG("[recipe] expanded %zu part(s) to %zu by pulling in extra parts "
               "the recipe did not name", r.head_parts.size(), want.size());
    }

    // Head parts first, colour after: the vanilla menu's order, and the
    // colour is a property of the hair that is now present.
    for (const std::uint32_t fid : want) {
        void* part = resolve_typed(fid, FORMTYPE_HDPT);
        if (!part) {
            FW_WRN("[recipe] part 0x%08X missing or not a head part — skipped",
                   fid);
            continue;
        }
        if (call_add_headpart(module_base, npc, part)) {
            ++applied;
        } else {
            FW_ERR("[recipe] SEH applying part 0x%08X — aborting the rest",
                   fid);
            return applied;
        }
    }

    if (r.hair_colour) {
        void* col = resolve_typed(r.hair_colour, FORMTYPE_CLFM);
        if (!col) {
            FW_WRN("[recipe] colour 0x%08X missing or not a colour form",
                   r.hair_colour);
        } else if (call_set_haircolor(module_base, npc, col)) {
            ++applied;
        }
    }

    // TINTS last. They depend on the race's tint chain rather than on the head
    // parts, so the order relative to the parts does not matter — but doing them
    // after means a log read top-to-bottom follows the same order as the line.
    // THE PLAYER HAS TWO TINT ARRAYS, and both must be written or the visible
    // result silently detaches from the record. The compositor's state machine
    // (sub_1406DF150, state 0) reads the tints "from player Actor+3328 (or
    // TESNPC+768)": for anyone else the TESNPC record is the source, but for
    // the PLAYER it is the actor-side array that sub_140D759E0 maintains. This
    // function used to write only the record, which produced three symptoms
    // with one cause: the borrow built the peer's parts with the LOCAL tints
    // (each screen's ghost wore the local tattoos and skin over the peer's
    // hair), the join-time adoption restored the hair but no tattoos, and
    // dying rebuilt the head from stale actor-side data. The editor never
    // showed the problem because its set_tint calls both paths itself.
    const bool tints_to_player = (npc == player_npc(module_base));
    void* player_actor = tints_to_player
        ? seh_ptr(reinterpret_cast<void*>(module_base + PLAYER_SINGLETON_RVA))
        : nullptr;

    {
        // CLEAR THE TINTS FIRST TOO, for exactly the reason the parts are cleared
        // above -- and this one cost a whole two-client test.
        //
        // The tint array at TESNPC+0x300 is a SPARSE DIFF against the race
        // defaults, and sub_14065DAB0 replaces or deletes one keyed entry at a
        // time. Applying a recipe's tints on top of whatever is already there is
        // therefore additive: the result is (existing UNION recipe), not the
        // recipe. Every tint the recipe does not mention survives.
        //
        // For the face borrow that is fatal rather than merely untidy. The borrow
        // saves the local recipe, writes the PEER's recipe onto the local player,
        // clones the built face onto the ghost, then restores. With additive
        // tints the restore could never reproduce the saved recipe, so the
        // verification failed and the borrow WEDGED on its first attempt --
        // correctly refusing to try again on top of a failed restore. Both
        // clients wedged, so each one's ghost of the other kept the local
        // player's tints: on A's screen both faces wore A's blue makeup and pale
        // skin, on B's both wore B's radiation tattoo and dark skin, while the
        // hair -- a head part, cleared properly -- differed correctly.
        //
        // Clearing everything currently applied and then applying the recipe
        // makes this reproductive: the result IS the recipe, which is what a
        // restore needs and what a peer's face needs.
        const Recipe now = read_from_npc(module_base, npc);
        std::uint32_t cleared = 0;
        for (const Tint& t : now.tints) {
            const bool wanted = std::any_of(
                r.tints.begin(), r.tints.end(),
                [&](const Tint& w) { return w.tint_id == t.tint_id; });
            if (wanted) continue;   // about to be overwritten anyway
            // Clear BY APPLYING THE TEMPLATE'S DEFAULTS, so the engine deletes
            // the entry instead of writing a husk. See resolve_tint_default for
            // why {0, no-colour} was only ever a correct clear for masks.
            float         def_val = 0.0f;
            std::uint32_t def_rgb = TINT_NO_COLOUR;
            resolve_tint_default(module_base, npc, t.tint_id,
                                 &def_val, &def_rgb);
            if (call_set_tint_raw(module_base, npc, t.tint_id,
                                  def_val, def_rgb)) {
                ++cleared;
            }
            if (player_actor) {
                call_set_tint_live_raw(module_base, player_actor, t.tint_id,
                                       def_val, def_rgb);
            }
        }
        if (cleared) {
            FW_LOG("[recipe] cleared %u tint(s) the recipe does not carry (had "
                   "%zu, recipe has %zu)", cleared, now.tints.size(),
                   r.tints.size());
        }
    }

    if (!r.tints.empty()) {
        std::uint32_t ok = 0;
        for (const Tint& t : r.tints) {
            if (!call_set_tint(module_base, npc, t)) {
                FW_ERR("[recipe] SEH applying tint id=%u — aborting the "
                       "remaining tints", t.tint_id);
                break;
            }
            if (player_actor) {
                call_set_tint_live(module_base, player_actor, t.tint_id,
                                   t.intensity_pct, t.rgb);
            }
            ++ok;
            ++applied;
        }
        if (ok != r.tints.size()) {
            FW_WRN("[recipe] applied %u of %zu tint(s)", ok, r.tints.size());
        }
    }

    FW_LOG("[recipe] applied %u field(s) to npc=0x%08X (%zu part(s), %zu tint(s) "
           "in the recipe)", applied, form_id_of(npc), r.head_parts.size(),
           r.tints.size());
    return applied;
}

std::uint32_t apply_to_player(std::uintptr_t module_base,
                              const Recipe& r) noexcept {
    if (!module_base) return 0;
    void* player = seh_ptr(reinterpret_cast<void*>(module_base
                                                   + PLAYER_SINGLETON_RVA));
    if (!player) return 0;
    void* npc = seh_ptr(reinterpret_cast<std::uint8_t*>(player) + ACTOR_NPC_OFF);
    if (!npc) return 0;
    return apply_to_npc(module_base, npc, r);
}

namespace {
std::atomic<bool> g_editing{false};

// The PNAM of a head part, resolved through the form. Needed because a recipe
// carries form ids and nothing else, so replacing "the hair" means asking each
// part what type it is.
std::int32_t part_type_of(std::uint32_t form_id) noexcept {
    void* part = resolve_typed(form_id, FORMTYPE_HDPT);
    if (!part) return -1;
    return static_cast<std::int32_t>(
        seh_u32(reinterpret_cast<std::uint8_t*>(part) + 0x74));
}
}  // namespace

std::uint32_t current_part_of_type(std::uintptr_t module_base,
                                   std::int32_t type) noexcept {
    const Recipe r = read_from_player(module_base);
    for (const std::uint32_t fid : r.head_parts) {
        if (part_type_of(fid) == type) return fid;
    }
    return 0;
}

std::uint32_t current_hair_colour(std::uintptr_t module_base) noexcept {
    return read_from_player(module_base).hair_colour;
}

bool swap_part(std::uintptr_t module_base, std::int32_t type,
               std::uint32_t form_id) {
    if (!module_base || form_id == 0) return false;
    if (fw::native::face_borrow::in_progress()) {
        FW_WRN("[recipe] refusing to swap a part while a face borrow is in "
               "flight — the player is wearing a peer's appearance right now");
        return false;
    }
    Recipe r = read_from_player(module_base);
    if (r.head_parts.empty()) return false;

    // Drop every part of this type, then put the new one in. A recipe is a set
    // with one part per exclusive type, so this is what "swap" means.
    const auto before = r.head_parts.size();
    r.head_parts.erase(
        std::remove_if(r.head_parts.begin(), r.head_parts.end(),
                       [&](std::uint32_t fid) {
                           return part_type_of(fid) == type;
                       }),
        r.head_parts.end());
    if (std::find(r.head_parts.begin(), r.head_parts.end(), form_id)
            == r.head_parts.end()) {
        r.head_parts.push_back(form_id);
    }
    std::sort(r.head_parts.begin(), r.head_parts.end());

    FW_LOG("[recipe] swap type=%d -> 0x%08X (%zu part(s) became %zu)",
           type, form_id, before, r.head_parts.size());
    apply_to_player(module_base, r);
    return rebuild_player_head(module_base);
}

bool set_tint(std::uintptr_t module_base, std::uint16_t tint_id,
              std::uint8_t intensity_pct, std::uint32_t rgb, bool rebuild) {
    if (!module_base || tint_id == 0) return false;
    if (fw::native::face_borrow::in_progress()) {
        FW_WRN("[recipe] refusing to set a tint while a face borrow is in "
               "flight - the player is wearing a peer's appearance right now");
        return false;
    }
    void* npc = player_npc(module_base);
    if (!plausible(npc)) return false;

    // Applied DIRECTLY rather than through a recipe round-trip, unlike
    // swap_part. A head part swap has to go through the recipe because it must
    // clear the other parts of the same exclusive type first; a tint has no such
    // rule -- the engine's own setter is keyed by tint id and replaces or deletes
    // that one entry by itself. sub_1403FE900 even removes the entry outright
    // when the value matches the race default, which is what makes the array a
    // sparse diff, and reconstructing that behaviour from our side would be
    // copying it badly.
    Tint t;
    t.tint_id       = tint_id;
    t.intensity_pct = intensity_pct;
    t.rgb           = rgb;
    if (!call_set_tint(module_base, npc, t)) {
        FW_WRN("[recipe] set_tint faulted for id=%u", tint_id);
        return false;
    }

    // The live restain, and then a rebuild. BOTH, and the reason the rebuild is
    // back deserves recording because removing it was a wrong call made from a
    // contaminated measurement.
    //
    // The first attempt kept only Reset3D and nothing appeared, so Reset3D was
    // declared useless and dropped in favour of sub_140D759E0 alone -- and still
    // nothing appeared. What that run actually proved is narrower than the
    // conclusion drawn from it: at the time the tints were being written with a
    // zero intensity and a zero colour, so the engine was DELETING every entry as
    // soon as it was applied. Reset3D was faithfully rebuilding a record with no
    // tints in it. With the sentinel and the intensity fixed, a hair swap -- which
    // is to say a Reset3D -- makes the accumulated tints appear at once, which is
    // the observation that settled it.
    //
    // So the rebuild is what puts a tint on screen, the live call is what the
    // engine's own menu does alongside it, and doing both is a superset of both.
    void* actor = seh_ptr(reinterpret_cast<void*>(module_base
                                                  + PLAYER_SINGLETON_RVA));
    const bool live = actor && call_set_tint_live(module_base, actor, tint_id,
                                                  intensity_pct, rgb);
    FW_LOG("[recipe] tint %u -> intensity %u%% rgb=0x%08X, live=%s, rebuild=%s",
           tint_id, intensity_pct, rgb, live ? "ok" : "FAILED",
           rebuild ? "yes" : "deferred");
    if (!rebuild) return live;
    return rebuild_player_head(module_base) || live;
}

bool current_tint(std::uintptr_t module_base, std::uint16_t tint_id,
                  std::uint8_t* out_intensity, std::uint32_t* out_rgb) noexcept {
    if (out_intensity) *out_intensity = 0;
    if (out_rgb)       *out_rgb = 0;
    if (!module_base || tint_id == 0) return false;
    const Recipe r = read_from_player(module_base);
    for (const auto& t : r.tints) {
        if (t.tint_id != tint_id) continue;
        if (out_intensity) *out_intensity = t.intensity_pct;
        if (out_rgb)       *out_rgb = t.rgb;
        return true;
    }
    return false;
}

bool set_hair_colour(std::uintptr_t module_base, std::uint32_t colour_form_id) {
    if (!module_base || colour_form_id == 0) return false;
    if (fw::native::face_borrow::in_progress()) {
        FW_WRN("[recipe] refusing to set the hair colour while a face borrow is "
               "in flight");
        return false;
    }
    Recipe r = read_from_player(module_base);
    if (r.hair_colour == colour_form_id) return false;
    r.hair_colour = colour_form_id;
    FW_LOG("[recipe] hair colour -> 0x%08X", colour_form_id);
    apply_to_player(module_base, r);
    return rebuild_player_head(module_base);
}

// Set when the server says this identity has no character yet; cleared ONLY by a
// confirmation. Separate from g_editing on purpose -- see the header.
std::atomic<bool> g_chargen_pending{false};

void set_chargen_pending(bool on) noexcept {
    const bool was = g_chargen_pending.exchange(on, std::memory_order_acq_rel);
    if (was == on) return;
    if (on) {
        FW_LOG("[appearance] character creation is PENDING: nothing will be "
               "published until it is confirmed, so closing the panel by any "
               "other route cannot finish the ritual by accident");
    } else {
        FW_LOG("[appearance] character creation CONFIRMED - the finished "
               "appearance may now be published");
    }
}

bool chargen_pending() noexcept {
    return g_chargen_pending.load(std::memory_order_acquire);
}

// ---- the authoritative own appearance, server -> this client ----------------
// Written by the network thread, consumed by the main tick. States:
//   0 nothing arrived   1 pending apply   2 adopted   3 none is coming / gave up
std::mutex        g_auth_mx;
std::string       g_auth_line;
std::atomic<int>  g_auth_state{0};

void set_editing(bool on) noexcept {
    const bool was = g_editing.exchange(on, std::memory_order_acq_rel);
    if (was != on) {
        // Says which of the two gates is still shut. Reporting "publishing is
        // live again" on close was true only before the pending flag existed,
        // and it is exactly the sort of confidently wrong line that sends the
        // next reader looking in the wrong place.
        const char* pub = on            ? "held off (panel open)"
                        : chargen_pending() ? "STILL held off (creation not "
                                              "confirmed yet)"
                                            : "live again";
        FW_LOG("[appearance] editor %s — borrows and publishing are %s",
               on ? "OPENED" : "CLOSED", pub);
    }
}

bool editing() noexcept { return g_editing.load(std::memory_order_acquire); }

void adopt_authoritative(const std::string& recipe_line) {
    {
        std::lock_guard<std::mutex> lk(g_auth_mx);
        // 2026-09-18 — se e' la stessa ricetta che abbiamo gia' adottato,
        // non c'e' niente da adottare.
        //
        // Rialzare lo stato fa scattare al tick seguente un
        // `rebuild_player_head`, cioe' lo smontaggio e la ricostruzione
        // della testa del giocatore LOCALE. Dal vivo capita una volta sola
        // all'ingresso e non si nota; ma un client che rientra si rigioca
        // l'intero bootstrap, aspetti compresi, e quella ricostruzione
        // diventerebbe uno scatto visibile a ogni riconnessione.
        if (recipe_line == g_auth_line
            && g_auth_state.load(std::memory_order_acquire) > 1) {
            FW_LOG("[appearance] the server sent back the character we have "
                   "already adopted (%zu bytes) - nothing to do",
                   recipe_line.size());
            return;
        }
        g_auth_line = recipe_line;
    }
    g_auth_state.store(1, std::memory_order_release);
    FW_LOG("[appearance] the server holds OUR character (%zu bytes) - it will "
           "be applied to the local player on the next tick and becomes the "
           "publish baseline", recipe_line.size());
}

void publish_if_changed(std::uintptr_t module_base) {
    if (!module_base) return;

    // Reading the recipe walks the live record; at 2 s the cost is invisible
    // and a chargen change still reaches peers effectively immediately.
    static DWORD       s_last_ms = 0;
    static std::string s_last_sent;
    static bool        s_was_editing = false;
    const DWORD now = GetTickCount();

    // While the editor is open every intermediate state is a real change, so
    // publishing would broadcast each half-finished face. Hold off, and on the
    // falling edge clear the throttle so the FINISHED appearance goes out on
    // the very next tick instead of up to 2 s later.
    const bool is_editing = editing();
    if (is_editing) { s_was_editing = true; return; }

    // AND NOT UNTIL THE RITUAL IS CONFIRMED. This gate is separate from the one
    // above, and the reason is a real hole that closing the panel used to open.
    //
    // The design said "the recipe's arrival IS the confirmation", which is only
    // sound if a confirmation is the only thing that can lower the editing flag.
    // It is not: the toggle key lowers it too. So a session where the key was
    // cycled -- for something completely unrelated, in the case that found this,
    // just to straighten a camera -- published the recipe on the falling edge,
    // the server recorded it, the body became visible to everyone, and the next
    // join reported chargen_required=0. The ritual completed itself without
    // anybody confirming anything, and the only trace was a log line.
    //
    // Two flags, two questions. Is the panel open (hold off, the face is
    // half-finished)? Has the character been confirmed (until then there is no
    // character to publish at all)? Only CONFIRM answers the second one.
    if (chargen_pending()) { s_was_editing = false; return; }

    if (s_was_editing) { s_was_editing = false; s_last_ms = 0; }

    // ADOPT THE SERVER'S RECIPE FIRST, if one is pending. It outranks whatever
    // the save loaded: the local player is redressed from it and the publisher
    // baseline is set to it, so nothing default ever goes out. Retries every
    // tick until the player is built and no borrow is wearing a peer's face.
    if (g_auth_state.load(std::memory_order_acquire) == 1) {
        if (fw::native::face_borrow::in_progress()) return;
        std::string line;
        {
            std::lock_guard<std::mutex> lk(g_auth_mx);
            line = g_auth_line;
        }
        Recipe want;
        if (!from_line(line, &want)) {
            FW_ERR("[appearance] the server's stored recipe for us does not "
                   "parse (%zu bytes) - ignoring it and keeping the save's "
                   "look", line.size());
            g_auth_state.store(3, std::memory_order_release);
        } else if (!can_rebuild_player_head(module_base)) {
            return;   // world not ready; try again next tick
        } else {
            const std::uint32_t n = apply_to_player(module_base, want);
            rebuild_player_head(module_base);
            s_last_sent = line;
            g_auth_state.store(2, std::memory_order_release);
            FW_LOG("[appearance] ADOPTED the server's character: %u field(s) "
                   "applied, head rebuilding. The save's default look never "
                   "existed as far as anyone else is concerned.", n);
            return;
        }
    }

    if (s_last_ms != 0 && now - s_last_ms < 2000) return;
    s_last_ms = now;

    // NEVER publish while a borrow is in flight. During a borrow the local
    // player is deliberately wearing a PEER's appearance, and publishing it
    // would tell the server that face is ours — which then broadcasts it to
    // everyone and makes every client wrong, from a mechanism whose whole
    // purpose is to make them right.
    if (fw::native::face_borrow::in_progress()) return;

    const Recipe r = read_from_player(module_base);
    if (r.head_parts.empty()) return;   // player not built yet

    const std::string line = to_line(r);
    if (line == s_last_sent) return;

    // FIRST-PUBLISH GRACE. Never sent anything and no adoption arrived: the
    // bootstrap may still be in flight, and publishing now is exactly the
    // clobber the adoption exists to prevent -- the save's default look would
    // overwrite the stored character on the server. Ten seconds is two orders
    // of magnitude above the bootstrap's real latency; if nothing arrives in
    // that long, the server genuinely has no character for this identity and
    // the save's look is legitimately ours to publish.
    if (s_last_sent.empty() &&
        g_auth_state.load(std::memory_order_acquire) == 0) {
        static DWORD s_grace_t0 = 0;
        if (s_grace_t0 == 0) s_grace_t0 = now;
        if (now - s_grace_t0 < 10000) return;
        g_auth_state.store(3, std::memory_order_release);
        FW_LOG("[appearance] no stored character arrived from the server "
               "within 10 s - the save's look is the character");
    }

    fw::net::client().enqueue_appearance_set(line);
    // Log the CHANGE, not every check — an appearance that changes is an
    // event worth seeing in a log; one that does not is noise.
    if (s_last_sent.empty()) {
        FW_LOG("[appearance] publishing my appearance for the first time "
               "(%zu part(s))", r.head_parts.size());
    } else {
        FW_LOG("[appearance] my appearance CHANGED — republishing "
               "(%zu part(s))", r.head_parts.size());
    }
    s_last_sent = line;
}

std::string to_line(const Recipe& r) {
    char head[128];
    std::snprintf(head, sizeof(head), "v2\trace=%08X\tsex=%c\thair=%08X\tparts=",
                  r.race_form_id, r.female ? 'F' : 'M', r.hair_colour);
    std::string out(head);
    for (std::size_t i = 0; i < r.head_parts.size(); ++i) {
        char buf[16];
        std::snprintf(buf, sizeof(buf), "%s%08X", i ? "," : "",
                      r.head_parts[i]);
        out += buf;
    }
    // Always emit the field, even empty. A reader that finds `tints=` and
    // nothing after it knows the sender had no tints; a reader that does not
    // find the field at all is looking at a v1 line from an older store.
    out += "\ttints=";
    for (std::size_t i = 0; i < r.tints.size(); ++i) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%s%04X:%u:%08X", i ? "," : "",
                      r.tints[i].tint_id,
                      static_cast<unsigned>(r.tints[i].intensity_pct),
                      r.tints[i].rgb);
        out += buf;
    }
    return out;
}

bool from_line(const std::string& line, Recipe* out) {
    if (!out) return false;
    Recipe r;

    // Strict: every field must be present and parse. A half-parsed appearance
    // would render as a silently wrong character, which is harder to notice
    // and harder to debug than a rejected one.
    auto field = [&line](const char* key, std::string* val) -> bool {
        const std::string k = std::string("\t") + key + "=";
        const auto p = line.find(k);
        if (p == std::string::npos) return false;
        const auto s = p + k.size();
        auto e = line.find('\t', s);
        if (e == std::string::npos) e = line.size();
        *val = line.substr(s, e - s);
        return true;
    };
    auto hex32 = [](const std::string& s, std::uint32_t* v) -> bool {
        if (s.empty() || s.size() > 8) return false;
        char* end = nullptr;
        const unsigned long long p = std::strtoull(s.c_str(), &end, 16);
        if (!end || *end != '\0' || p > 0xFFFFFFFFull) return false;
        *v = static_cast<std::uint32_t>(p);
        return true;
    };

    // v1 is still accepted, and deliberately so: the server persists appearance
    // lines across restarts, so its snapshot can hold v1 lines written before
    // tints existed. Rejecting them would silently wipe every stored character
    // the first time a v2 build read the file. A v1 line simply has no tints.
    const bool is_v1 = (line.rfind("v1\t", 0) == 0);
    const bool is_v2 = (line.rfind("v2\t", 0) == 0);
    if (!is_v1 && !is_v2) return false;

    std::string race, sex, hair, parts;
    if (!field("race", &race) || !field("sex", &sex) ||
        !field("hair", &hair) || !field("parts", &parts)) {
        return false;
    }
    if (sex != "M" && sex != "F") return false;
    if (!hex32(race, &r.race_form_id)) return false;
    if (!hex32(hair, &r.hair_colour)) return false;
    r.female = (sex == "F");

    std::size_t pos = 0;
    while (pos <= parts.size() && !parts.empty()) {
        const auto comma = parts.find(',', pos);
        const std::string tok = parts.substr(
            pos, comma == std::string::npos ? std::string::npos : comma - pos);
        std::uint32_t v = 0;
        if (!hex32(tok, &v)) return false;
        r.head_parts.push_back(v);
        if (comma == std::string::npos) break;
        pos = comma + 1;
    }

    if (is_v2) {
        std::string tints;
        if (!field("tints", &tints)) return false;   // v2 must carry the field
        std::size_t tp = 0;
        while (tp < tints.size()) {
            const auto comma = tints.find(',', tp);
            const std::string tok = tints.substr(
                tp, comma == std::string::npos ? std::string::npos : comma - tp);
            // ID:PCT:RGB — all three required. Anything else is a malformed
            // line, and a half-parsed appearance is worse than a rejected one.
            const auto c1 = tok.find(':');
            if (c1 == std::string::npos) return false;
            const auto c2 = tok.find(':', c1 + 1);
            if (c2 == std::string::npos) return false;
            std::uint32_t id = 0, rgb = 0;
            if (!hex32(tok.substr(0, c1), &id) || id > 0xFFFFu) return false;
            if (!hex32(tok.substr(c2 + 1), &rgb)) return false;
            const std::string pct_s = tok.substr(c1 + 1, c2 - c1 - 1);
            if (pct_s.empty() || pct_s.size() > 3) return false;
            char* pend = nullptr;
            const unsigned long pct = std::strtoul(pct_s.c_str(), &pend, 10);
            if (!pend || *pend != '\0' || pct > 100) return false;
            Tint t;
            t.tint_id       = static_cast<std::uint16_t>(id);
            t.intensity_pct = static_cast<std::uint8_t>(pct);
            t.rgb           = rgb;
            r.tints.push_back(t);
            if (comma == std::string::npos) break;
            tp = comma + 1;
        }
    }

    *out = std::move(r);
    return true;
}

}  // namespace fw::native::appearance
