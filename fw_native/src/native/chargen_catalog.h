// Chargen catalogue (2026-08-08) — the option lists the editor picks from.
//
// BUILT AT RUNTIME, NOT SHIPPED AS AN ASSET
//   An earlier plan was a JSON asset so the editor would do no reverse
//   engineering at load. Dropped in favour of walking TESDataHandler's form
//   arrays directly: fewer moving parts, no build step, and it cannot go stale
//   against the game's own data. The walk is one pass over 420 head parts and
//   166 colour forms, once, and it is the same walk chargen_dump already does.
//
// THE FILTER IS THE VANILLA MENU'S
//   sub_140BBB120 builds its per-type lists with four tests, and this uses the
//   same ones (CHARGEN_PLAN §26/§29):
//     1. the type is EXCLUSIVE           sub_14061C9A0 = {1,2,3,4,6,8,9}
//     2. the part is valid for the race  BGSHeadPart+0x160, null = all races
//     3. the OPPOSITE sex bit is clear   flags 0x02 male, 0x04 female
//     4. Playable                        flags 0x01
//   IsExtraPart (0x08) is excluded too: hairlines and the like are reached
//   through their parent, never picked directly.
//
// WHAT THE COUNTS COME OUT AT
//   Measured from the live catalogue: 48 hair (M) / 39 (F), 20 eyes, 43 facial
//   hair (M only), 1 face, 3 teeth, 1 head rear. Plus 166 colour forms. So the
//   editor's real surface is four lists, not a wall of sliders — vanilla has
//   ZERO eyebrow and ZERO scar head parts, because those are tints.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace fw::native::catalog {

struct Option {
    std::uint32_t form_id = 0;
    std::int32_t  type    = 0;    // BGSHeadPart PNAM; unused for colours
    std::string   name;           // display name, or the editor id when blank
};

// Walk the form arrays and build the lists for this sex. Idempotent per sex:
// the second call with the same sex returns immediately. MAIN THREAD ONLY.
// Returns false when the data handler is not populated yet — try again later.
bool build(std::uintptr_t module_base, bool female);

// True once build() has succeeded for the sex the player currently is.
bool ready(bool female) noexcept;

// Head parts of one PNAM type, filtered as described above. Empty when the
// catalogue is not built or the type has no playable entries.
//   1 Face   2 Eyes   3 Hair   4 FacialHair   8 Teeth   9 HeadRear
const std::vector<Option>& parts_of_type(std::int32_t type) noexcept;

// Every BGSColorForm, for hair and facial hair. 166 of them in vanilla.
const std::vector<Option>& colours() noexcept;

// ------------------------------------------------------------------- tints
//
// Eyebrows, skin tone, scars, tattoos, war paint and dirt are NOT head parts.
// Vanilla has zero type-5 (Scar) and zero type-6 (Eyebrow) head parts, which is
// why the Face and Hair tabs can never offer them: they are TINTS, applied with
// sub_14065DAB0(npc, uint16 tintId, float intensity, uint32 rgb) into the sparse
// array at TESNPC+0x300.
//
// Where they live: race + 0x698 + 8*sex -> CharGenData -> +0x00 BSTArray<Group*>,
// and each group holds an array of templates at +0x10 with its count at +0x20.
// Every offset below was already proven by the offline dumper (chargen_dump.cpp)
// against 306 captured template records, so this walk reuses those facts rather
// than re-deriving them.
//
// TWO FAMILIES, and the distinction drives the whole UI. A template's class comes
// from its `type` at +0x18: below 7 it is a Mask, 7..20 a Palette, 21 and above a
// TextureSet. A Palette carries a list of named colours; a Mask carries none and
// is a shape with an intensity. So Skin tone (one Palette template, type 12, with
// 13 colours) needs a colour grid, while Brows needs a plain list.
//
// GROUP ORDER IS NOT THE SAME FOR THE TWO SEXES and must never be indexed by
// number. Male:   Grime, Face Paint, Brows, Face Tattoos, SkinTints, Damage,
//                 Markings, Blemishes, FaceRegions
// Female: Grime, Face Paint, Brows, Face Tattoos, MAKEUP, SkinTints, Damage,
//                 Blemishes, FaceRegions, Markings
// Slot 4 is SkinTints on a male and Makeup on a female. Look groups up by name.

struct TintColour {
    std::uint32_t clfm_form_id = 0;
    std::uint32_t rgb          = 0;    // 0x00BBGGRR; 0 when the form remaps
    float         alpha        = 0.0f; // the template's own value for this entry
    std::string   name;
};

struct TintOption {
    std::uint16_t tint_id = 0;      // the key sub_14065DAB0 takes
    std::int32_t  type    = 0;      // +0x18; 12 is skin tone
    std::uint8_t  flags   = 0;      // bit0: binary on/off, intensity forced to 1
    bool          palette = false;  // true when `colours` is meaningful
    std::string   name;             // TTGP, "Default" when the record has none
    std::vector<TintColour> colours;
};

struct TintGroup {
    std::string  name;              // "Brows", "SkinTints", "Face Paint", ...
    std::uint32_t ttge = 0;
    std::vector<TintOption> items;
};

// Walk the player's own race and sex. Idempotent per sex, like build(). Returns
// false when the race data is not reachable yet. MAIN THREAD ONLY.
bool build_tints(std::uintptr_t module_base);

// Empty until build_tints has succeeded.
const std::vector<TintGroup>& tint_groups() noexcept;

// The group with this exact name, or null. Use this rather than an index.
const TintGroup* tint_group(const char* name) noexcept;

}  // namespace fw::native::catalog
