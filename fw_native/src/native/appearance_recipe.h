// Appearance recipe (2026-08-08) — the data structure the whole
// character-customisation epic is built on.
//
// WHAT A RECIPE IS
//   A character's visible identity expressed as engine form ids, nothing
//   else: no meshes, no textures, no vertex data. Engine-native means every
//   client has identical vanilla Data, so a form id is a universal constant —
//   0x0023A474 is "The Hornet's Nest" on every machine. That makes a
//   character a couple of hundred bytes on the wire instead of megabytes of
//   geometry, and makes a change a message instead of a re-upload.
//
//   See CHARGEN_PLAN §12 for why this beats shipping the built result, and
//   §16 for how each field below was located (by applying a KNOWN value and
//   seeing which slot took it — never by guessing an offset).
//
// LAYOUT THIS DEPENDS ON
//   TESNPC+0x248 -> +0x00   BGSColorForm*  hair colour
//   TESNPC+0x2D0            BGSHeadPart**  head parts, null-terminated
//   TESNPC+0x1B8            TESRace*
//   TESNPC+0x70   bit 0     female
//   Morphs, body weights and tints are NOT located yet and are therefore NOT
//   in the recipe. It is honest about that: a v1 recipe carries parts, hair
//   colour, race and sex, which is what makes a character recognisable.
//
// WHAT IT IS NOT, YET
//   Reading is implemented and testable today. Writing (apply a recipe to an
//   NPC) is the next step and is deliberately a separate function, because
//   applying has to go through the engine's own apply calls — writing these
//   fields directly would set data the engine never rebuilt from.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace fw::native::appearance {

// One applied face tint. This is what carries eyebrows and skin tone, and
// §26 corrected a wrong belief about it: tints do NOT live in the keyed-float
// map at TESNPC+0x2F8 (that is morphs only). They live in a separate array at
// TESNPC+0x300, written by sub_14065DAB0(npc, uint16 tintId, float, uint32 rgb).
//
// `tint_id` is the template's `+0x1C` read as a **uint16**. Never as 32 bits:
// `+0x1E` is a flags byte and `+0x1F` is never initialised.
//
// `intensity_pct` is 0..100, which is exactly how the engine stores it (a byte
// at PaletteEntry+0x12, read back multiplied by 0.01). Carrying the engine's own
// resolution makes the round-trip lossless instead of nearly lossless.
//
// `rgb` is a packed colour, and the channel order is settled by data (§29):
// 0x00BBGGRR, byte 0 is RED. Pale skin is 0x00EEEFF7 = RGB(247,239,238).
struct Tint {
    std::uint16_t tint_id       = 0;
    std::uint8_t  intensity_pct = 0;
    std::uint32_t rgb           = 0;
};

struct Recipe {
    std::uint32_t              race_form_id  = 0;
    bool                       female        = false;
    std::uint32_t              hair_colour   = 0;   // BGSColorForm form id
    // BGSHeadPart form ids, ALWAYS in ascending order: a recipe is a set,
    // and a canonical order is what makes two recipes comparable.
    std::vector<std::uint32_t> head_parts;
    // Applied tints, ALWAYS sorted by tint_id, for the same reason the parts
    // are sorted: two recipes must be comparable as text. The engine's array is
    // a sparse diff against the race defaults, so this carries only what the
    // player changed — small for free.
    std::vector<Tint>          tints;

    bool empty() const noexcept {
        return race_form_id == 0 && hair_colour == 0 && head_parts.empty()
            && tints.empty();
    }
};

// Read a recipe off a TESNPC. MAIN THREAD ONLY (it walks live engine data).
// Returns an empty recipe if the NPC is not readable.
Recipe read_from_npc(std::uintptr_t module_base, void* npc) noexcept;

// Convenience: the local player's TESNPC.
Recipe read_from_player(std::uintptr_t module_base) noexcept;

// The local player's TESNPC and its TESRace, for callers that need the records
// themselves rather than a recipe -- the tint catalogue has to walk the race's
// per-sex CharGenData, which a recipe cannot carry.
//
// Exposed rather than re-derived on purpose: the player singleton RVA, the
// actor-to-NPC offset and the race offset are all facts that were established
// once and would silently drift if a second module kept its own copies.
// Null when the player does not exist yet. MAIN THREAD ONLY.
void* player_npc(std::uintptr_t module_base) noexcept;
void* npc_race(void* npc) noexcept;
bool  npc_is_female(void* npc) noexcept;

// Compact, stable text form — one line, tab-separated, form ids in hex.
// This is what goes on the wire and into the server's per-identity store.
// Deliberately human-readable: an appearance bug should be diagnosable from
// a log line without a decoder.
std::string to_line(const Recipe& r);

// Parse what to_line produced. Returns false on any malformed field rather
// than half-filling the recipe — a partial appearance is worse than none.
bool from_line(const std::string& line, Recipe* out);

// Write a recipe onto a TESNPC, through the ENGINE'S OWN apply functions —
// never by poking the fields directly. §15 established why: data written
// behind the engine's back is data it never rebuilt from, and the character
// silently stays as it was. So this calls sub_140655010 per head part and
// sub_140654DF0 for the hair colour, exactly as the vanilla menu does.
//
// Note what it does NOT do: trigger a rebuild. The apply does not redraw an
// already-built head (§15). For a fresh NPC — the donor case — the first
// build picks this up naturally, which is the whole point. For the local
// player, a 3D reload (death, cell change) is what shows it.
//
// Returns the number of fields successfully applied. MAIN THREAD ONLY.
std::uint32_t apply_to_npc(std::uintptr_t module_base, void* npc,
                           const Recipe& r) noexcept;

// The local player's TESNPC.
std::uint32_t apply_to_player(std::uintptr_t module_base,
                              const Recipe& r) noexcept;

// Force the engine to rebuild the local player's head NOW.
//
// Actor::Reset3D, RVA 0xC73DD0, FIVE arguments, tuple (actor, 0, 0, 1, 0) —
// what Papyrus ChangeHeadPart, the chargen menu and Actor::LoadGame all use.
// See CHARGEN_PLAN §18: an apply alone does NOT redraw an already-built head,
// which is why dying used to be the only way to see a change.
//
// ASYNCHRONOUS. It queues the work; the head builder runs a frame or more
// later. A caller that needs the result must wait and watch, not assume.
//
// Returns false if a precondition would have made it a silent no-op — every
// gate in that chain returns early without logging, so they are all checked
// and reported here instead. MAIN THREAD ONLY.
bool rebuild_player_head(std::uintptr_t module_base) noexcept;

// Would rebuild_player_head() actually do something right now?
//
// Same gates, no side effects and no logging. Exists so a caller can PROBE
// BEFORE COMMITTING: the borrow used to write a peer's appearance onto the
// local player and only then discover Reset3D was refused, which during a
// loading screen meant writing and undoing a full recipe every 1.5 s. Check
// first, write second.
bool can_rebuild_player_head(std::uintptr_t module_base) noexcept;

// Publish the local player's appearance to the server when it CHANGES.
//
// Not a one-shot on join: the creator exists, so a character can change
// mid-session, and a join-only send would leave every peer looking at a stale
// face with no event to correct it. Comparing against the last line sent makes
// the common case (nothing changed) free, and the server also ignores an
// unchanged recipe — belt and braces, because a client that spams is a client
// that degrades everyone's session.
//
// Self-throttled; safe to call every tick. MAIN THREAD ONLY (it reads live
// engine data). No-op until the player exists and the client is connected.
void publish_if_changed(std::uintptr_t module_base);

// ---------------------------------------------------------------- live editing
//
// Swap ONE head part on the local player and make it visible, which is what a
// click in the editor does.
//
// `type` is the PNAM the new part belongs to (3 Hair, 2 Eyes, 4 FacialHair, ...)
// and it is what makes this a swap rather than an addition: the recipe is read
// off the player, every part of that type is dropped, the new one is put in, and
// the whole thing is applied and rebuilt. Going through the recipe rather than
// calling add-headpart directly is deliberate — the recipe is the one place that
// knows about clearing first, expanding extra parts, and the flags the engine's
// own call site uses.
//
// `set_hair_colour` is the same idea for the one field that is not a part.
//
// Both refuse while a face borrow is in flight: the borrow has the player
// wearing a peer's appearance, and editing on top of that would be authoring
// onto somebody else's face.
//
// Returns false when nothing changed. MAIN THREAD ONLY.
bool swap_part(std::uintptr_t module_base, std::int32_t type,
               std::uint32_t form_id);
bool set_hair_colour(std::uintptr_t module_base, std::uint32_t colour_form_id);

// Apply ONE face tint and make it visible: eyebrows, skin tone, scars, tattoos,
// war paint, dirt. These are not head parts and cannot be reached through
// swap_part -- vanilla ships zero eyebrow and zero scar head parts because the
// engine does them as tints.
//
// `intensity_pct` is 0..100, the resolution the engine itself stores (a byte at
// PaletteEntry+0x12). Zero means "the race default", and the engine responds by
// DELETING the entry rather than storing a zero -- which is how a tint is
// removed, and why there is no separate clear function here.
//
// `rgb` is 0x00BBGGRR for a Palette template and must be 0xFFFFFFFF -- NOT zero
// -- for a Mask. Zero is black, a real colour; 0xFFFFFFFF is what the engine's own
// menu passes when there is no colour, and the difference decides whether the
// applied entry survives sub_1403FE900's delete-if-default check.
//
// Refuses while a face borrow is in flight, for the same reason swap_part does.
// Returns false when nothing was applied. MAIN THREAD ONLY.
// `rebuild` exists so a caller that is about to apply several tints in one go --
// clearing a group's previous selection before setting the new one, say -- pays
// for a single head rebuild at the end instead of one per write.
bool set_tint(std::uintptr_t module_base, std::uint16_t tint_id,
              std::uint8_t intensity_pct, std::uint32_t rgb,
              bool rebuild = true);

// What the player currently has for this tint id, so the editor can show the
// selection without keeping its own copy. False when the tint is not applied --
// which, given the array is a sparse diff, is the normal case for most ids.
bool current_tint(std::uintptr_t module_base, std::uint16_t tint_id,
                  std::uint8_t* out_intensity, std::uint32_t* out_rgb) noexcept;

// The part the local player currently wears of a given type, or 0. Lets the
// editor show which row is selected without keeping its own state, so the panel
// can never disagree with the character.
std::uint32_t current_part_of_type(std::uintptr_t module_base,
                                   std::int32_t type) noexcept;
std::uint32_t current_hair_colour(std::uintptr_t module_base) noexcept;

// EDITING — the local player's appearance is being authored right now.
//
// Two things must stand aside while this is true, and they are the reason the
// flag exists rather than each module keeping its own:
//
//   - face_borrow must not borrow. Both the borrow and the editor write the
//     player's TESNPC, and a borrow landing mid-edit would have the editor
//     author on top of a peer's face and the borrow's restore then write back
//     the half-finished snapshot it happened to capture. The settle guard makes
//     that unlikely — the editor changes the face node on every edit, so the
//     guard would mostly hold a borrow off — but mostly is not a design.
//
//   - publish_if_changed must not publish. Every intermediate state during
//     editing is a real change to the local player, so the publisher would
//     broadcast each half-finished face to every peer. The appearance is worth
//     sending once, when it is finished.
//
// Setting this to false publishes on the very next tick rather than waiting out
// the throttle: closing the editor is exactly the moment peers should be told.
//
// Cheap and safe to read from any thread.
void set_editing(bool on) noexcept;
bool editing() noexcept;

// CHARGEN PENDING -- the server is waiting for this identity to be created, and
// nothing may be published until somebody confirms it.
//
// WHY THIS IS NOT THE SAME FLAG AS `editing`. The two answer different questions
// and conflating them cost a silent bug. `editing` means the panel is up, so the
// appearance in front of us is half-finished; it goes down whenever the panel
// closes, including via the toggle key. `chargen_pending` means there is no
// character yet at all, and it goes down only on confirmation.
//
// With one flag, closing the panel any other way published the work-in-progress
// as if it were finished: the server stored it, the body became visible to the
// other clients, and the next join no longer asked for the ritual. It was found
// by cycling the toggle key for an unrelated reason -- to straighten the camera --
// and it completed the whole ritual without a single deliberate confirmation.
//
// Set from the WELCOME handler on the network thread; cleared by CONFIRM. Atomic,
// readable from anywhere.
void set_chargen_pending(bool on) noexcept;
bool chargen_pending() noexcept;

// The server sent OUR OWN stored recipe (it does so in the appearance
// bootstrap at join). Adopt it: apply it to the local player on the next
// main-thread tick and make it the publisher's baseline, so the freshly-loaded
// save's default look neither shows nor gets published over the stored one.
//
// WHY THIS EXISTS. The server is authoritative and the save is a vessel; a
// character customised through the ritual lives only in the server's recipe.
// Before this, a client joined, read its default save character, and published
// it -- overwriting the stored custom recipe for everyone. Both test characters
// were lost that way in one join.
//
// Network-thread safe; the apply itself happens on the main tick inside
// publish_if_changed, which retries until the player is built.
void adopt_authoritative(const std::string& recipe_line);

}  // namespace fw::native::appearance
