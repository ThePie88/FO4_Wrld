// Anatomy mirror (2026-08-07) — the ghost wears the local player's face.
//
// HOW THIS BECAME SIMPLE
//   The read-only anatomy probe showed the player's whole face lives under a
//   single node (BSFaceGenNiNodeSkinned, vtable RVA 0x24FF280) whose 12
//   children are BSDynamicTriShape parts — and every child's NODE NAME is the
//   EDITOR ID of a BGSHeadPart form ("HairMale01", "MaleEyesHumanHazel", ...).
//   The head-part catalogue maps editor id -> NIF path. So replicating the
//   player's face onto the ghost does not need geometry cloning at all:
//
//       read child names  ->  resolve to NIF paths  ->  load + attach
//
//   using load_nif_and_apply + skin swap, the exact machinery that already
//   dresses the ghost's hardcoded head today. The base head and head-rear the
//   ghost already loads are themselves just the Face and HeadRear entries of
//   this list, so the mirror only ADDS the missing parts (hair, hairline,
//   beard, eyes, mouth, neck) — it changes no existing load.
//
// WHAT THIS DOES NOT DO (yet)
//   - Morphs: the catalogue NIF is the neutral mesh. The player's baked
//     vertex deltas are not carried over. Shape fidelity is the clone-factory
//     step, later. Part fidelity — right hair, right beard, right eye colour
//     — is this step.
//   - Face texture: skin tone and tints are composited by FaceGen at runtime;
//     the mirrored parts render with their stock textures.
//   - Sex/race: the ghost base head stays male-human for now; parts follow
//     the player. Full fidelity arrives with the profile work.
//
// SAFETY
//   collect() is main-thread-only and read-only (same SEH pattern as the
//   probe). The loads it feeds run inside inject_head, on the paths and
//   flags that have been loading the ghost head since v11. Config-gated,
//   default off; when off, cost is one atomic load at inject.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace fw::native::anatomy_mirror {

struct Part {
    std::string   edid;    // node name == head-part editor id
    std::string   path;    // model path resolved from the catalogue
    std::uint32_t pnam;    // part type: 1 Face, 9 HeadRear are pre-loaded
    std::uint32_t form_id;
    void*         src_node = nullptr;  // the player's live facegen child
    void*         dst_node = nullptr;  // the ghost node this part became
};

// Arm/disarm from config. Called from dll_main.
void init(bool enabled, bool clone);
bool enabled() noexcept;

// True when the FACE CLONE is armed (config key `ghost_face_clone`). It takes
// precedence over the mirror: cloning the player's built subtree supersedes
// re-loading the same NIFs by path, and running both would render two faces
// in the same place.
bool clone_enabled() noexcept;

// The player's whole face is ONE node — BSFaceGenNiNodeSkinned, vtable RVA
// 0x24FF280, a direct child of the third-person root, with its 12 geometry
// children. Exposed so the clone path in scene_inject can locate it without
// duplicating the walk. Returns null if the root has no such child.
void* find_facegen_node(std::uintptr_t module_base, void* player_root) noexcept;

// The local player's live face node, resolved from the third-person root in
// one call. The borrow watches this pointer: Reset3D is asynchronous, so
// "the rebuild finished" is observed as this returning a DIFFERENT node than
// before, not assumed from a return code.
void* player_face_node(std::uintptr_t module_base) noexcept;

// Read the local player's face composition and resolve it against the
// head-part forms. MAIN THREAD ONLY. Returns the number of parts resolved
// (0 on any failure — the ghost then keeps today's hardcoded look).
// Idempotent per call; each call re-reads the live state.
std::size_t collect(std::uintptr_t module_base);

// The parts the last collect() produced.
const std::vector<Part>& parts() noexcept;

// Mutable access for the attach loop in scene_inject: it records which ghost
// node each part became (dst_node), so the tint pass can pair source and
// destination without name lookups.
std::vector<Part>& parts_mut() noexcept;

// The colour pass. Copies the runtime tint payloads the engine has already
// computed on the LOCAL PLAYER's materials onto the ghost's freshly loaded
// ones — the same photocopy philosophy as the parts themselves:
//   - SkinTint  (vt 0x290A190): RGBA at material+0xC0, 16 bytes — skin tone.
//     Harvested once from any player geometry, applied to every SkinTint
//     material under the ghost body and head.
//   - HairTint  (vt 0x290A228): RGB at +0xC0, 12 bytes — the hair colour.
//     Copied per-part from the matching player shape.
//   - Face      (vt 0x290A0F8): NiPointer<NiTexture> at +0xC0 — the FaceGen
//     COMPOSITED texture (skin tone + tints baked by the engine at runtime).
//     Pointer-copied with a refcount increment, so the ghost head shares the
//     player's real composited face. No GPU readback needed.
// Layouts measured in the 2026-08-07 RE pass (ctors at 0x1421C9CC0 SkinTint
// 0xD0 bytes, 0x1421C9EB0 HairTint 0xD0, 0x1421C9780 Face 0xC8 with the
// lock-inc NiPointer pattern; SkinTint CopyMembers 0x1421C9DA0 moves one
// XMM from +0xC0).
// MAIN THREAD ONLY. Call after the parts are attached and skin-swapped.
void copy_tints(std::uintptr_t module_base, void* ghost_body,
                void* ghost_head);

// Skin tone only — the narrow survivor of copy_tints once the face is cloned.
//
// The face clone (§19) carries its own materials, so the per-part copies and
// the composited-face texture share are obsolete. The BODY is not cloned: it
// is a separate NIF (MaleBody.nif) deep-cloned from the resource cache, so its
// skin keeps the stock tone and has to be told the player's.
//
// Mechanically: harvest the player's BSLightingShaderMaterialSkinTint (vtable
// RVA 0x290A190) and memcpy its 16-byte payload at +0xC0 onto every SkinTint
// material under the ghost body. Measured working on 2026-08-07 before the
// clone existed. Must run AFTER the hands are attached — they load later than
// the head, and running it earlier left them stock-dark.
//
// Returns the number of materials recoloured. MAIN THREAD ONLY.
int copy_skin_tone(std::uintptr_t module_base, void* ghost_body);

// Give a cloned face ITS OWN copies of the composited face textures, so the
// ghost stops changing complexion whenever the local player's head is rebuilt.
//
// WHY (RE 2026-08-11, decomp-verified end to end). The clone machinery is not
// the culprit: BSFaceGenNiNode::CreateClone deep-copies the node, the property
// (BSLightingShaderProperty::CreateClone allocates fresh, unconditionally) and
// the material (SetMaterial unique=1 -> Create + CopyMembers). What CopyMembers
// shares -- by refcounted pointer, sub_1421C5F90 -- is the NiTexture wrappers at
// material +0x48/+0x50/+0x60. And those wrappers' rendererData (+0x38) point at
// GLOBAL render-target pool slots 16/17/18 of dword_142F42710, the targets named
// FaceCustomizationDiffuse/Normals/SmoothSpec (sub_1406F3DF0). The tint composite
// re-renders into those same global slots on every head rebuild, for whoever is
// being rebuilt. One canvas per process; every stale wrapper watches it.
//
// THE FIX: at clone time -- while the composite still holds the PEER's face --
// duplicate each composited texture with CopyResource on the game's own device
// and swap the wrapper's rendererData to the copy. The draw path re-walks
// material -> NiTexture -> +0x38 -> SRV on every BSLightingShader::SetupMaterial
// (sub_142232DC0), comparison is raw-pointer, so the swap takes effect on the
// next frame with no other invalidation. The wrapper is briefly still shared
// with the live head (until the restore rebuild replaces it with fresh wrappers)
// but the snapshot's CONTENT is identical at that instant, so nothing visible.
//
// The snapshots are deliberately never freed: their BSGraphics::Texture struct
// is ours, not the pool's, and handing it to the engine's release path would
// free our D3D objects with the wrong allocator. A few MB per borrow, bounded
// by how often peers change their face. Returns the number of wrappers swapped
// (3 for one face geometry). MAIN THREAD ONLY.
int own_face_composite(std::uintptr_t module_base, void* clone_root);

// Paint a subtree's SkinTint materials with the skin colour the ENGINE computes
// for this NPC, rather than copying it from the live player's body materials.
//
// The copy was the bug: the borrow rebuilds only the HEAD, so during the borrow
// window the player's body materials still carry the LOCAL skin — and copying
// from them gave every ghost the local complexion from the shoulders down while
// the face (which goes through the composite) came out right. The engine's own
// pair does it properly: sub_1406555D0(npc, float4*, 0, 1) computes the colour
// from the NPC's tint state with the engine's own conversion, and sub_1406EED30
// (root, float4*) walks the subtree writing it into every GetType()==5 material
// at +0xC0 and marking the property dirty. Called at clone time, while the
// player's NPC still wears the PEER's recipe, npc-side state is the peer's —
// which is the whole point.
//
// Returns true when both engine calls survived. MAIN THREAD ONLY.
bool paint_skin_from_npc(std::uintptr_t module_base, void* npc,
                         void* subtree_root);

// The compute/stash/paint split of the above, and why it exists: the borrow
// completes and the ghost BODY gets injected in whichever order the session
// happens to produce -- measured 11 and 16 seconds apart, borrow first, in the
// run that found this. The colour can only be computed at clone time (the one
// window in which the player's NPC wears the PEER's recipe), but the body may
// not exist yet to paint. So the borrow computes and STASHES; the inject path
// paints the stash right after its own local copy, overriding it. The stash
// stays valid until the next borrow replaces it, so a re-injected body gets
// repainted too.
bool compute_skin_from_npc(std::uintptr_t module_base, void* npc,
                           float out_col[4]);
void stash_ghost_skin(const float col[4]);
// Returns true when a stashed colour existed and was painted onto the subtree.
bool paint_stashed_ghost_skin(std::uintptr_t module_base, void* subtree_root);

}  // namespace fw::native::anatomy_mirror
