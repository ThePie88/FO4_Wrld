// M9 wedge 4 (witness pattern, step 2) — local-player weapon NIF walker.
//
// PURPOSE:
//   After the SENDER's equip detour chains to g_orig_equip (which causes the
//   engine to assemble the modded weapon onto the local player's BipedAnim),
//   we walk the weapon subtree under the player's loaded3D. For each
//   NiAVObject we encounter, we query nif_path_cache to recover the .nif
//   path the engine used to load it. Cache hits found UNDER the weapon
//   root are mod attachments; their (path, parent_node_name, local_transform)
//   tuple becomes a wire descriptor the receiver can replay locally.
//
// WHY THIS WORKS:
//   The engine loads each mod NIF as a separate file via sub_1417B3E90 and
//   attaches the resulting BSFadeNode under a named NiNode inside the base
//   weapon's NIF tree (e.g. "BarrelAttachNode", "ScopeAttachNode"). By
//   reading the engine's own assembly result, we sidestep the entire mod
//   pipeline (BGSMod descriptors, BGSObjectInstanceExtra OMOD records,
//   BipedAnim::ProcessTechniques, BGSNamedNodeAttach) — which RE iter 6→9
//   conclusively proved is fused with REFR vt[119]/vt[136] Reset3D and
//   cannot be invoked on a non-Actor receiver.
//
// THREADING:
//   MAIN THREAD ONLY. The walker traverses the engine's scene graph which
//   is mutated only on the main thread. Calling from another thread can
//   race against UpdateWorldData.
//
// FAILURE MODES (return empty Snapshot):
//   - PlayerSingleton null (loading screen / pre-game)
//   - loaded3D null (player ragdoll'd or in transition)
//   - no WEAPON / Weapon / WeaponBone / RArm_Hand attach node found
//     in the body subtree (very rare; means the skeleton variant doesn't
//     match any of our candidate names — log and bail)
//   - SEH during walk (logged; partial snapshot may still be returned)

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace fw::native::weapon_witness {

// One mod NIF the engine attached during weapon assembly. The local
// transform is the FULL NiTransform (rotation 3x4 SIMD + translate vec3
// + scale float = 16 floats = 64 bytes) read from node+0x30..+0x70. The
// receiver can write it back into the same offset on its replicated NIF.
struct ModDescriptor {
    std::string nif_path;          // e.g. "Weapons\\10mmPistol\\Mods\\Barrel_Long.nif"
    std::string parent_node_name;  // e.g. "BarrelAttachNode"
    float       local_transform[16]; // raw NiTransform: rot[12] + trans[3] + scale[1]
};

// One snapshot of the local player's currently-equipped weapon assembly.
struct Snapshot {
    std::string base_nif_path;     // e.g. "Weapons\\10mmPistol\\10mmPistol.nif"
    std::string base_parent_name;  // bone name where engine attached the base ("WEAPON")
    std::vector<ModDescriptor> mods;  // cache hits found under the base
};

// === M9.w4 Path B — raw mesh extraction (iter 11 RE complete) ============
//
// One BSGeometry leaf the engine assembled into the player's modded
// weapon subtree. We extract enough data for the receiver to RECONSTRUCT
// the same shape locally via factory sub_14182FFD0 (M2 dossier proven).
//
// All fields live in HEAP-ALLOCATED arrays owned by the struct (deep
// copies of the engine's internal buffers — the engine retains its own
// copies; ours can be freely freed when the wire encoding is done).
struct ExtractedMesh {
    std::string m_name;              // e.g. "10mmHeavyPortedBarrel002:0"
    // Immediate parent of the BSGeometry leaf — in practice, the mod NIF
    // root (e.g. "Pistol10mmReceiver"). Used by the receiver as the KEY
    // for the resmgr-share lookup (matches the cached BSFadeNode m_name).
    std::string parent_placeholder;
    // Grand-parent of the BSGeometry leaf — in practice, the slot
    // placeholder NiNode in the base weapon NIF (e.g. "PistolReceiver").
    // Used by the receiver to position the mod under the right slot in
    // the loaded base. May be empty if grandparent missing or unnamed.
    // (Added 2026-05-05 to fix the "all-mods-stacked-at-root" bug.)
    std::string slot_name;
    std::string bgsm_path;           // e.g. "Materials\\Weapons\\10mmPistol\\10mmPistol.bgsm"

    std::uint16_t vert_count = 0;
    std::uint32_t tri_count  = 0;     // idx_count = 3 * tri_count

    std::vector<float>         positions;  // 3*vc floats (xyz per vertex)
    std::vector<std::uint16_t> indices;    // 3*tc u16 (one triangle = 3 indices)

    float local_transform[16] = {};  // raw NiTransform from node+0x30
};

// Result of the new Path B sender extraction. Replaces the old `Snapshot`
// for weapon-mod sync. Each ExtractedMesh corresponds to one BSGeometry
// leaf found below the weapon root.
struct MeshSnapshot {
    std::string weapon_root_name;    // base weapon name (e.g. "Weapon  (00004822)")
    std::string attach_bone_name;    // the WEAPON / RArm_Hand bone the weapon is on
    std::vector<ExtractedMesh> meshes;
};

// Walk + extract. Returns MeshSnapshot with `meshes.empty()` on failure.
// Main thread only. Always SEH-safe internally (per-leaf failures don't
// poison the whole snapshot).
MeshSnapshot snapshot_player_weapon_meshes();

// Pretty-print mesh snapshot to FW_LOG. Includes vertex count, triangle
// count, position bbox, indices checksum, m_name, bgsm_path per mesh.
void log_mesh_snapshot(const MeshSnapshot& s, const char* tag = "[mesh-witness]");

// Walk the local player's BipedAnim weapon subtree and produce a snapshot.
// Empty snapshot (base_nif_path empty) on failure. Always SEH-safe.
//
// Cap on mods discovered: 32 (matches MAX_EQUIP_MODS protocol cap).
// Beyond that we log a warning and truncate.
Snapshot snapshot_local_player_weapon();

// Pretty-print a snapshot to the FW_LOG channel. Never throws.
void log_snapshot(const Snapshot& s, const char* tag = "[witness]");

// M9.w4 PROPER (v0.4.2+) — single-source mesh extraction for the
// clone-factory-driven capture pipeline (weapon_capture module).
// Takes a BSGeometry-derived node (BSTriShape / BSSITF) and fills
// `m` with positions, indices, transform, m_name, bgsm_path.
//
// Returns true on success, false if:
//   - geom is null
//   - reading +0x148 helper struct fails (= not a real BSGeometry,
//     e.g. NiNode where +0x148 is past-the-end heap garbage)
//   - vert_count or tri_count is zero
//   - any SEH read fails on engine memory
//
// SEH-safe internally. Main thread only (engine memory mutates from
// main thread via clone factory + render walk).
bool extract_mesh_for_capture(void* geom, ExtractedMesh& m);

// Low-level scene-graph readers — public wrappers around the
// anonymous-namespace primitives in weapon_witness.cpp. Allow other
// TUs (e.g. weapon_capture's finalize post-pass that re-reads
// slot_name from the clone's grandparent after assembly settles)
// to access them without exposing the anon-ns internals.
//
// All SEH-caged. Return null/false on AV.
void* read_parent_pub(void* node);
bool  read_node_name_pub(void* node, char* buf, std::size_t bufsz);

// 2026-05-06 — walk UP from `leaf` (a BSGeometry leaf or any descendant of
// a mod NIF subtree) looking for the FIRST ancestor whose vtable RVA is
// BSFADENODE_VTABLE_RVA (= the mod NIF's root, since loaded NIFs wrap in
// BSFadeNode). Returns that BSFadeNode or nullptr if not found within
// `max_walk` levels.
//
// Used by both clone-time (weapon_witness.cpp extract_one_mesh) and
// finalize-time (weapon_capture.cpp post-pass) to locate the mod-NIF
// boundary so we can derive the BASE PLACEHOLDER name (= the mod root's
// PARENT m_name) instead of accidentally landing inside a mod-internal
// wrapper like "P-Receiver".
void* find_mod_nif_root_pub(void* leaf, int max_walk = 8);

// 2026-05-06 LATE evening (M9 closure, PLAN B) — locate the LOCAL
// player's assembled weapon root via the same path as
// snapshot_player_weapon_meshes (player loaded3D → WEAPON bone → first
// named child). On success returns the assembled weapon's root NiNode
// / BSFadeNode (engine-built, all OMODs already applied). On failure
// returns nullptr (no player loaded, no WEAPON bone, no weapon equipped).
//
// Threading: MAIN THREAD ONLY (touches scene graph + reads via SEH).
void* find_player_assembled_weapon_root_pub();

} // namespace fw::native::weapon_witness
