// Strada B — native Creation Engine integration offsets.
//
// Target: Fallout4.exe 1.11.191 next-gen (image base 0x140000000, no ASLR
// in practice — still resolved at runtime via GetModuleHandleW).
//
// Source: re/stradaB_M1_dossier.txt (2026-04-22 full RE pass via IDA 9.3
// headless + hexrays, cross-referenced against CommonLibF4 type headers).
// See dossier section numbers in each block comment below.
//
// Philosophy: this header is INDEPENDENT of src/offsets.h. The Strada A
// pipeline had its own surface of offsets (VP matrices, DSVs, etc.)
// Strada B is a completely different integration path — we allocate
// engine objects, we attach to engine scene graph, we never touch D3D11
// directly. Keeping the offset surface separate makes the pivot cleaner
// and lets us delete one or the other without collateral.

#pragma once

#include <cstddef>
#include <cstdint>

namespace fw::native {

// ============================================================================
// 1. ALLOCATOR  (dossier §3 — HIGH confidence)
// ============================================================================
// All NiObject-derived allocations go through a single pool. This is THE
// allocator: 8763 callers across the binary. malloc() is NOT a substitute —
// refcount/pool invariants would break.
//
// Signature:
//   void* __fastcall(pool*, size_t size, u32 align, bool aligned_fallback)
//
// Canonical usage (from NiNode ctor variant sub_1416BDEF0):
//   if (dword_143E5F2D0 != 2)
//     sub_141657F90(&unk_143E5E0F0, &dword_143E5F2D0);
//   void* p = sub_1416579C0(&unk_143E5E0F0, 0x140u, 0x10u, 1);
//
// The allocator writes a diagnostic u32 to TEB+0x9C0 (TLS cookie slot 2496)
// for leak tracking. We can safely write to it from our thread as long as
// we save/restore around the call (different threads have different TEBs).

constexpr std::uintptr_t MEM_POOL_RVA          = 0x03E5E0F0; // unk_143E5E0F0
constexpr std::uintptr_t ALLOCATE_FN_RVA       = 0x016579C0; // sub_1416579C0
constexpr std::uintptr_t POOL_INIT_FN_RVA      = 0x01657F90; // sub_141657F90
constexpr std::uintptr_t POOL_INIT_FLAG_RVA    = 0x03E5F2D0; // dword_143E5F2D0
constexpr std::uint32_t  POOL_INIT_FLAG_READY  = 2;          // value when initialized

// ============================================================================
// 2. NINODE CTOR / VTABLE  (dossier §2, §4 — HIGH confidence)
// ============================================================================
// NiNode canonical allocation pattern:
//   void* v = Allocate(pool, 0x140, 0x10, 1);
//   sub_1416BDFE0(v, /*capacity=*/0);      // in-place ctor
//   // *(QWORD*)v == &NiNode::vftable after ctor returns
//
// CORRECTION vs memory: the previously recorded NiNode vtable 0x2564838
// was actually PlayerCharacter. Real NiNode vtable RVA is 0x267C888.

constexpr std::uintptr_t NINODE_VTABLE_RVA     = 0x0267C888;
constexpr std::uintptr_t NINODE_CTOR_RVA       = 0x016BDFE0; // sub_1416BDFE0
constexpr std::size_t    NINODE_SIZEOF         = 0x140;      // 320 bytes
constexpr std::size_t    NINODE_ALIGN          = 0x10;       // 16-byte

// NiAVObject (base of NiNode) — not allocated directly in M1, but member
// offsets are inherited and matter for setting the cube's position.
constexpr std::uintptr_t NIAVOBJECT_VTABLE_RVA = 0x0267D0C0;
constexpr std::uintptr_t NIAVOBJECT_CTOR_RVA  = 0x016C8CD0; // sub_1416C8CD0
constexpr std::size_t    NIAVOBJECT_SIZEOF    = 0x120;      // 288 bytes

// NiRefObject — root of the hierarchy. We never allocate one directly,
// but the refcount discipline applies to every object we create.
constexpr std::uintptr_t NIREFOBJECT_VTABLE_RVA = 0x02462F88;

// ============================================================================
// 3. SCENE ROOT  (dossier §1 — HIGH confidence)
// ============================================================================
// The renderer walks the scene graph starting from ShadowSceneNode (SSN),
// which is singleton-cached at qword_143E47A10. SSN is re-created on every
// worldspace unload (see writer sub_142179140), so we must:
//   - read the singleton pointer AT ATTACH TIME (not cached across cells)
//   - skip attach entirely if it's null (happens during loading screens)
//
// Alternative longer-lived anchor: qword_1432D2228 (World SceneGraph).
// Persists for the entire game session but its child[0] is SSN anyway,
// so attaching there just adds an extra indirection. For M1 we attach
// directly to SSN to minimize scope.

constexpr std::uintptr_t SSN_SINGLETON_RVA     = 0x03E47A10; // qword_143E47A10
constexpr std::uintptr_t WORLD_SG_SINGLETON_RVA = 0x032D2228; // qword_1432D2228 (SceneGraph)

// SceneGraph shortcut to ShadowSceneNode. Dossier M1 §1:
//   "*(QWORD*)(World + 320) = SSN"
// i.e. SceneGraph stores a direct pointer to the SSN at offset 0x140 as a
// fast path (bypassing the children array walk). Live-verified 2026-04-23:
// qword_143E47A10 was misidentified as SSN singleton — it actually points
// to NiCamera. The REAL SSN is reachable via this shortcut.
//
// CRITICAL for rendering: the Creation Engine renderer walks the scene
// starting FROM SSN. Attaching an object to World SceneGraph as a sibling
// of SSN (not a child of it) means the renderer never reaches it.
// Geometry must be a descendant of SSN to be drawn.
constexpr std::size_t SCENEGRAPH_SSN_SHORTCUT_OFF = 0x140;

// ============================================================================
// 4. ATTACH CHILD  (dossier §5 — HIGH confidence)
// ============================================================================
// NiNode::AttachChild is VTABLE SLOT 58 (byte offset 464 = 0x1D0).
// Canonical call (from renderer init sub_140C322C0):
//   (*(void(__fastcall**)(NiNode*, NiAVObject*, char))
//       (*(QWORD*)parent + 464LL))(parent, child, reuseFirstEmpty);
//
// reuseFirstEmpty=1 fills the first empty slot (used for LOD reuse).
// reuseFirstEmpty=0 always appends.
//
// AttachChild behavior (reference — we don't replicate, we call):
//   _InterlockedIncrement(child+8);               // ref++
//   SetParent(child, parent);                     // sub_1416C8B60
//   _InterlockedIncrement(child+8);               // ref++
//   PushToArray(parent+288, idx, &child);         // NiTObjectArray append
//   _InterlockedExchangeAdd(child+8, -1) x 2;     // undo both local refs
//   // Net: parent holds 1 ref.

constexpr std::size_t VT_SLOT_ATTACH_CHILD     = 58;      // byte offset 0x1D0
constexpr std::size_t VT_SLOT_ATTACH_CHILD_AT  = 59;      // byte offset 0x1D8
constexpr std::size_t VT_SLOT_DETACH_CHILD     = 60;      // byte offset 0x1E0

// Direct function RVAs (for sanity logging / fallback call paths):
constexpr std::uintptr_t NINODE_ATTACH_CHILD_FN_RVA    = 0x016BE170; // sub_1416BE170
constexpr std::uintptr_t NINODE_ATTACH_CHILD_AT_FN_RVA = 0x016BE2B0; // sub_1416BE2B0
constexpr std::uintptr_t NINODE_DETACH_CHILD_FN_RVA    = 0x016BE390; // sub_1416BE390

// ============================================================================
// 5. NIFIXEDSTRING API  (dossier §4 — HIGH confidence)
// ============================================================================
// Nodes are named via NiFixedString, the engine's deduped string type.
// Canonical pattern (from any SetName call site in binary):
//   uint64_t buf = 0;
//   sub_14167BDC0(&buf, "fw_debug_cube");    // alloc+intern
//   sub_1416BCD40(node, (void*)buf);         // node->SetName(fs)
//   sub_14167BEF0(&buf);                     // release temp ref

constexpr std::uintptr_t FIXEDSTR_CREATE_RVA   = 0x0167BDC0; // sub_14167BDC0
constexpr std::uintptr_t FIXEDSTR_RELEASE_RVA  = 0x0167BEF0; // sub_14167BEF0
constexpr std::uintptr_t NINODE_SETNAME_RVA    = 0x016BCD40; // sub_1416BCD40

// ============================================================================
// 6. NIAVOBJECT MEMBER LAYOUT  (dossier §6 — HIGH confidence)
// ============================================================================
// NiRefObject (base):
//   +0x00  vtable ptr
//   +0x08  refcount (u32, atomic — use _InterlockedIncrement / Decrement)
//
// NiObjectNET (inherits NiRefObject):
//   +0x10  m_name (NiFixedString, 8 bytes)
//   +0x18  m_extraData
//   +0x20  m_controllers
//
// NiAVObject (inherits NiObjectNET, sizeof 0x120):
//   +0x28  parent (NiNode*)
//   +0x30  m_kLocal     (NiTransform, 0x40 bytes: 3x3 rot + vec3 trans + scale)
//     +0x30..+0x54   rotation 3x3 (row-major, 9 floats)
//     +0x54..+0x60   translation (vec3, 12 bytes)  <-- we write this
//     +0x6C          scale (f32, init to 1.0)
//   +0x70  m_kWorld     (NiTransform, same layout)
//     +0xA0..+0xAC   world translation (confirmed via SSN reader)
//     +0xAC          world scale
//   +0x108 flags (u64 — 0x800 = movable, 0x1 = appCulled)

constexpr std::size_t NIAV_REFCOUNT_OFF        = 0x08;
constexpr std::size_t NIAV_NAME_OFF            = 0x10;
constexpr std::size_t NIAV_PARENT_OFF          = 0x28;
constexpr std::size_t NIAV_LOCAL_ROTATE_OFF    = 0x30;

// CORRECTED 2026-04-23: was 0x54, which is INSIDE the rotation matrix.
// NiMatrix3 is NOT 9 floats (0x24 bytes) as M1 dossier §6 claimed —
// it's 3 NiPoint4 rows (SIMD-padded to 16 bytes each = 48 bytes = 0x30
// total), per CommonLibF4's authoritative NiMatrix3 definition. So
// NiTransform layout is rotate@+0x00 (0x30B) + translate@+0x30 (0xCB) +
// scale@+0x3C (4B). local NiTransform starts at NiAVObject+0x30, so
// local.translate = +0x30+0x30 = +0x60, NOT +0x54.
//
// The old +0x54 was overlapping with rotation matrix cell r22 — this
// is why the walker showed pos=(0,1,0) for EVERY node (r22 = 1.0 on
// identity rotation). And why our injected cube never appeared at
// the intended position: we were corrupting the rotation matrix with
// huge worldspace coordinates while the real translate stayed at
// (0,0,0), placing the cube at the worldspace origin far from the
// player's view.
constexpr std::size_t NIAV_LOCAL_TRANSLATE_OFF = 0x60;  // vec3 of f32

constexpr std::size_t NIAV_LOCAL_SCALE_OFF     = 0x6C;
constexpr std::size_t NIAV_WORLD_ROTATE_OFF    = 0x70;
constexpr std::size_t NIAV_WORLD_TRANSLATE_OFF = 0xA0;
constexpr std::size_t NIAV_WORLD_SCALE_OFF     = 0xAC;
constexpr std::size_t NIAV_FLAGS_OFF           = 0x108;

// Flag bits (u64 at +0x108). CommonLibF4 names in comments:
//   bit 0x001 = kAppCulled          (hide from rendering)
//   bit 0x800 = kIsMovable          (allow runtime transform updates)
//   bit 0x2000 = kIsDynamic         (live-updated rather than baked)
// For M1 we set kIsMovable so the engine knows we'll mutate local.translate.
constexpr std::uint64_t NIAV_FLAG_APP_CULLED   = 0x0001ull;
constexpr std::uint64_t NIAV_FLAG_MOVABLE      = 0x0800ull;
constexpr std::uint64_t NIAV_FLAG_DYNAMIC      = 0x2000ull;

// NiNode-specific members (after NiAVObject's 0x120 — sizeof NiNode = 0x140):
//   +0x120  children array vtable (NiTObjectArray<NiPointer<NiAVObject>>)
//   +0x128  children ptr
//   +0x130  capacity (u16)
//   +0x132  count    (u16)
//   +0x134  grow_by / flags
//   +0x138  always 0 initially
constexpr std::size_t NINODE_CHILDREN_VT_OFF   = 0x120;
constexpr std::size_t NINODE_CHILDREN_PTR_OFF  = 0x128;
constexpr std::size_t NINODE_CHILDREN_CAP_OFF  = 0x130;
constexpr std::size_t NINODE_CHILDREN_CNT_OFF  = 0x132;

// ============================================================================
// 7. OPTIONAL / DEFERRED  (dossier §7-§9 — LOW/MEDIUM confidence, for M2+)
// ============================================================================
// Not used in M1 (empty NiNode), listed here so M2 can lift directly:

// BSGeometry / BSTriShape / BSDynamicTriShape — for the actual cube mesh:
constexpr std::uintptr_t BSGEOMETRY_VTABLE_RVA       = 0x0267E0B8;
constexpr std::uintptr_t BSGEOMETRY_CTOR_RVA         = 0x016D4BD0;
constexpr std::size_t    BSGEOMETRY_SIZEOF           = 0x170;

constexpr std::uintptr_t BSTRISHAPE_VTABLE_RVA       = 0x0267E948;
constexpr std::uintptr_t BSTRISHAPE_CTOR_RVA         = 0x016D99E0;
constexpr std::size_t    BSTRISHAPE_SIZEOF           = 0x170;

// NOTE 2026-04-23 live test: the ctor sub_1416E4090 wires vtable
// 0x0267F758, NOT 0x0267F948 as both M1 and M2 dossier sections
// originally claimed. The confusion stems from IDA mis-labeling a
// nearby vtable "NiDirectionalLight::vftable" — the M2 dossier
// assumed the mis-label was the wrong one, but actually 0x0267F948
// is a different class (probably BSSubIndexTriShape, multi-material
// variant). The walker also observed 0x0267F758 on real live leaves
// under SSN with BSGeometry-like layout (chld=0/0, pos=(0,1,0)).
//
// We use 0x0267F758 as the expected vtable. If future RE proves the
// true BSDynamicTriShape vtable is elsewhere, flip this constant.
constexpr std::uintptr_t BSDYNAMICTRISHAPE_VTABLE_RVA = 0x0267F758;
constexpr std::uintptr_t BSDYNAMICTRISHAPE_CTOR_RVA   = 0x016E4090;
constexpr std::size_t    BSDYNAMICTRISHAPE_SIZEOF     = 0x190;

// Keep the dossier-claimed RVA around for comparison / diagnostics.
// If live BSDynamicTriShape objects ever show up with this vtable,
// we know the other direction was the mis-label.
constexpr std::uintptr_t BSDYNAMICTRISHAPE_VTABLE_ALT_RVA = 0x0267F948;

// BSSubIndexTriShape — multi-segment tri shape used for character bodies
// (MaleBody.nif's BaseMaleBody:0 etc.). Inherits BSGeometry → BSTriShape →
// BSDynamicTriShape → BSSubIndexTriShape; sizeof = 0x190.
//
// Settled 2026-05-02 by 2 independent IDA agents (A+B HIGH×HIGH consensus):
// see re/M9w3_ssitf_vtable_AGENT_A.md / _B.md. Evidence chain:
//   1. RTTI TD `BSSubIndexTriShape` @ 0x14309D948 → unique COL @ 0x142AA0170
//      → vtable @ 0x142697D40 (RVA 0x2697D40). MSVC ClassHierarchyDescriptor
//      lists the canonical 7-class chain BSSubIndexTriShape → BSTriShape →
//      BSGeometry → NiAVObject → NiObjectNET → NiObject → NiRefObject.
//   2. NIF parser `sub_1417F0550` registers "BSSubIndexTriShape" string with
//      ctor `sub_1417E63A0`; the ctor at +0x82 writes 0x142697D40 as vptr.
//   3. Reverse search of `.rdata`: only ONE COL anywhere references the
//      BSSubIndexTriShape TD → the answer is unique.
// Used by skin_rebind locally too (kBSSubIndexTriShapeVtRva) — single source
// of truth here.
constexpr std::uintptr_t BSSUBINDEXTRISHAPE_VTABLE_RVA = 0x02697D40;

// ============================================================================
// 8. BSGeometry property offsets  (dossier M2 §1-§3 — HIGH confidence)
// ============================================================================
//
// Validated 2026-04-23 via IDA decomp of BSGeometry::ctor + BSGeometry::vt[42]
// + cross-ref of both BSLightingShaderProperty and NiAlphaProperty vtables
// into two real installer sites (sub_140372CC0, sub_1406B60C0). See
// re/stradaB_M2_shader_offset_dossier.txt §1-§3 for disasm.
//
// IMPORTANT: The M1 dossier §9 tentatively put shaderProperty @+0x130 and
// alphaProperty @+0x138. That was WRONG — they're swapped. Live walker dump
// confirmed the swap empirically (shared alpha across 4 TriShape = per-mesh,
// per-shape shader = per-material).
//
// Install conventions:
//   - alphaProperty: use BSGeometry::vt[42] which is a refcount-safe
//     setter (bumps new ref, direct-writes, releases old). This IS the
//     official SetAlphaProperty call.
//   - shaderProperty: no public setter; do the manual refcount dance
//     yourself (InterlockedIncrement on new, direct-write to +0x138,
//     release old if it was non-null). The installer sites in the binary
//     all do it inline — there's no hidden helper.

constexpr std::size_t BSGEOM_ALPHAPROP_OFF           = 0x130; // NiPointer<NiAlphaProperty>
constexpr std::size_t BSGEOM_SHADERPROP_OFF          = 0x138; // NiPointer<BSShaderProperty>

// === BSGeometry mesh-extract offsets (M9.w4 Path B / iter 11 dossier) ====
//
// Read-side layout for raw mesh extraction. Confirmed via direct decomp
// of sub_14182FFD0 (factory) → sub_1416DA0A0 (post-alloc populate) and
// the BSPositionData ctor sub_1416CE630 in re/M9_w4_iter11_ida.log.
//
// NOTE: M2 dossier called +0x160 "index count". That was a misnomer.
// Direct decomp shows it's TRI count (idx_count = 3 * tri_count).
constexpr std::size_t BSGEOM_SKIN_INSTANCE_OFF       = 0x140; // BSSkinInstance* (null = static)
constexpr std::size_t BSGEOM_POSITION_DATA_OFF       = 0x148; // BSPositionData*
constexpr std::size_t BSGEOM_VERTEX_DESC_OFF         = 0x150; // packed u64 BSVertexDesc
constexpr std::size_t BSGEOM_MAT_TYPE_OFF            = 0x158; // u8 (3 = BSTriShape)
constexpr std::size_t BSGEOM_TRI_COUNT_OFF           = 0x160; // u32  (NOT idx count!)
constexpr std::size_t BSGEOM_VERT_COUNT_OFF          = 0x164; // u16

// BSPositionData layout (sizeof 0x38, vtable @ qword_1434391D0)
//   NOTE: this struct is attached as ExtraData on a node, NOT at +0x148.
//   Iter 12 dossier proved +0x148 holds a different struct entirely.
//   Layout retained here for completeness — used by ExtraData walks.
//     [0          .. 6*vc)              packed half-prec positions
//     [6*vc       .. 12*vc)             packed half-prec normals/aux
//     [12*vc      .. 12*vc + 2*ic)      u16 INDICES (extraction target)
constexpr std::size_t BSPOSDATA_SIZEOF                = 0x38;
constexpr std::size_t BSPOSDATA_PACKED_BUFFER_OFF     = 0x18;
constexpr std::size_t BSPOSDATA_FULL_PREC_OFF         = 0x20;
constexpr std::size_t BSPOSDATA_PACKED_SIZE_OFF       = 0x28;
constexpr std::size_t BSPOSDATA_FULL_SIZE_OFF         = 0x2C;
constexpr std::size_t BSPOSDATA_FLAG_OFF              = 0x30;

// === REAL +0x148 layout — BSGeometryStreamHelper (M9.w4 iter 12 dossier) ==
//
// 32 bytes, allocated from BSSmallBlockAllocatorUtil::TLockingUserPool<32,
// BSGraphics::ResourceCacheAllocator, BSNonReentrantSpinLock>. Pool blocks
// are CONTIGUOUS in memory — reading past +0x1F lands in the NEXT block.
// (Iter 11 misread the +0x18..+0x30 region exactly because of this.)
//
// Layout:
//   +0x00  uint64_t  vertex_desc      (packed BSVertexDesc — same as clone+0x150)
//   +0x08  void*     vstream_desc     (~80 bytes; +0x08 inside = raw vertex bytes)
//   +0x10  void*     istream_desc     (~80 bytes; +0x08 inside = raw u16 indices)
//   +0x18  uint32_t  refcount         (1 source + N clones)
//   +0x1C..+0x1F     padding
constexpr std::size_t BSGEOSTREAMH_SIZEOF             = 0x20;
constexpr std::size_t BSGEOSTREAMH_VERTEX_DESC_OFF    = 0x00;
constexpr std::size_t BSGEOSTREAMH_VSTREAM_OFF        = 0x08;
constexpr std::size_t BSGEOSTREAMH_ISTREAM_OFF        = 0x10;
constexpr std::size_t BSGEOSTREAMH_REFCOUNT_OFF       = 0x18;

// BSStreamDesc layout (~80+ bytes, allocated by sub_14184EF10).
// One per buffer (vertex stream OR index stream). The actual raw buffer
// hangs off +0x08; the size at +0x30 is byte count rounded up to multiple
// of 4 (so for indices: (3 * tri_count * 2 + 3) & ~3).
constexpr std::size_t BSSTREAMDESC_RAW_BUF_OFF        = 0x08; // void* raw buffer
constexpr std::size_t BSSTREAMDESC_SIZE_OFF           = 0x30; // u32 size in bytes
constexpr std::size_t BSSTREAMDESC_TYPE_TAG_OFF       = 0x38; // u32 (2 = index buffer)
constexpr std::size_t BSSTREAMDESC_FILLED_FLAG_OFF    = 0x4E; // u8  (1 = data uploaded)

// Common subexpressions for extraction:
//   indices_byte_offset_in_packed_buffer = 12 * vc
//   indices_byte_size                    = 2 * idx_count  (= 6 * tri_count)
//   half_prec_positions_byte_size        = 6 * vc
//   full_prec_positions_byte_size        = 12 * vc

// BSGeometry::vt[42] = SetAlphaProperty (5-instruction refcount-safe setter).
// Writes to +0x130. Inherited unchanged by BSTriShape / BSDynamicTriShape.
constexpr std::size_t    BSGEOM_VT_SLOT_SET_ALPHA    = 42;    // offset 0x150 in vtable
constexpr std::uintptr_t BSGEOM_SET_ALPHA_FN_RVA     = 0x016D5930; // sub_1416D5930

// Other BSGeometry slots (from ctor decomp — semantics low confidence):
constexpr std::size_t BSGEOM_VERT_DESC_OFF           = 0x120; // u32 vertex-desc flags
constexpr std::size_t BSGEOM_SKIN_OWNER_OFF          = 0x128; // u64, skin/owner-related
constexpr std::size_t BSGEOM_UNK_12C_OFF             = 0x12C; // u32, init 0
constexpr std::size_t BSGEOM_UNK_140_OFF             = 0x140; // NiPointer<?>
constexpr std::size_t BSGEOM_UNK_148_OFF             = 0x148; // NiPointer<?>
constexpr std::size_t BSGEOM_UNK_150_OFF             = 0x150; // NiPointer<?>
constexpr std::size_t BSGEOM_MATERIAL_TYPE_OFF       = 0x158; // u16, set to 3 in BSTriShape

// ============================================================================
// 9. BSDynamicTriShape extra layout  (dossier M2 §4 — MED confidence)
// ============================================================================
//
// Beyond BSTriShape's 0x170, BSDynamicTriShape adds 0x20 bytes of state.
// The ctor sub_1416E4090 initializes 4 of those fields:
//   +0x170  qword = 0x3F800000 (low dword = 1.0f, high = 0)  [fade/anim]
//   +0x178  dword = 0                                         [vert count this frame?]
//   +0x17C  qword = 0                                         [DYNAMIC VERTEX BUFFER ptr]
//   +0x184  dword = 0                                         [flags]
//   +0x188..+0x190  trailing padding (uninitialized)
//
// +0x17C is the critical one for M2.4 — we'll populate it with a pointer
// to our cube's vertex data (8 verts, packed per BSVertexDesc at +0x150 of
// the inherited BSGeometry).

constexpr std::size_t BSDYNAMIC_FADE_SCALE_OFF       = 0x170; // low = 1.0f
constexpr std::size_t BSDYNAMIC_VERT_COUNT_OFF       = 0x178; // dword
constexpr std::size_t BSDYNAMIC_VERT_BUFFER_OFF      = 0x17C; // ptr to dyn vertex data
constexpr std::size_t BSDYNAMIC_FLAGS_OFF            = 0x184; // dword

// UpdateDownwardPass kick (for forcing a transform recompute after
// changing local.translate mid-frame). Not needed for M1 — engine's
// normal per-frame walk picks up the change on the next tick.
constexpr std::uintptr_t UPDATE_DOWNWARD_PASS_RVA    = 0x016C8050; // sub_1416C8050

// ============================================================================
// 12. NIF LOADER  (dossier stradaB_nif_loader_api.txt + hang-diagnosis 2026-04-23)
// ============================================================================
//
// Load a .nif from the BA2/filesystem and get back a BSFadeNode* with
// the whole scene-graph sub-tree ready to attach — mesh geometry,
// BSLightingShaderProperty, BSLightingShaderMaterial, BSShaderTextureSet
// all wired up by the engine's NIF parser. This bypasses the entire
// M3.3 BSLSP-by-hand saga.
//
// CORRECTION (2026-04-23 live-test hang): the dossier originally suggested
// sub_14026E1C0 "TESModel wrapper" as the preferred entry. THAT IS WRONG —
// that function takes:
//   a1 = ResourceManager + 256  (NOT ResourceManager directly)
//   a2 = BSResource::EntryDB::Entry*  (NOT a user-allocated NiNode holder)
// passing a NiNode holder puts its +12 padding into the cache state
// machine, which spin-locks forever via Sleep(0) / Sleep(1) inside
// sub_1416A6D00. Our first live attempt hung the main thread for 60s
// then got OS-watchdog-killed. DO NOT USE sub_14026E1C0.
//
// REAL PUBLIC API: sub_1417B3E90.
//
// V2 ATTEMPT FAILED TOO — the prior-agent-identified signature
// `(path, out, int64_t flags=0)` was WRONG in the third arg's
// SEMANTIC. arg3 is NOT a scalar flag qword — it is a POINTER to a
// 16-byte opts struct. Passing 0 (NULL) causes the inner loader
// (sub_1417B3480) to AV at `test byte ptr [r15+8], 20h` when it
// reads opts.flags. See re/_nif_entry_search.log for the decomp
// that caught this.
//
// V3 (correct) signature:
//   u32 __fastcall sub_1417B3E90(
//       const char*    path,    // rcx — ANSI, no "Meshes\\" prefix
//       NiAVObject**   out,     // rdx — BYREF; receives BSFadeNode*
//       NifLoadOpts*   opts);   // r8  — POINTER to 16-byte opts
//
// NifLoadOpts layout (16 bytes, stack-alloc, zero-init the slack):
//   +0x00  uint64_t ignored       (zero)
//   +0x04  uint32_t stream_key    (0 OK) [OVERLAPS +0x00 in decomp —
//                                 decomp splits the first qword into
//                                 qword@0 + dword@4; physical memory
//                                 is 8 bytes of zeros]
//   +0x08  uint8_t  flags         (BITFIELD — see below; SET 0x10)
//   +0x09..+0x0F  padding         (zero)
//
// Flag bits (inner loader sub_1417B3480 checks these):
//   0x02  acquire D3D renderer lock (ONLY on render thread — AV off-thread)
//   0x08  BSModelProcessor post-hook (material swaps; safe if post-proc null)
//   0x10  wrap result as BSFadeNode  (vs plain NiNode)  [SET THIS]
//   0x20  mark node as dynamic
// Vanilla uses values like 0x2D, 0x2E, 0x2C, 0x28, 0x2A. For our
// ghost-body use case, 0x10 is the minimum — gives us a fade-wrapped
// body ready to attach. We avoid 0x02 (requires render thread) and
// 0x08 (material swap hook; we want the raw NIF as-is).
//
// Returns: 0 on success, non-zero on failure.
// On success, *out is a BSFadeNode* with refcount already bumped.
//
// Threading: main thread only in practice (scene-graph attach rule);
// loader itself is synchronous (blocking) — ~2-10 ms for a body NIF.
constexpr std::uintptr_t NIF_LOAD_BY_PATH_RVA        = 0x0017B3E90; // sub_1417B3E90
constexpr std::uintptr_t NIF_LOAD_RESMGR_SLOT_RVA    = 0x030DD618;  // qword_1430DD618 (diagnostics)

// === LOWER-LEVEL WORKER (for choke-point hooking) ===
//
// sub_1417B3480 is the actual NIF-parse-and-build worker that ALL the
// public/wrapper APIs converge on (per re/stradaB_nif_loader_api.txt §1):
//
//   sub_1417B3E90 (public API, what `g_r.nif_load_by_path` calls)
//   sub_14026E1C0 (TESModel wrapper)        ─┐
//   sub_14033EC90 (batch loader 6-args)      ├─→ all funnel into → sub_1417B3480
//   sub_14033D1E0 (REFR::Load3D pipeline)    │
//   sub_140458740 (Actor::Load3D pipeline)  ─┘
//
// Hooking the public API ONLY misses every load that flows through the
// other wrappers — observed in M9.w4 logs as zero "Weapons\..." entries
// in the cache, since cell-load weapons go through Actor/REFR Load3D paths
// rather than the bare sub_1417B3E90 entry.
//
// Worker signature (5 args, from raw decomp lines 67-89 of nif_loader_api):
//   _DWORD* __fastcall sub_1417B3480(
//       __int64           streamCtx,   // rcx — BSResourceNiBinaryStream* (or null)
//       const char*       pathCstr,    // rdx — ANSI; null falls back to global
//       void*             opts,        // r8  — 16-byte NifLoadOpts (same as public)
//       NiAVObject**      outNode,     // r9  — BYREF, receives BSFadeNode*
//       __int64           userCtx);    // stack — passed to BSModelProcessor cb
//
// Return: a TLS scratch DWORD* (irrelevant to caller). Real output is
// *outNode (refcount already incremented). Caller treats the return as
// success-by-side-effect.
constexpr std::uintptr_t NIF_LOAD_WORKER_RVA         = 0x0017B3480; // sub_1417B3480

// === CACHE RESOLVER (last shot before Path B raw capture) ===
//
// sub_1416A6D00 ("ResolveFromCacheOrQueue") sits ABOVE the worker.
// EVERY NIF lookup goes through it — cache hit AND cache miss alike.
// If weapons are pre-loaded by the engine into the BSModelDB cache
// before our DLL injects, the worker hook never sees them on subsequent
// equip events; but the resolver does, on every cache HIT.
//
// Signature (from re/stradaB_nif_loader_api.txt §6, line 238):
//   v10 = sub_1416A6D00(modelDB, pathCstr, entry, &handle, flag);
//
// Argument order (Windows x64 fastcall):
//   rcx = modelDB                  (ResourceManager-derived ptr)
//   rdx = pathCstr                 (ANSI; THE path we want to log)
//   r8  = entry                    (BSResource::EntryDB::Entry* or similar)
//   r9  = &handle                  (BYREF intermediate state — used by
//                                   worker as streamCtx if cache miss)
//   stack = flag                   (char/byte)
//
// Return value semantics:
//   1 = cache hit  → caller extracts BSFadeNode from `handle` (offset TBD)
//   2 = cache miss → caller calls sub_1417B3480 with `handle`
//   0 = ambiguous / pending
//
// We HOOK this with logging-only behavior first to confirm weapon paths
// flow through it. If they do, a follow-up pass extracts the NiAVObject*
// from `handle` to populate the cache map for cache-hit lookups.
constexpr std::uintptr_t NIF_CACHE_RESOLVER_RVA      = 0x0016A6D00; // sub_1416A6D00

// Player singleton + loaded3D offset for M7.b bone-copy approach.
// See re/_player_copy_m7.log. Player's loaded3D is a direct BSFadeNode*
// pointer embedded in the Actor struct (inherited from TESObjectREFR).
// No loadedData indirection. Confirmed via PC vt[140] Get3D decomp
// which reads *(rbx+0xB78) directly.
constexpr std::uintptr_t PLAYER_SINGLETON_RVA      = 0x032D2260;  // qword_1432D2260
constexpr std::size_t    REFR_LOADED_3D_OFF        = 0x0B78;      // BSFadeNode*

// Opts flag bits.
constexpr std::uint8_t   NIF_OPT_D3D_LOCK        = 0x02;  // render-thread-only
constexpr std::uint8_t   NIF_OPT_POSTPROC        = 0x08;  // BSModelProcessor hook
constexpr std::uint8_t   NIF_OPT_FADE_WRAP       = 0x10;  // result is BSFadeNode
constexpr std::uint8_t   NIF_OPT_DYNAMIC         = 0x20;  // mark as dynamic

// ============================================================================
// 13. APPLY MATERIALS WALKER  —  THE pink-body fix
// ============================================================================
// Full dossier: re/stradaB_pink_body_solution.txt (tattoo it in fire).
//
// FO4 character bodies do NOT embed DDS paths in the NIF. They embed a
// single .bgsm (BGSMaterial) file reference. The NIF loader
// (sub_1417B3E90) stores that path at BSLSP+0x10 (BSFixedString) but
// DOES NOT resolve it. The material at BSLSP+0x58 is a valid
// BSLightingShaderMaterialBase (vt 0x290A190) but with its 4 tex slots
// pointing at the engine's shared default-fallback NiSourceTexture
// singletons ("<empty>" name). Rendering pink is the engine correctly
// showing "no real texture loaded".
//
// This walker (sub_140255BA0) is what vanilla Actor::Load3D calls
// AFTER sub_1417B3E90 to finalize the load:
//   For each BSTriShape/BSSIT in the subtree:
//     sub_140256070 (per-geometry apply)
//       ├─ Read .bgsm path from BSLSP+0x10
//       ├─ Strip "materials\\" prefix
//       ├─ sub_1417A9620(path, &mat, 0)    load .bgsm from BA2
//       ├─ for 10 tex slots:
//       │   sub_142162340 + sub_1417A4A30   resolve DDS + load handle
//       └─ sub_142169AD0(mat, geom, 1)      bind + flag update
// On return: same material object (vt still 0x290A190 — walker patches
// IN-PLACE, doesn't swap), but its 4 tex slots hold real NiSourceTexture
// handles and flags byte at +0x30 has been updated.
//
// SKIPPING THIS CALL = pink body. WITH THIS CALL = proper-textured body.
//
// Signature:
//   void __fastcall sub_140255BA0(void* root, __int64 a2=0,
//                                 __int64 a3=0, __int64 a4=0, __int64 a5=0);
// Main thread only (BSMaterialDB + scene graph locks). Synchronous
// ~5-30 ms for body-sized subtree.
//
// History: this cost us ~20 iterations of guessing (cube BSEffectShader,
// BSLSP by hand, killswitch, POSTPROC flag) before an RE agent traced
// Actor::Load3D and spotted the missing walker invocation.
constexpr std::uintptr_t APPLY_MATERIALS_WALKER_RVA = 0x00255BA0; // sub_140255BA0

// Additional RVAs for manual/targeted use (not needed for the main fix):
constexpr std::uintptr_t APPLY_MATERIALS_PERNODE_RVA = 0x00256070; // sub_140256070
constexpr std::uintptr_t BGSM_LOADER_RVA             = 0x017A9620; // sub_1417A9620
constexpr std::uintptr_t MAT_BIND_TO_GEOM_RVA        = 0x02169AD0; // sub_142169AD0
constexpr std::uintptr_t BSMATERIAL_DB_SLOT_RVA      = 0x030DC2A8; // qword_1430DC2A8

// LEGACY — do NOT use. Kept as constant for documentation / historical
// reference only. Calling this with ResourceManager + NiNode holder hangs.
constexpr std::uintptr_t NIF_LOAD_WRAPPER_LEGACY_RVA = 0x0026E1C0; // sub_14026E1C0
constexpr std::size_t    NIF_HOLDER_OUTPUT_OFF       = 0x20;       // was: where wrapper wrote output

// ============================================================================
// 10. GEO BUILDER factory  (dossier M2.4 §2/§4 — HIGH confidence)
// ============================================================================
// sub_14182FFD0 — the canonical "build a BSTriShape from raw vertex arrays"
// factory. 32 vanilla call sites across the binary. Replaces the manual
// alloc+ctor+populate+pack approach we used initially.
//
// Signature (16 meaningful args, Windows x64 fastcall):
//   BSTriShape* (int tri_count, u16* idx, u32 vcount, float* pos3,
//                float* uvs2, float* tan4, float* pos_alt, float* nrm3,
//                float* col4f, float* sk_w, u32* sk_i, float* tan_ex,
//                u32* eye, float* nrm_alt, u16* remap, char extra_helper)
//
// Returns fully-initialized BSTriShape (sizeof 0x170):
//   +0x000 vtable (BSTriShape)
//   +0x008 refcount = 0
//   +0x120 BSBound (AABB auto-computed from positions)
//   +0x130 null  (alphaProperty — caller installs)
//   +0x138 null  (shaderProperty — caller installs)
//   +0x140 null  (skinInstance — leave null for static)
//   +0x148 BSPositionData* (fresh allocation owned by this TriShape)
//   +0x150 packed BSVertexDesc (built by sub_14182DFC0)
//   +0x158 material type = 3
//   +0x160 index_count (u32)
//   +0x164 vert_count  (u16)
constexpr std::uintptr_t GEO_BUILDER_FN_RVA = 0x0182FFD0;

// ============================================================================
// 11. Own shader + alpha allocation  (dossier M2 geometry §4.C — HIGH conf)
// ============================================================================
//
// Instead of cloning shader/alpha from a vanilla BSTriShape (which caused
// a ~59s-post-inject crash via orphan internal owner pointers), we follow
// the FogOfWarOverlay vanilla pattern (sub_140372CC0 lines 575-595):
//
//   // BSEffectShaderProperty fresh alloc:
//   v47 = sub_1416579C0(pool, 0x88, 0, 0);          // alloc 0x88 bytes
//   v49 = sub_14216F9C0(v47);                       // BSEffectShader ctor
//   sub_142161B10(v49, *(QWORD*)(v49+88), 1);       // setup (arg2 = self+88 slot)
//   *(QWORD*)(v49[11] + 72) = qword_1434391A0;      // texture handle
//   *(DWORD*)(v49[11] + 80) = dword_1434391A8;      // int
//   (*v49->vtable[42])(v49, geom);                  // install into geom
//
//   // NiAlphaProperty fresh alloc:
//   v51 = sub_1416579C0(pool, 0x30, 0, 0);
//   sub_1416BD6F0(v51);                             // init
//   *(QWORD*)v51 = &NiAlphaProperty::vftable;
//   v51[20] = 236;   *((BYTE*)v51 + 42) = 0;   v51[20] |= 1;
//   (*geom->vtable[42])(geom, v51);                 // SetAlphaProperty

constexpr std::uintptr_t BSEFFECT_SHADER_CTOR_RVA   = 0x0216F9C0; // sub_14216F9C0
constexpr std::uintptr_t BSEFFECT_SHADER_SETUP_RVA  = 0x02161B10; // sub_142161B10
constexpr std::uintptr_t BSEFFECT_SHADER_TEX_HANDLE_RVA = 0x034391A0; // qword_1434391A0
constexpr std::uintptr_t BSEFFECT_SHADER_TEX_INT_RVA    = 0x034391A8; // dword_1434391A8
constexpr std::size_t    BSEFFECT_SHADER_SIZEOF     = 0x88;

constexpr std::uintptr_t NIALPHAPROP_INIT_RVA       = 0x016BD6F0; // sub_1416BD6F0
constexpr std::size_t    NIALPHAPROP_SIZEOF         = 0x30;

// BSEffectShader vt[42] = "AttachGeometry" — installs shader into geom.
// Same slot index as BSGeometry's SetAlphaProperty (vt[42]).
constexpr std::size_t VT_SLOT_42 = 42;

// ============================================================================
// 12. BSLightingShaderProperty + texture loading  (texture API dossier)
// ============================================================================
// Produced by the texture API dossier (2026-04-23). The BSEffectShaderProperty
// path we had been using was writing a COLOR TINT slot (qword_1434391A0 =
// RGB 0,0,0 default) — not a texture handle, which is why our cube was
// flat white. The correct path for "runtime BSTriShape with a DDS from BA2"
// is:
//
//   1. Alloc BSLightingShaderProperty via sub_142171050 (0xE8 bytes).
//   2. Alloc BSShaderTextureSet via sub_14216ED10 (0x60 bytes, 10 path slots).
//   3. SetTexturePath(slot=0, "Actors\\Character\\...\\body_d.DDS") via sub_1421627B0.
//   4. Bind via sub_1421C6870(material, shader+520, textureSet) — this iterates
//      the 10 paths and calls the load API (sub_14217A910) per slot, wiring
//      the resulting NiSourceTexture* handles into the material's tex slots.
//   5. Install the BSLSP into cube's +0x138 (refcount bump + direct write).

constexpr std::uintptr_t BSLSP_NEW_RVA              = 0x02171050; // sub_142171050 (alloc + ctor wrapper)
constexpr std::uintptr_t BSLSP_CTOR_RVA             = 0x02171620; // sub_142171620 (in-place ctor, NOT used directly)
constexpr std::size_t    BSLSP_SIZEOF               = 0xE8;

constexpr std::uintptr_t BSSHADERTEXSET_CTOR_RVA    = 0x0216ED10; // sub_14216ED10
constexpr std::uintptr_t BSSHADERTEXSET_SETPATH_RVA = 0x021627B0; // sub_1421627B0 (slot, ANSI path)
constexpr std::size_t    BSSHADERTEXSET_SIZEOF      = 0x60;

// Binds material → texture set, resolving all 10 paths to NiSourceTexture*.
// Args: (material, stream_ctx_ignored, textureSet).
constexpr std::uintptr_t BSLSP_BIND_MATERIAL_TEXSET_RVA = 0x021C6870; // sub_1421C6870

// KILLSWITCH byte — gates the 10-slot texture-resolution loop inside
// sub_1421C6870 (the bind fn). Xref scan shows ZERO writers in the binary,
// meaning it's BSS-default 0 at runtime → bind takes the "light" ELSE
// branch that NEVER resolves paths → material keeps pointing at the
// ctor-default error/normal globals → our custom textures never install.
//
// FIX: write 1 to this byte before calling bind, restore after.
// (Dossier: re/stradaB_bslsp_activation_systematic.txt §1 + §6 fix #2.)
constexpr std::uintptr_t BSLSP_BIND_KILLSWITCH_BYTE_RVA = 0x03E488C0; // byte_143E488C0

// Offset inside BSLightingShaderProperty.
constexpr std::size_t BSLSP_MATERIAL_OFF     = 0x58;   // 88, i.e. shader[11]
constexpr std::size_t BSLSP_BIND_ARG2_OFF    = 0x208;  // 520 — unused by bind, kept for doc

// BSLSP+0x64 is a "drawable/alpha" float field read by vt[43] SetupGeometry
// (sub_142172540). The ctor allocates 0xE8 WITHOUT zero-fill and NEVER
// writes +0x64 — field contains whatever memory leftover. If 0.0, the
// render path early-rejects our cube.
// FIX: set +0x64 = 1.0f after ctor returns.
// (Dossier §5 + §6 fix #1c.)
constexpr std::size_t BSLSP_DRAWABLE_FLOAT_OFF = 0x64;

// BSLightingShaderMaterialBase — fresh allocation path (fix #1a).
// sub_142171620 (BSLSP ctor) installs qword_143E488C8 (the SHARED DEFAULT
// material singleton) at shader+0x58 via the hash-cache sub_1421F9F00.
// When we call sub_1421C6870 with the default material we're mutating the
// shared singleton — other vanilla BSLSP instances using that material
// get cross-contaminated, and our cube's draw may be rejected by per-
// instance state that lives on the shared object.
//
// Fix: after BSLSP ctor, allocate our OWN material via sub_1421C5CE0
// (raw material base ctor), swap into shader+0x58 refcount-safely. Then
// our bind only mutates OUR material.
//
// NOTE: sizeof is INFERRED (0xC0) from ctor decomp "last write at +0xB8".
// OPEN-4 in the dossier — may need runtime probe if fresh-alloc crashes.
//
// 2026-04-23 live results:
//   - 0xC0 + no zero-fill → cube invisible, no crash (render early-reject)
//   - 0x200 + zero-fill  → CRASH first frame (render goes further,
//                           derefs a field that zero-fill broke).
// Reverted to 0xC0 / no zero-fill for stability. Plan C (Triton/angr
// agents in background) will return the exact field requirements so we
// can set specific values instead of relying on heap luck.
constexpr std::uintptr_t BSLIGHTINGMAT_CTOR_RVA      = 0x021C5CE0; // sub_1421C5CE0
constexpr std::size_t    BSLIGHTINGMAT_SIZEOF        = 0xC0;

// Body textures — all three are in the BA2 archives. The engine's texture
// load API prefixes "textures\\" internally, so we pass relative paths.
// BSLightingShader material expects at least slots 0/1/2 populated to
// render properly: leaving slot 1 (normal) or 2 (specular) null causes
// the lighting calc to skip the draw.
//   slot 0 = diffuse / albedo (_d)
//   slot 1 = normal map (_n)
//   slot 2 = specular / smoothness (_s)
//   slots 3..9 = environment, subsurface, etc. (ok if empty for body)
constexpr const char* DEFAULT_CUBE_DIFFUSE_PATH =
    "Actors\\Character\\BaseHumanMale\\BaseMaleBody_d.DDS";
constexpr const char* DEFAULT_CUBE_NORMAL_PATH =
    "Actors\\Character\\BaseHumanMale\\BaseMaleBody_n.DDS";
constexpr const char* DEFAULT_CUBE_SPECULAR_PATH =
    "Actors\\Character\\BaseHumanMale\\BaseMaleBody_s.DDS";

} // namespace fw::native
