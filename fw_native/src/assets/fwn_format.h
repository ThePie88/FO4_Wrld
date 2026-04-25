// FWN format spec — shared between PIEassetDecompiler (writer) and
// fw_native/src/assets/fwn_loader.{h,cpp} (reader, proprietary).
//
// Format: FWNM = Fallout World Node Mesh
// Version: v1.0 (2026-04-21)
// Endianness: little-endian (x64 Windows hardcoded; no BE support planned)
//
// Design notes:
// - IFF-style chunk format: extensible. New chunks can be added in later
//   phases (tangents, morph targets, physics hulls) without breaking the
//   existing loader. Unknown chunks are skipped via size field.
// - AoS interleaved vertex format. 64 bytes per vertex, cache-aligned.
//   Supports up to 4-bone skinning per vertex.
// - Tight bone storage (132 B/bone). Loader expands to 64B aligned
//   matrices when uploading to D3D11 constant buffer.
// - No compression at v1. If file sizes become a concern in later phases,
//   add a 'COMP' chunk wrapper for selective gzip/lz4 of individual chunks.
//
// SHARING NOTE: this header is **copied** into fw_native (not linked) so
// the proprietary runtime doesn't transitively pull any GPL code from
// this GPL-licensed tool. The format spec is data-format, not a derivative
// work of the parser.

#pragma once

#include <cstdint>

namespace fwn {

// ASCII 4-char tag packed as little-endian u32.
// Writes match source order: 'F','W','N','M' → 0x4D4E5746
constexpr std::uint32_t make_tag(char a, char b, char c, char d) {
    return static_cast<std::uint32_t>(a)
         | (static_cast<std::uint32_t>(b) << 8)
         | (static_cast<std::uint32_t>(c) << 16)
         | (static_cast<std::uint32_t>(d) << 24);
}

// --- File header (16 bytes) ---
constexpr std::uint32_t MAGIC = make_tag('F','W','N','M');

constexpr std::uint16_t VERSION_MAJOR = 1;
constexpr std::uint16_t VERSION_MINOR = 0;

struct FileHeader {
    std::uint32_t magic;        // FWNM
    std::uint16_t version_major;
    std::uint16_t version_minor;
    std::uint64_t total_size;   // whole file size in bytes, sanity check
};
static_assert(sizeof(FileHeader) == 16, "FileHeader must be 16B");

// --- Chunk header (16 bytes, followed by `size` bytes of data) ---
struct ChunkHeader {
    std::uint32_t tag;
    std::uint32_t _pad;  // keep size field 8-byte aligned
    std::uint64_t size;  // data bytes following this header
};
static_assert(sizeof(ChunkHeader) == 16, "ChunkHeader must be 16B");

// --- Tags for v1 chunks ---
constexpr std::uint32_t TAG_HEAD = make_tag('H','E','A','D');  // MeshHeader
constexpr std::uint32_t TAG_VERT = make_tag('V','E','R','T');  // VertexBuffer
constexpr std::uint32_t TAG_INDX = make_tag('I','N','D','X');  // IndexBuffer
constexpr std::uint32_t TAG_BONE = make_tag('B','O','N','E');  // BoneTable
constexpr std::uint32_t TAG_SUBM = make_tag('S','U','B','M');  // SubmeshTable
constexpr std::uint32_t TAG_MATR = make_tag('M','A','T','R');  // MaterialRefs

// Future tags (reserved, not emitted in v1):
constexpr std::uint32_t TAG_TANG = make_tag('T','A','N','G');  // Tangents (β.4)
constexpr std::uint32_t TAG_MRPH = make_tag('M','R','P','H');  // Morph targets
constexpr std::uint32_t TAG_PHYS = make_tag('P','H','Y','S');  // Physics hulls

// --- HEAD chunk data (32 bytes) ---
struct MeshHeader {
    std::uint32_t vertex_count;
    std::uint32_t index_count;
    std::uint32_t bone_count;
    std::uint32_t submesh_count;
    std::uint32_t flags;         // bit0 = skinned, bit1 = has_normals (always 1 v1),
                                 // bit2 = has_uvs (always 1 v1), bit3 = index_u32
    std::uint32_t _reserved[3];
};
static_assert(sizeof(MeshHeader) == 32, "MeshHeader must be 32B");

constexpr std::uint32_t MESH_FLAG_SKINNED      = 1u << 0;
constexpr std::uint32_t MESH_FLAG_HAS_NORMALS  = 1u << 1;
constexpr std::uint32_t MESH_FLAG_HAS_UVS      = 1u << 2;
constexpr std::uint32_t MESH_FLAG_INDEX_U32    = 1u << 3;  // else u16

// --- Vertex format (AoS, 64 bytes) ---
// Inside TAG_VERT chunk: [Vertex * vertex_count]
struct Vertex {
    float    position[3];      // local space, FO4 units (1 unit ≈ 1.4cm)
    float    normal[3];        // local space, unit-length
    float    uv[2];            // [0,1]
    std::uint32_t bone_idx[4]; // indices into bone table; 0xFFFFFFFF = unused
    float    bone_weights[4];  // sum = 1.0; if unused, weight = 0.0
};
static_assert(sizeof(Vertex) == 64, "Vertex must be 64B for cache alignment");

// --- Bone entry (tight, 132 bytes) ---
// Inside TAG_BONE chunk: [BoneEntry * bone_count]
constexpr std::size_t BONE_NAME_MAX = 64;

struct BoneEntry {
    char          name[BONE_NAME_MAX];  // zero-padded ASCII
    std::uint32_t parent_index;         // 0xFFFFFFFF for root
    float         inverse_bind_matrix[16];  // 4x4 row-major
};
static_assert(sizeof(BoneEntry) == 132, "BoneEntry must be 132B");

constexpr std::uint32_t BONE_PARENT_NONE = 0xFFFFFFFFu;

// --- Submesh entry (72 bytes) ---
// Inside TAG_SUBM chunk: [SubmeshEntry * submesh_count]
constexpr std::size_t MATERIAL_NAME_MAX = 64;

struct SubmeshEntry {
    char          material_name[MATERIAL_NAME_MAX];
    std::uint32_t index_start;   // offset in the index buffer
    std::uint32_t index_count;   // number of indices (tris * 3)
};
static_assert(sizeof(SubmeshEntry) == 72, "SubmeshEntry must be 72B");

} // namespace fwn
