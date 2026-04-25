// fwn_loader — proprietary FWN binary reader for fw_native runtime.
//
// Reads .fwn files produced by the separate GPL-3.0-licensed
// PIEassetDecompiler tool. The file format is defined in fwn_format.h
// (shared spec, not code derived from nifly — clean copy of self-authored
// data-format header).
//
// Legal boundary: this file has ZERO code from nifly or any GPL-licensed
// source. It only reads a binary format we defined ourselves. Per FSF
// clarification on "output of a GPL program is not GPL", the .fwn files
// on disk are DATA, and parsing them is no different from parsing PNG
// or JSON.
//
// Thread safety: load_fwn is a blocking file I/O call. Call it during
// DLL init or from a background thread — NOT from the render thread.
// The returned MeshAsset is plain POD + std::vector, safe to move to
// other threads, safe to read concurrently from multiple threads.

#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace fw::assets {

// Runtime vertex representation. Mirrors fwn::Vertex byte-for-byte so we
// can read the VB chunk directly into a std::vector<Vertex>.
struct MeshVertex {
    float         position[3];
    float         normal[3];
    float         uv[2];
    std::uint32_t bone_idx[4];
    float         bone_weights[4];
};
static_assert(sizeof(MeshVertex) == 64, "MeshVertex must match fwn::Vertex 64B");

struct MeshBone {
    std::string   name;                     // decoded from 64-byte padded field
    std::uint32_t parent_index;              // 0xFFFFFFFF = root (hierarchy from skeleton.fws later)
    float         inverse_bind_matrix[16];   // 4x4 row-major
};

struct MeshSubmesh {
    std::string   material_name;
    std::uint32_t index_start;
    std::uint32_t index_count;
};

struct MeshAsset {
    // Flags from fwn::MeshHeader (bit0 skinned, bit1 has_normals, bit2 has_uvs,
    // bit3 index_u32).
    std::uint32_t flags = 0;

    std::vector<MeshVertex>    vertices;
    std::vector<std::uint16_t> indices_u16;   // non-empty if flags & INDEX_U32 == 0
    std::vector<std::uint32_t> indices_u32;   // non-empty if flags & INDEX_U32 != 0
    std::vector<MeshBone>      bones;
    std::vector<MeshSubmesh>   submeshes;

    bool is_skinned()   const { return (flags & 0x1) != 0; }
    bool has_normals()  const { return (flags & 0x2) != 0; }
    bool has_uvs()      const { return (flags & 0x4) != 0; }
    bool uses_u32_indices() const { return (flags & 0x8) != 0; }

    // Total index count (whichever buffer is populated).
    std::size_t index_count() const {
        return uses_u32_indices() ? indices_u32.size() : indices_u16.size();
    }
};

// Load a .fwn file from disk. Returns std::nullopt on any I/O error,
// bad magic, unsupported version, or chunk size inconsistency. All
// errors logged via FW_ERR/FW_WRN/FW_DBG with context (file path).
std::optional<MeshAsset> load_fwn(const std::filesystem::path& path);

} // namespace fw::assets
