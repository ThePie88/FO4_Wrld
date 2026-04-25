#include "fwn_loader.h"
#include "fwn_format.h"

#include "../log.h"

#include <cstring>
#include <filesystem>
#include <fstream>
#include <vector>

namespace fs = std::filesystem;

namespace fw::assets {

namespace {

// Read raw bytes into a buffer. Returns false on partial read / error.
bool read_exact(std::ifstream& f, void* dst, std::size_t n) {
    f.read(reinterpret_cast<char*>(dst), static_cast<std::streamsize>(n));
    return static_cast<std::size_t>(f.gcount()) == n;
}

// Pretty-print a 4-char tag for logs. Tags are little-endian u32 so we
// need to unpack bytes in order.
std::string tag_name(std::uint32_t tag) {
    char buf[5];
    buf[0] = static_cast<char>((tag >> 0)  & 0xFF);
    buf[1] = static_cast<char>((tag >> 8)  & 0xFF);
    buf[2] = static_cast<char>((tag >> 16) & 0xFF);
    buf[3] = static_cast<char>((tag >> 24) & 0xFF);
    buf[4] = '\0';
    // Sanitize non-printable
    for (int i = 0; i < 4; ++i) {
        if (buf[i] < 32 || buf[i] > 126) buf[i] = '?';
    }
    return std::string(buf);
}

// Read a zero-padded fixed-size ASCII name from a raw buffer.
// strnlen-equivalent; we avoid std::strnlen since MSVC only exposes the
// POSIX symbol via <string.h> at global scope, not std:: via <cstring>.
std::string read_padded_name(const char* raw, std::size_t cap) {
    std::size_t n = 0;
    while (n < cap && raw[n] != '\0') ++n;
    return std::string(raw, n);
}

} // namespace

std::optional<MeshAsset> load_fwn(const fs::path& path) {
    const std::string path_s = path.string();

    if (!fs::exists(path)) {
        FW_ERR("[fwn] file does not exist: %s", path_s.c_str());
        return std::nullopt;
    }

    const std::uintmax_t file_size = fs::file_size(path);
    FW_DBG("[fwn] opening '%s' (%llu B)",
           path_s.c_str(), static_cast<unsigned long long>(file_size));

    std::ifstream f(path, std::ios::binary);
    if (!f) {
        FW_ERR("[fwn] cannot open '%s' for reading", path_s.c_str());
        return std::nullopt;
    }

    // --- File header ---
    fwn::FileHeader hdr{};
    if (!read_exact(f, &hdr, sizeof(hdr))) {
        FW_ERR("[fwn] '%s': truncated file header", path_s.c_str());
        return std::nullopt;
    }
    if (hdr.magic != fwn::MAGIC) {
        FW_ERR("[fwn] '%s': bad magic 0x%08X (expected 'FWNM')",
               path_s.c_str(), hdr.magic);
        return std::nullopt;
    }
    if (hdr.version_major != fwn::VERSION_MAJOR) {
        FW_ERR("[fwn] '%s': unsupported major version %u.%u (loader supports %u.x)",
               path_s.c_str(), hdr.version_major, hdr.version_minor,
               fwn::VERSION_MAJOR);
        return std::nullopt;
    }
    if (hdr.total_size != file_size) {
        FW_WRN("[fwn] '%s': header total_size=%llu mismatches disk size=%llu "
               "— file may be truncated or mid-write",
               path_s.c_str(),
               static_cast<unsigned long long>(hdr.total_size),
               static_cast<unsigned long long>(file_size));
        // Non-fatal: we still attempt to parse. The chunk iteration
        // will fail cleanly if data is actually missing.
    }

    MeshAsset out;
    bool seen_head = false;
    bool seen_vert = false;
    std::uint32_t expected_vertex_count = 0;
    std::uint32_t expected_index_count  = 0;
    std::uint32_t expected_bone_count   = 0;
    std::uint32_t expected_submesh_count = 0;

    // --- Chunk iteration ---
    std::size_t chunks_read = 0;
    while (f.peek() != EOF) {
        fwn::ChunkHeader ch{};
        if (!read_exact(f, &ch, sizeof(ch))) {
            FW_ERR("[fwn] '%s': truncated at chunk header #%zu",
                   path_s.c_str(), chunks_read);
            return std::nullopt;
        }

        FW_DBG("[fwn]   chunk '%s' size=%llu",
               tag_name(ch.tag).c_str(),
               static_cast<unsigned long long>(ch.size));

        // Reasonable upper bound: 256 MB per chunk. Above this is likely
        // corrupted data, not a legitimate asset.
        if (ch.size > (256ull * 1024 * 1024)) {
            FW_ERR("[fwn] '%s': chunk '%s' size=%llu is absurd — aborting",
                   path_s.c_str(), tag_name(ch.tag).c_str(),
                   static_cast<unsigned long long>(ch.size));
            return std::nullopt;
        }

        switch (ch.tag) {
        case fwn::TAG_HEAD: {
            if (ch.size < sizeof(fwn::MeshHeader)) {
                FW_ERR("[fwn] HEAD chunk too small (%llu < %zu)",
                       static_cast<unsigned long long>(ch.size),
                       sizeof(fwn::MeshHeader));
                return std::nullopt;
            }
            fwn::MeshHeader mh{};
            if (!read_exact(f, &mh, sizeof(mh))) {
                FW_ERR("[fwn] HEAD chunk truncated");
                return std::nullopt;
            }
            // Skip any extra padding in this chunk (forward-compat).
            const std::size_t rem = ch.size - sizeof(mh);
            if (rem > 0) f.seekg(static_cast<std::streamoff>(rem), std::ios::cur);

            out.flags              = mh.flags;
            expected_vertex_count  = mh.vertex_count;
            expected_index_count   = mh.index_count;
            expected_bone_count    = mh.bone_count;
            expected_submesh_count = mh.submesh_count;
            seen_head = true;
            FW_DBG("[fwn]   HEAD: verts=%u idx=%u bones=%u subm=%u flags=0x%X",
                   mh.vertex_count, mh.index_count, mh.bone_count,
                   mh.submesh_count, mh.flags);
            break;
        }

        case fwn::TAG_VERT: {
            if (!seen_head) {
                FW_ERR("[fwn] VERT chunk before HEAD — bad ordering");
                return std::nullopt;
            }
            const std::uint64_t expected_bytes =
                static_cast<std::uint64_t>(expected_vertex_count) * sizeof(MeshVertex);
            if (ch.size != expected_bytes) {
                FW_ERR("[fwn] VERT size mismatch: got %llu, expected %llu "
                       "(%u verts * 64 B)",
                       static_cast<unsigned long long>(ch.size),
                       static_cast<unsigned long long>(expected_bytes),
                       expected_vertex_count);
                return std::nullopt;
            }
            out.vertices.resize(expected_vertex_count);
            if (!read_exact(f, out.vertices.data(), expected_bytes)) {
                FW_ERR("[fwn] VERT read truncated");
                return std::nullopt;
            }
            seen_vert = true;
            break;
        }

        case fwn::TAG_INDX: {
            if (!seen_head) {
                FW_ERR("[fwn] INDX chunk before HEAD");
                return std::nullopt;
            }
            const bool u32 = out.uses_u32_indices();
            const std::uint64_t expected_bytes =
                static_cast<std::uint64_t>(expected_index_count) * (u32 ? 4u : 2u);
            if (ch.size != expected_bytes) {
                FW_ERR("[fwn] INDX size mismatch: got %llu, expected %llu "
                       "(%u indices * %u B)",
                       static_cast<unsigned long long>(ch.size),
                       static_cast<unsigned long long>(expected_bytes),
                       expected_index_count, u32 ? 4u : 2u);
                return std::nullopt;
            }
            if (u32) {
                out.indices_u32.resize(expected_index_count);
                if (!read_exact(f, out.indices_u32.data(), expected_bytes)) {
                    FW_ERR("[fwn] INDX (u32) read truncated");
                    return std::nullopt;
                }
            } else {
                out.indices_u16.resize(expected_index_count);
                if (!read_exact(f, out.indices_u16.data(), expected_bytes)) {
                    FW_ERR("[fwn] INDX (u16) read truncated");
                    return std::nullopt;
                }
            }
            break;
        }

        case fwn::TAG_BONE: {
            if (!seen_head) {
                FW_ERR("[fwn] BONE chunk before HEAD");
                return std::nullopt;
            }
            const std::uint64_t expected_bytes =
                static_cast<std::uint64_t>(expected_bone_count) * sizeof(fwn::BoneEntry);
            if (ch.size != expected_bytes) {
                FW_ERR("[fwn] BONE size mismatch: got %llu, expected %llu",
                       static_cast<unsigned long long>(ch.size),
                       static_cast<unsigned long long>(expected_bytes));
                return std::nullopt;
            }
            std::vector<fwn::BoneEntry> raw(expected_bone_count);
            if (!read_exact(f, raw.data(), expected_bytes)) {
                FW_ERR("[fwn] BONE read truncated");
                return std::nullopt;
            }
            out.bones.reserve(expected_bone_count);
            for (const auto& r : raw) {
                MeshBone b;
                b.name = read_padded_name(r.name, fwn::BONE_NAME_MAX);
                b.parent_index = r.parent_index;
                std::memcpy(b.inverse_bind_matrix, r.inverse_bind_matrix,
                            sizeof(b.inverse_bind_matrix));
                out.bones.push_back(std::move(b));
            }
            break;
        }

        case fwn::TAG_SUBM: {
            if (!seen_head) {
                FW_ERR("[fwn] SUBM chunk before HEAD");
                return std::nullopt;
            }
            const std::uint64_t expected_bytes =
                static_cast<std::uint64_t>(expected_submesh_count)
                * sizeof(fwn::SubmeshEntry);
            if (ch.size != expected_bytes) {
                FW_ERR("[fwn] SUBM size mismatch: got %llu, expected %llu",
                       static_cast<unsigned long long>(ch.size),
                       static_cast<unsigned long long>(expected_bytes));
                return std::nullopt;
            }
            std::vector<fwn::SubmeshEntry> raw(expected_submesh_count);
            if (!read_exact(f, raw.data(), expected_bytes)) {
                FW_ERR("[fwn] SUBM read truncated");
                return std::nullopt;
            }
            out.submeshes.reserve(expected_submesh_count);
            for (const auto& r : raw) {
                MeshSubmesh sm;
                sm.material_name = read_padded_name(r.material_name,
                                                     fwn::MATERIAL_NAME_MAX);
                sm.index_start = r.index_start;
                sm.index_count = r.index_count;
                out.submeshes.push_back(std::move(sm));
            }
            break;
        }

        default: {
            // Unknown tag — log + skip forward by ch.size bytes. This is the
            // chunk-based format's forward-compatibility promise.
            FW_DBG("[fwn] unknown chunk '%s' size=%llu — skipping (forward compat)",
                   tag_name(ch.tag).c_str(),
                   static_cast<unsigned long long>(ch.size));
            f.seekg(static_cast<std::streamoff>(ch.size), std::ios::cur);
            break;
        }
        }
        ++chunks_read;
    }

    // --- post-parse validation ---
    if (!seen_head) {
        FW_ERR("[fwn] '%s': file has no HEAD chunk", path_s.c_str());
        return std::nullopt;
    }
    if (!seen_vert) {
        FW_ERR("[fwn] '%s': file has no VERT chunk", path_s.c_str());
        return std::nullopt;
    }
    if (out.vertices.size() != expected_vertex_count) {
        FW_ERR("[fwn] '%s': vertex count drift (have %zu, expected %u)",
               path_s.c_str(), out.vertices.size(), expected_vertex_count);
        return std::nullopt;
    }
    if (out.index_count() != expected_index_count) {
        FW_ERR("[fwn] '%s': index count drift (have %zu, expected %u)",
               path_s.c_str(), out.index_count(), expected_index_count);
        return std::nullopt;
    }
    if (out.bones.size() != expected_bone_count) {
        FW_ERR("[fwn] '%s': bone count drift (have %zu, expected %u)",
               path_s.c_str(), out.bones.size(), expected_bone_count);
        return std::nullopt;
    }
    if (out.submeshes.size() != expected_submesh_count) {
        FW_ERR("[fwn] '%s': submesh count drift (have %zu, expected %u)",
               path_s.c_str(), out.submeshes.size(), expected_submesh_count);
        return std::nullopt;
    }

    FW_LOG("[fwn] loaded '%s': verts=%zu idx=%zu bones=%zu subm=%zu flags=0x%X",
           path_s.c_str(),
           out.vertices.size(), out.index_count(),
           out.bones.size(), out.submeshes.size(), out.flags);
    return out;
}

} // namespace fw::assets
