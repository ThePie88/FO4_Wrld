// M9.w4 PROPER (v0.4.2+) — sender-side weapon-mesh capture pipeline.
// See header for design rationale + flow.
//
// PHASE 2 (2026-05-04): full extraction + wire ship.
// During each armed window, every clone factory invocation routes through
// `record_clone()`. We extract the source BSTriShape's mesh data on the
// spot (vert_count, tri_count, positions, indices, m_name, bgsm_path,
// local_transform) via the existing weapon_witness::extract_mesh_for_capture
// helper, then stage the ExtractedMesh. On TTL we package as MESH_BLOB_OP
// and ship via fw::net::client (existing v9 protocol from v0.4.0 PoC).
//
// FILTER: only clones with delta_ms <= BURST1_CUTOFF_MS are kept. TTD
// 2026-05-04 showed every modded weapon equip produces a tight burst
// (16-32ms post-arm, ~28 clones for 6-mod pistol) followed by an
// unrelated second burst (~412ms post-arm, 1P animation prep).
// 100ms cutoff cleanly captures burst 1, drops burst 2.

#include "weapon_capture.h"

#include <windows.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

#include "../log.h"
#include "../main_thread_dispatch.h"
#include "../net/client.h"
#include "spai_prewarm.h"
#include "weapon_witness.h"
#include "scene_inject.h"  // serialize_and_ship_player_weapon (PLAN B)

namespace fw::native::weapon_capture {

namespace {

// Drop clones that arrive after this many ms post-arm. Burst 1 fully
// inside 32ms in TTD trace; 100ms gives 3x headroom for heavily-modded
// weapons. Burst 2 starts at +412ms; this cutoff drops it cleanly.
constexpr std::uint64_t BURST1_CUTOFF_MS = 100;

// One captured mesh from the equip's 3rd-person assembly.
struct StagedMesh {
    weapon_witness::ExtractedMesh mesh;   // owned data
    std::uint64_t                 delta_ms;
    const void*                   source;  // diagnostic
    const void*                   clone;   // diagnostic
};

// Pending capture window state.
struct PendingCapture {
    std::uint32_t form_id     = 0;
    std::uint64_t arm_ms      = 0;
    std::uint64_t deadline_ms = 0;
    std::vector<StagedMesh> staged;
    // Counters for skipped clones (visibility into filter behaviour).
    std::uint32_t dropped_late      = 0;  // delta_ms > cutoff
    std::uint32_t dropped_extract   = 0;  // extract_mesh failed (NiNode etc.)
    // Path NIF-CAPTURE: weapon-related paths the engine loaded during the
    // window. Deduped. Receiver replays these via nif_load_by_path.
    std::vector<std::string> loaded_paths;
};

std::mutex          g_mtx;
PendingCapture      g_pending;
std::atomic<bool>   g_armed{false};

std::atomic<std::uint64_t> g_total_arms{0};
std::atomic<std::uint64_t> g_total_records{0};
std::atomic<std::uint64_t> g_total_finalizes{0};
std::atomic<std::uint64_t> g_total_meshes_shipped{0};

std::uint64_t now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(
        steady_clock::now().time_since_epoch()).count();
}

void timer_worker(std::uint32_t ttl_ms) {
    Sleep(ttl_ms);
    HWND hwnd = fw::dispatch::get_target_hwnd();
    if (!hwnd) {
        FW_WRN("[weapon-capture] timer: no FO4 hwnd, dropping finalize");
        return;
    }
    PostMessageW(hwnd,
                 static_cast<UINT>(FW_MSG_WEAPON_CAPTURE_FINALIZE),
                 0, 0);
}

// Identity 4x4 transform for path-only meshes (engine will use it; whole
// matrix at NIF root will override anyway when nif_load_by_path runs).
static const float kIdentityXform[16] = {
    1.0f, 0.0f, 0.0f, 0.0f,
    0.0f, 1.0f, 0.0f, 0.0f,
    0.0f, 0.0f, 1.0f, 0.0f,
    0.0f, 0.0f, 0.0f, 1.0f,
};

// Path NIF-CAPTURE: build wire records that carry NIF paths instead of
// raw geometry. Each captured path becomes one MeshBlobMesh with
// `m_name = path`, `vert_count=0` (sentinel: receiver detects this
// and treats as path-only). All other geom fields nulled.
//
// Caller must hold g_mtx.
std::vector<fw::net::MeshBlobMesh>
build_path_wire_records_locked() {
    std::vector<fw::net::MeshBlobMesh> wire;
    wire.reserve(g_pending.loaded_paths.size());
    for (const auto& p : g_pending.loaded_paths) {
        fw::net::MeshBlobMesh w{};
        w.m_name             = p.c_str();      // SENTINEL: path lives here
        w.parent_placeholder = "";
        w.slot_name          = "";
        w.bgsm_path          = "";
        w.vert_count         = 0;              // SENTINEL: vert_count=0 → path-only
        w.tri_count          = 0;
        w.local_transform    = kIdentityXform;
        w.positions          = nullptr;
        w.indices            = nullptr;
        wire.push_back(w);
    }
    return wire;
}

// Legacy raw-geom wire records (Phase 1+2 ship format). Restored as
// fallback when path capture fails (the engine's weapon NIF loader
// bypasses the hooks per nif_path_cache.cpp:314-321 documented dead-
// end). Receiver's dispatch derives bgsm-derived path from the meshes'
// bgsm_path fields → loads BASE weapon NIF → at least base visible.
//
// Caller must hold g_mtx.
std::vector<fw::net::MeshBlobMesh>
build_geom_wire_records_locked() {
    std::vector<fw::net::MeshBlobMesh> wire;
    wire.reserve(g_pending.staged.size());
    for (const auto& s : g_pending.staged) {
        const auto& m = s.mesh;
        fw::net::MeshBlobMesh w{};
        w.m_name             = m.m_name.c_str();
        w.parent_placeholder = m.parent_placeholder.c_str();
        w.slot_name          = m.slot_name.c_str();
        w.bgsm_path          = m.bgsm_path.c_str();
        w.vert_count         = m.vert_count;
        w.tri_count          = m.tri_count;
        w.local_transform    = m.local_transform;
        w.positions          = m.positions.empty()
                                  ? nullptr : m.positions.data();
        w.indices            = m.indices.empty()
                                  ? nullptr : m.indices.data();
        wire.push_back(w);
    }
    return wire;
}

// Internal: do the finalize work. Caller holds g_mtx.
void finalize_locked() {
    if (!g_armed.load(std::memory_order_acquire)) {
        return;
    }

    g_total_finalizes.fetch_add(1, std::memory_order_relaxed);

    // 2026-05-06 — re-read slot_name from each staged mesh's CLONE
    // pointer. record_clone() captures slot_name from the SOURCE
    // BSGeometry's grandparent at clone time — but at clone time the
    // source is a top-level cached resmgr entry with NO scene-graph
    // parent yet, so grandparent is null and slot_name comes out
    // empty for almost every mod (live test 2026-05-06: 5/6 mods had
    // empty slot_name, only the in-base placeholder receiver had a
    // non-empty value). At finalize time the engine's mod assembly
    // is complete and the CLONE is now attached inside the assembled
    // tree — its grandparent is the base weapon's loaded root NiNode,
    // which has the placeholder name we want to ship to the receiver.
    // 2026-05-06 LATE evening (ATTEMPT #7 v2) — only correct slot_name.
    // parent_placeholder stays as the immediate parent of the leaf (the
    // resmgr cache lookup key on the receiver). Walk UP from clone to
    // first BSFadeNode (= mod NIF root) and use its PARENT's m_name as
    // slot_name (= base placeholder where engine attached the mod).
    {
        std::size_t fixed_slot = 0;
        std::size_t no_modroot = 0;
        for (auto& s : g_pending.staged) {
            if (!s.clone) continue;
            void* mod_root = weapon_witness::find_mod_nif_root_pub(
                const_cast<void*>(s.clone), 8);
            if (!mod_root) {
                ++no_modroot;
                continue;
            }
            void* base_placeholder = weapon_witness::read_parent_pub(
                mod_root);
            if (!base_placeholder) continue;
            char buf[128] = {};
            if (!weapon_witness::read_node_name_pub(
                    base_placeholder, buf, sizeof(buf)) || !buf[0]) {
                continue;
            }
            if (s.mesh.slot_name != buf) {
                s.mesh.slot_name.assign(buf);
                ++fixed_slot;
            }
        }
        FW_LOG("[weapon-capture] slot_name post-pass: fixed_slot=%zu "
               "no_modroot=%zu (out of %zu staged)",
               fixed_slot, no_modroot, g_pending.staged.size());
    }

    const std::size_t n_kept    = g_pending.staged.size();
    const std::uint32_t n_late  = g_pending.dropped_late;
    const std::uint32_t n_xfail = g_pending.dropped_extract;
    const std::size_t n_paths   = g_pending.loaded_paths.size();
    const std::uint64_t window_ms = now_ms() - g_pending.arm_ms;

    FW_LOG("[weapon-capture] FINALIZE form=0x%X kept=%zu paths=%zu "
           "dropped_late=%u dropped_extract=%u window=%llums",
           g_pending.form_id, n_kept, n_paths, n_late, n_xfail,
           static_cast<unsigned long long>(window_ms));

    // Per-mesh diagnostic (truncated for log volume).
    constexpr std::size_t MAX_LOG = 16;
    for (std::size_t i = 0; i < n_kept && i < MAX_LOG; ++i) {
        const auto& s = g_pending.staged[i];
        FW_LOG("[weapon-capture]   [%zu] m_name='%s' vc=%u tc=%u "
               "parent='%s' bgsm='%s' t+%llums",
               i, s.mesh.m_name.c_str(),
               static_cast<unsigned>(s.mesh.vert_count),
               s.mesh.tri_count,
               s.mesh.parent_placeholder.c_str(),
               s.mesh.bgsm_path.c_str(),
               static_cast<unsigned long long>(s.delta_ms));
    }
    if (n_kept > MAX_LOG) {
        FW_LOG("[weapon-capture]   ... (%zu more meshes, truncated)",
               n_kept - MAX_LOG);
    }

    // Path NIF-CAPTURE (Path NIF-PATHS, 2026-05-04 PM): ship the LOADED
    // PATHS instead of raw geometry. Receiver replays via nif_load_by_path
    // — engine handles shader / material / vertex format binding naturally.
    // No factory, no donor shader, no vd format mismatch.
    //
    // Per-path log first so the operator can SEE what we're shipping.
    constexpr std::size_t MAX_LOG_PATHS = 24;
    for (std::size_t i = 0; i < n_paths && i < MAX_LOG_PATHS; ++i) {
        FW_LOG("[weapon-capture]   path[%zu]='%s'", i,
               g_pending.loaded_paths[i].c_str());
    }
    if (n_paths > MAX_LOG_PATHS) {
        FW_LOG("[weapon-capture]   ... (%zu more paths, truncated)",
               n_paths - MAX_LOG_PATHS);
    }

    // 2026-05-06 LATE evening (M9 closure, PLAN B) — engine-native
    // serialization. After 30+ failed attempts to reconstruct the
    // assembled weapon on the receiver from primitive parts (per-leaf
    // mesh data, mod-NIF cache lookups, placeholder resolution
    // heuristics, world-relative transform composition), pivot to:
    // the engine ALREADY assembled the weapon correctly — let it
    // serialize what it has, ship the bytes, let the engine on the
    // other side load them back. Zero math, zero placeholder logic,
    // zero shader binding manual. Recipe verified by
    // re/nistream_memory_serialize_AGENT.md.
    //
    // 2026-05-07 — DISABLED. The new ghost weapon path uses name-match
    // assembly (scene_inject.cpp::ghost_attach_assembled_weapon) which
    // works PURELY from the OMOD form_id list shipped inside EQUIP_OP.
    // The mesh-blob / NIF-blob / path-only payloads here generated MASSIVE
    // reliable traffic (a 6-mod 10mm pistol = 50+ chunks each ≤1372 B,
    // many KB total). That swamped the P2P channel and caused
    // MAX_RETRANSMITS dead at 06:27 in the live test. Disable entirely.
    //
    // The capture pipeline itself (clone-factory tracker, deferred TTL)
    // remains running for diagnostics — only the SHIP step is disabled.
    constexpr bool SHIP_LEGACY_BLOBS = false;

    if (SHIP_LEGACY_BLOBS) {
        const std::size_t nif_chunks =
            fw::native::serialize_and_ship_player_weapon(g_pending.form_id);
        if (nif_chunks > 0) {
            FW_LOG("[weapon-capture] SHIP form=0x%X NIF-blob chunks=%zu",
                   g_pending.form_id, nif_chunks);
        }

        if (n_paths > 0) {
            auto wire = build_path_wire_records_locked();
            const std::size_t n_chunks =
                fw::net::client().enqueue_mesh_blob_for_equip(
                    g_pending.form_id, wire.data(), wire.size());
            g_total_meshes_shipped.fetch_add(n_paths,
                                              std::memory_order_relaxed);
            FW_LOG("[weapon-capture] SHIP form=0x%X paths=%zu chunks=%zu",
                   g_pending.form_id, n_paths, n_chunks);
        } else if (n_kept > 0) {
            auto wire = build_geom_wire_records_locked();
            const std::size_t n_chunks =
                fw::net::client().enqueue_mesh_blob_for_equip(
                    g_pending.form_id, wire.data(), wire.size());
            g_total_meshes_shipped.fetch_add(n_kept,
                                              std::memory_order_relaxed);
            FW_LOG("[weapon-capture] SHIP form=0x%X meshes=%zu chunks=%zu",
                   g_pending.form_id, n_kept, n_chunks);
        }
    } else {
        FW_DBG("[weapon-capture] SHIP DISABLED form=0x%X (n_paths=%zu "
               "n_kept=%zu) — name-match path uses OMOD form_ids only",
               g_pending.form_id, n_paths, n_kept);
    }

    g_pending = {};
    g_armed.store(false, std::memory_order_release);
}

} // namespace

// ---- Public API ----------------------------------------------------------

void arm(std::uint32_t form_id, std::uint32_t ttl_ms) {
    std::lock_guard lk(g_mtx);
    g_total_arms.fetch_add(1, std::memory_order_relaxed);

    if (g_armed.load(std::memory_order_acquire)) {
        FW_DBG("[weapon-capture] arm: superseding active window "
               "(prev form=0x%X kept=%zu) with new form=0x%X",
               g_pending.form_id, g_pending.staged.size(), form_id);
        finalize_locked();
    }

    const std::uint64_t t0 = now_ms();
    g_pending.form_id          = form_id;
    g_pending.arm_ms           = t0;
    g_pending.deadline_ms      = t0 + ttl_ms;
    g_pending.staged.clear();
    g_pending.staged.reserve(32);
    g_pending.dropped_late     = 0;
    g_pending.dropped_extract  = 0;

    g_armed.store(true, std::memory_order_release);

    FW_LOG("[weapon-capture] ARM form=0x%X ttl=%ums (window now open, "
           "burst1_cutoff=%llums)",
           form_id, ttl_ms,
           static_cast<unsigned long long>(BURST1_CUTOFF_MS));

    std::thread(&timer_worker, ttl_ms).detach();
}

void record_clone(const void* source, const void* clone) {
    // Hot-path fast-out before mutex.
    if (!g_armed.load(std::memory_order_acquire)) {
        return;
    }

    std::lock_guard lk(g_mtx);
    if (!g_armed.load(std::memory_order_acquire)) return;

    g_total_records.fetch_add(1, std::memory_order_relaxed);

    const std::uint64_t t = now_ms();
    const std::uint64_t delta_ms =
        (t > g_pending.arm_ms) ? (t - g_pending.arm_ms) : 0;

    // Filter: drop late clones (likely 1P assembly burst 2 from TTD).
    if (delta_ms > BURST1_CUTOFF_MS) {
        ++g_pending.dropped_late;
        FW_DBG("[weapon-capture] drop late clone t+%llums (cutoff=%llums)",
               static_cast<unsigned long long>(delta_ms),
               static_cast<unsigned long long>(BURST1_CUTOFF_MS));
        return;
    }

    // Try to extract mesh data from source (the template BSTriShape).
    // For non-BSGeometry clones (NiNode etc.) extract returns false and
    // we silently skip — those don't carry vertex/index data anyway.
    weapon_witness::ExtractedMesh em{};
    const bool ok = weapon_witness::extract_mesh_for_capture(
        const_cast<void*>(source), em);
    if (!ok) {
        ++g_pending.dropped_extract;
        FW_DBG("[weapon-capture] extract failed src=%p (probably "
               "non-BSGeometry clone)", source);
        return;
    }

    // Stage. ExtractedMesh has heap-owned vectors; std::move keeps zero copies.
    StagedMesh sm{};
    sm.mesh     = std::move(em);
    sm.delta_ms = delta_ms;
    sm.source   = source;
    sm.clone    = clone;
    g_pending.staged.push_back(std::move(sm));

    FW_DBG("[weapon-capture] kept m_name='%s' vc=%u tc=%u t+%llums "
           "(form=0x%X)",
           g_pending.staged.back().mesh.m_name.c_str(),
           static_cast<unsigned>(g_pending.staged.back().mesh.vert_count),
           g_pending.staged.back().mesh.tri_count,
           static_cast<unsigned long long>(delta_ms),
           g_pending.form_id);
}

bool is_armed() {
    return g_armed.load(std::memory_order_acquire);
}

// Path NIF-CAPTURE — record an engine-loaded path during the armed window.
// Called from nif_path_cache's worker AND resolver detours.
//
// Filter to weapon-related paths only (case-insensitive substring match):
//   - "Weapons\\..."  (most paths)
//   - "weapons\\..."  (lowercase)
//
// Drop everything else (body, head, hands, anim graphs, effects, etc.) —
// those are reloaded organically when the receiver attaches the ghost
// body, no need to capture.
void record_loaded_path(const char* path) {
    if (!g_armed.load(std::memory_order_acquire)) return;
    // 2026-05-05 — ignore loads driven by SPAI Tier 1 prewarm worker.
    // The prewarm fires nif_load_by_path on its own cadence (~12 ms per
    // weapon NIF in the offline catalog) which would otherwise flood the
    // per-equip path-capture window with hundreds of unrelated paths
    // (HMAR, Combat Rifle, pipe weapons, etc.) and ship them on the
    // wire as if they were the actual equipped weapon's mods. The
    // first symptom was the "10mm pistol that looks like an HMAR"
    // bug user reported.
    if (fw::native::spai::in_prewarm_load()) return;
    if (!path || !path[0]) return;

    // Cheap case-insensitive substring scan for "Weapons\\".
    auto contains_ci = [](const char* hay, const char* needle) -> bool {
        for (const char* p = hay; *p; ++p) {
            const char* h = p; const char* n = needle;
            while (*h && *n) {
                char ch = *h; char cn = *n;
                if (ch >= 'A' && ch <= 'Z') ch = (char)(ch - 'A' + 'a');
                if (cn >= 'A' && cn <= 'Z') cn = (char)(cn - 'A' + 'a');
                if (ch != cn) break;
                ++h; ++n;
            }
            if (!*n) return true;
        }
        return false;
    };
    if (!contains_ci(path, "weapons\\")) return;

    std::lock_guard lk(g_mtx);
    if (!g_armed.load(std::memory_order_acquire)) return;

    // Dedup (engine often loads same path multiple times in one equip).
    for (const auto& existing : g_pending.loaded_paths) {
        if (existing == path) return;
    }
    g_pending.loaded_paths.emplace_back(path);

    FW_DBG("[weapon-capture] path '%s' (form=0x%X total=%zu)",
           path, g_pending.form_id, g_pending.loaded_paths.size());
}

void finalize_and_ship() {
    std::lock_guard lk(g_mtx);
    finalize_locked();
}

void on_finalize_message() {
    finalize_and_ship();
}

std::uint64_t total_arms()             { return g_total_arms.load(std::memory_order_relaxed); }
std::uint64_t total_records()          { return g_total_records.load(std::memory_order_relaxed); }
std::uint64_t total_finalizes()        { return g_total_finalizes.load(std::memory_order_relaxed); }

} // namespace fw::native::weapon_capture
