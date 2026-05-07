#include "main_thread_dispatch.h"

#include <atomic>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "engine/engine_calls.h"
#include "hooks/container_hook.h"   // ApplyingRemoteGuard + tls_applying_remote
#include "log.h"
#include "native/scene_inject.h"    // M9 wedge 2: ghost armor attach/detach

namespace fw::dispatch {

namespace {

std::mutex g_mtx;
std::deque<PendingContainerOp> g_queue;

// B6.1: door queue — separate mutex so doors don't contend with container
// ops. Doors are toggle-only and high-frequency (one per E press).
std::mutex g_door_mtx;
std::deque<PendingDoorOp> g_door_queue;

// M9 wedge 2: equip queue — for armor visual sync.
//   Per-event: net thread enqueues + posts FW_MSG_EQUIP_APPLY.
//   Drained on main thread by WndProc dispatcher.
std::mutex g_equip_mtx;
std::deque<PendingEquipOp> g_equip_queue;

// M9 wedge 4 v9: mesh blob queue — for raw weapon-mesh visual sync.
//   Net thread reassembles chunks → decodes blob → enqueues + posts.
//   Drained on main thread; rebuilds each mesh on the matching ghost
//   weapon root via factory call (Step 4c).
std::mutex g_mesh_blob_mtx;
std::deque<PendingMeshBlob> g_mesh_blob_queue;

// The FO4 main window handle. Set exactly once by main_menu_hook after
// it subclasses WndProc (post-B3.b-registrar detection). Read lock-free
// thereafter; atomic for publish/acquire ordering.
std::atomic<HWND> g_hwnd{nullptr};

// Post the wake-up message. Swallows failures (HWND missing at boot is
// expected; the queue will flush on next post after set_target_hwnd).
void post_wakeup_container() noexcept {
    HWND h = g_hwnd.load(std::memory_order_acquire);
    if (!h) return;
    if (!PostMessageW(h, FW_MSG_CONTAINER_APPLY, 0, 0)) {
        FW_DBG("dispatch: PostMessage(FW_MSG_CONTAINER_APPLY) failed (err=%lu)",
               GetLastError());
    }
}

void post_wakeup_door() noexcept {
    HWND h = g_hwnd.load(std::memory_order_acquire);
    if (!h) return;
    if (!PostMessageW(h, FW_MSG_DOOR_APPLY, 0, 0)) {
        FW_DBG("dispatch: PostMessage(FW_MSG_DOOR_APPLY) failed (err=%lu)",
               GetLastError());
    }
}

void post_wakeup_equip() noexcept {
    HWND h = g_hwnd.load(std::memory_order_acquire);
    if (!h) return;
    if (!PostMessageW(h, FW_MSG_EQUIP_APPLY, 0, 0)) {
        FW_DBG("dispatch: PostMessage(FW_MSG_EQUIP_APPLY) failed (err=%lu)",
               GetLastError());
    }
}

void post_wakeup_mesh_blob() noexcept {
    HWND h = g_hwnd.load(std::memory_order_acquire);
    if (!h) return;
    if (!PostMessageW(h, FW_MSG_MESH_BLOB_APPLY, 0, 0)) {
        FW_DBG("dispatch: PostMessage(FW_MSG_MESH_BLOB_APPLY) failed (err=%lu)",
               GetLastError());
    }
}

} // namespace

void enqueue_container_apply(const PendingContainerOp& op) {
    std::size_t qsize;
    {
        std::lock_guard lk(g_mtx);
        g_queue.push_back(op);
        qsize = g_queue.size();
    }
    FW_DBG("dispatch: enqueued kind=%u cfid=0x%X item=0x%X count=%d (qsize=%zu)",
           op.kind, op.container_form_id, op.item_base_id, op.count, qsize);
    post_wakeup_container();
}

void enqueue_door_apply(const PendingDoorOp& op) {
    std::size_t qsize;
    {
        std::lock_guard lk(g_door_mtx);
        g_door_queue.push_back(op);
        qsize = g_door_queue.size();
    }
    FW_DBG("dispatch: door enqueued form=0x%X base=0x%X cell=0x%X (qsize=%zu)",
           op.door_form_id, op.door_base_id, op.door_cell_id, qsize);
    post_wakeup_door();
}

void enqueue_equip_apply(const PendingEquipOp& op) {
    std::size_t qsize;
    {
        std::lock_guard lk(g_equip_mtx);
        g_equip_queue.push_back(op);
        qsize = g_equip_queue.size();
    }
    FW_DBG("dispatch: equip enqueued peer=%s form=0x%X kind=%u (qsize=%zu)",
           op.peer_id, op.item_form_id, op.kind, qsize);
    post_wakeup_equip();
}

void enqueue_mesh_blob_apply(PendingMeshBlob op) {
    std::size_t qsize;
    const std::size_t mesh_count = op.meshes.size();
    const std::uint32_t form_id = op.item_form_id;
    const std::uint32_t equip_seq = op.equip_seq;
    char peer_buf[16] = {};
    std::memcpy(peer_buf, op.peer_id, sizeof(peer_buf));
    {
        std::lock_guard lk(g_mesh_blob_mtx);
        g_mesh_blob_queue.push_back(std::move(op));
        qsize = g_mesh_blob_queue.size();
    }
    FW_LOG("dispatch: mesh-blob enqueued peer=%s form=0x%X equip_seq=%u "
           "meshes=%zu (qsize=%zu)",
           peer_buf, form_id, equip_seq, mesh_count, qsize);
    post_wakeup_mesh_blob();
}

void drain_mesh_blob_apply_queue() {
    std::deque<PendingMeshBlob> local;
    {
        std::lock_guard lk(g_mesh_blob_mtx);
        local.swap(g_mesh_blob_queue);
    }
    if (local.empty()) {
        FW_DBG("dispatch: mesh-blob drain with empty queue — no-op");
        return;
    }

    // M9 wedge 4 v9 step 4c (PIVOT 2026-05-01 21:50 — Opzione A pragmatic):
    //   Factory + donor pattern crashed (vd format mismatch with donor
    //   shader). Pivot: skip factory entirely. Use the wire blob ONLY to
    //   derive the proper base weapon NIF path from the first mesh's
    //   bgsm path, then call the existing ghost_attach_weapon path which
    //   loads the NIF + apply_materials + attach_child_direct (proven-
    //   working for manganello / armor sync).
    //
    //   Cost: only base weapon visible (no mod-specific meshes). For PoC
    //   acceptable. Mod-mesh visibility deferred to v0.5+ (full BSVertex-
    //   Desc RE work).
    //
    //   Replacement: detach prior weapon for same peer/form first, so
    //   the legacy EQUIP_BCAST attach (which loaded "RecieverDummy.nif"
    //   from the wrong TESModel slot) is replaced by our proper NIF.
    std::size_t applied_blobs = 0;
    int total_attached = 0;
    for (auto& blob : local) {
        // 2026-05-06 LATE evening (M9 closure, PLAN B) — NIF blob
        // shortcut. If sender shipped a serialized assembled-weapon
        // tree, deserialize it via NiStream::Load and attach the root
        // to ghost's WEAPON bone. Skip all per-mesh / per-path logic.
        if (!blob.nif_blob_bytes.empty()) {
            FW_LOG("[mesh-rx] APPLY (NIF-blob) peer=%s form=0x%X "
                   "equip_seq=%u nif_bytes=%zu",
                   blob.peer_id, blob.item_form_id, blob.equip_seq,
                   blob.nif_blob_bytes.size());

            // Cleanup previous equip's deserialized roots first.
            fw::native::clear_ghost_extra_mods(blob.peer_id);

            const bool ok = fw::native::deserialize_and_attach_nif_blob(
                blob.peer_id, blob.item_form_id,
                blob.nif_blob_bytes.data(),
                blob.nif_blob_bytes.size());
            if (ok) {
                ++applied_blobs;
                FW_LOG("[mesh-rx] NIF-blob attached OK peer=%s form=0x%X",
                       blob.peer_id, blob.item_form_id);
            } else {
                FW_WRN("[mesh-rx] NIF-blob attach FAILED peer=%s form=0x%X "
                       "size=%zu — ghost weapon may be empty until next "
                       "equip", blob.peer_id, blob.item_form_id,
                       blob.nif_blob_bytes.size());
            }
            continue;  // done with this blob, skip per-mesh path
        }

        FW_LOG("[mesh-rx] APPLY peer=%s form=0x%X equip_seq=%u meshes=%zu",
               blob.peer_id, blob.item_form_id, blob.equip_seq,
               blob.meshes.size());

        // M9.w4 PROPER (v0.4.2+, Path NIF-CAPTURE, 2026-05-04 PM) —
        // detect "path-only" blob (sentinel: any mesh with vert_count=0
        // AND non-empty m_name treated as path). The sender shipped the
        // engine's actually-loaded NIF paths instead of raw geometry.
        // We replay them: first path = base weapon, rest = mod NIFs
        // attached to base. Engine handles shader/material/vd binding.
        const bool is_path_only = !blob.meshes.empty()
            && blob.meshes[0].vert_count == 0
            && !blob.meshes[0].m_name.empty();
        if (is_path_only) {
            FW_LOG("[mesh-rx] PATH-ONLY blob peer=%s form=0x%X paths=%zu",
                   blob.peer_id, blob.item_form_id, blob.meshes.size());
            for (std::size_t pi = 0; pi < blob.meshes.size(); ++pi) {
                FW_DBG("[mesh-rx]   path[%zu]='%s'", pi,
                       blob.meshes[pi].m_name.c_str());
            }

            // First path → base weapon via ghost_set_weapon (handles slot
            // tracking + replacement). Use it as a single candidate.
            const std::string& base_path = blob.meshes[0].m_name;
            const char* base_candidates[] = { base_path.c_str() };
            const bool base_ok = fw::native::ghost_set_weapon(
                blob.peer_id, blob.item_form_id, base_candidates, 1);
            if (!base_ok) {
                FW_WRN("[mesh-rx] PATH-ONLY base load FAILED path='%s' "
                       "peer=%s form=0x%X — skipping mod paths too",
                       base_path.c_str(), blob.peer_id, blob.item_form_id);
                continue;
            }
            FW_LOG("[mesh-rx] PATH-ONLY base loaded: '%s'", base_path.c_str());

            // Subsequent paths → mod NIFs attached as children of base.
            int mods_attached = 0;
            int mods_failed = 0;
            for (std::size_t pi = 1; pi < blob.meshes.size(); ++pi) {
                const std::string& mod_path = blob.meshes[pi].m_name;
                if (mod_path.empty()) continue;
                if (mod_path == base_path) continue;  // dedup against base
                if (fw::native::attach_extra_nif_to_ghost_weapon(
                        blob.peer_id, mod_path.c_str())) {
                    ++mods_attached;
                } else {
                    ++mods_failed;
                }
            }
            FW_LOG("[mesh-rx] PATH-ONLY peer=%s form=0x%X DONE base=ok "
                   "mods_attached=%d mods_failed=%d",
                   blob.peer_id, blob.item_form_id,
                   mods_attached, mods_failed);
            ++applied_blobs;
            ++total_attached;
            continue;  // skip the legacy bgsm-derived path below
        }

        // Derive base NIF path from blob's meshes via SMART bgsm pick:
        // walk all meshes, prefer the one whose bgsm matches the canonical
        // pattern "Weapons\<X>\<X>.bgsm" (folder name == file basename).
        // That's where vanilla FO4 stores the main weapon body material.
        // Sub-components (Rocket, ShotgunShell, BloodWeapon) live in
        // sibling files like "Weapons\<X>\<XComponent>.bgsm" or sub-
        // folders like "Blood\BloodWeapon.bgsm" — those don't match the
        // pattern and get skipped.
        //
        // Helper lambda: convert a bgsm path to nif path, return empty
        // string on parse failure.
        auto bgsm_to_nif = [](const std::string& bgsm) -> std::string {
            std::string s = bgsm;
            static const char kPrefix[] = "Materials\\";
            static const char kPrefixLow[] = "materials\\";
            const std::size_t plen = sizeof(kPrefix) - 1;
            if (s.size() >= plen &&
                (std::strncmp(s.c_str(), kPrefix, plen) == 0 ||
                 std::strncmp(s.c_str(), kPrefixLow, plen) == 0))
            {
                s = s.substr(plen);
            }
            const std::size_t dot = s.find_last_of('.');
            if (dot != std::string::npos) {
                s.replace(dot, std::string::npos, ".nif");
            }
            return s;
        };

        // Helper: get folder + filename pieces.
        auto split_path = [](const std::string& p, std::string& folder,
                             std::string& filename) {
            const std::size_t backslash = p.find_last_of('\\');
            if (backslash == std::string::npos) {
                folder.clear();
                filename = p;
                return;
            }
            const std::size_t prev_backslash = p.find_last_of('\\', backslash - 1);
            if (prev_backslash == std::string::npos) {
                folder = p.substr(0, backslash);
            } else {
                folder = p.substr(prev_backslash + 1, backslash - prev_backslash - 1);
            }
            filename = p.substr(backslash + 1);
        };

        // Helper: filename without extension.
        auto strip_ext = [](const std::string& fn) -> std::string {
            const std::size_t dot = fn.find_last_of('.');
            if (dot == std::string::npos) return fn;
            return fn.substr(0, dot);
        };

        // Score each mesh's bgsm path: prefer canonical pattern.
        std::string nif_path;
        std::string fallback_path;
        for (const auto& m : blob.meshes) {
            if (m.bgsm_path.empty()) continue;
            std::string candidate = bgsm_to_nif(m.bgsm_path);
            if (candidate.empty()) continue;
            if (fallback_path.empty()) fallback_path = candidate;

            // Canonical: folder name == filename without ext.
            std::string folder, filename;
            split_path(candidate, folder, filename);
            const std::string base = strip_ext(filename);
            if (!folder.empty() && !base.empty() &&
                _stricmp(folder.c_str(), base.c_str()) == 0)
            {
                nif_path = candidate;
                FW_DBG("[mesh-rx] bgsm pick: canonical match '%s' (folder="
                       "'%s' base='%s')",
                       candidate.c_str(), folder.c_str(), base.c_str());
                break;
            }
        }
        if (nif_path.empty()) nif_path = fallback_path;

        if (nif_path.empty()) {
            FW_WRN("[mesh-rx] no bgsm-derived nif path for blob (peer=%s "
                   "form=0x%X) — skip", blob.peer_id, blob.item_form_id);
            continue;
        }

        FW_LOG("[mesh-rx] bgsm-derived nif path='%s' for peer=%s form=0x%X",
               nif_path.c_str(), blob.peer_id, blob.item_form_id);

        // === Build candidate list for ghost_set_weapon ===
        //
        // Priority order (highest first):
        //   1. nif_path (smart pick: canonical "Weapons\X\X.bgsm" pattern,
        //      e.g. for 10mm pistol the bgsm "10mmPistol.bgsm" exists)
        //   2. **FOLDER-DERIVED canonical**: for each unique parent folder
        //      seen in mesh bgsms, construct "Weapons\<folder>\<folder>.nif"
        //      and add as candidate. Catches runtime-assembled weapons
        //      whose sub-components live in a folder named after the base
        //      weapon (assault rifle = MachineGun folder → MachineGun.nif,
        //      shotgun = Shotgun folder → Shotgun.nif).
        //   3. All sub-component bgsm-derived paths (last resort — these
        //      load only one part of the assembled weapon).
        //
        // ghost_set_weapon will also auto-fallback to legacy resolve_weapon
        // _nif_path if all our candidates fail.
        std::vector<std::string> candidate_paths_storage;
        candidate_paths_storage.reserve(blob.meshes.size() + 4);
        auto push_unique = [&](std::string p) {
            if (p.empty()) return;
            for (const auto& s : candidate_paths_storage) {
                if (s == p) return;
            }
            candidate_paths_storage.push_back(std::move(p));
        };

        // 1. Smart-pick winner (if any).
        push_unique(nif_path);

        // 2. Folder-derived canonical: extract unique parent folders from
        //    every mesh's bgsm, construct "<folder>\<basename>.nif" where
        //    basename = last folder component.
        for (const auto& m : blob.meshes) {
            if (m.bgsm_path.empty()) continue;
            std::string nif = bgsm_to_nif(m.bgsm_path);
            if (nif.empty()) continue;
            const std::size_t bs = nif.find_last_of('\\');
            if (bs == std::string::npos) continue;
            std::string folder_path = nif.substr(0, bs);
            // Last folder name = basename of folder_path
            const std::size_t prev_bs = folder_path.find_last_of('\\');
            std::string last_folder = (prev_bs == std::string::npos)
                ? folder_path
                : folder_path.substr(prev_bs + 1);
            if (last_folder.empty()) continue;
            std::string canonical = folder_path + "\\" + last_folder + ".nif";
            push_unique(std::move(canonical));
        }

        // 3. Per-mesh bgsm-derived (sub-component fallbacks).
        for (const auto& m : blob.meshes) {
            if (m.bgsm_path.empty()) continue;
            std::string c = bgsm_to_nif(m.bgsm_path);
            push_unique(std::move(c));
        }

        // Convert to char*[] for the API.
        std::vector<const char*> candidate_paths;
        candidate_paths.reserve(candidate_paths_storage.size());
        for (const auto& s : candidate_paths_storage) {
            candidate_paths.push_back(s.c_str());
        }

        const bool ok = fw::native::ghost_set_weapon(
            blob.peer_id, blob.item_form_id,
            candidate_paths.empty() ? nullptr : candidate_paths.data(),
            candidate_paths.size());
        if (ok) {
            ++applied_blobs;
            ++total_attached;
            FW_LOG("[mesh-rx] ghost_set_weapon OK peer=%s form=0x%X "
                   "candidates=%zu",
                   blob.peer_id, blob.item_form_id,
                   candidate_paths.size());

            // M9.w4 PROPER (v0.4.2+, Path Y, 2026-05-04 PM) — disk-loaded
            // mod NIFs. The captured mesh data tells us WHICH mods the
            // peer has equipped (via parent_placeholder = mod root name).
            // For each, derive a candidate disk path and load via the
            // engine's nif_load_by_path — engine does shader binding
            // naturally so no vertex format mismatch crash (which doomed
            // factory-reconstruct + donor-shader in v0.4.0 + v0.4.2 P3.1).
            //
            // Convert blob.meshes (PendingMeshRecord) → CapturedMeshView.
            std::vector<fw::native::CapturedMeshView> views;
            views.reserve(blob.meshes.size());
            for (const auto& m : blob.meshes) {
                fw::native::CapturedMeshView v{};
                v.m_name             = m.m_name.c_str();
                v.parent_placeholder = m.parent_placeholder.c_str();
                v.positions          = m.positions.empty()
                                          ? nullptr : m.positions.data();
                v.indices            = m.indices.empty()
                                          ? nullptr : m.indices.data();
                v.vert_count         = m.vert_count;
                v.tri_count          = m.tri_count;
                v.local_transform    = m.local_transform;
                views.push_back(v);
            }

            // M9.w4 PROPER (v0.4.2+, RESMGR-LOOKUP, 2026-05-04 PM) —
            // walk the engine's NIF resource manager (singleton at
            // *qword_1430DD618), find each captured parent_placeholder
            // by m_name match, refbump-share the BSFadeNode, attach
            // to ghost weapon root. Engine handles shader/material/vd
            // binding because the node was loaded by the engine itself
            // — no factory reconstruction, no donor shader crash.
            //
            // The BSResource::EntryDB<BSModelDB> singleton holds ALL
            // pre-loaded NIFs including weapon mod sub-NIFs. Once the
            // local player has equipped a modded weapon, every mod's
            // BSFadeNode is in the cache, keyed by m_name. We just
            // look it up and share-attach to the ghost.
            // Hybrid: resmgr-share PRIMARY + disk-load FALLBACK.
            // Receiver's local resmgr only contains NIFs the receiver's
            // own engine has loaded; mod NIFs never seen on receiver
            // require disk fetch via nif_load_by_path (engine then caches
            // them for future use).
            //
            // Derive base folder from slot's loaded nif_path for disk
            // candidate paths.
            std::string base_folder;
            {
                // ghost_set_weapon stored the loaded path; we re-read it
                // by calling find via captured base bgsm. Already done by
                // attach_mod_nifs_via_disk path; here we replicate to
                // avoid that function's overhead.
                std::size_t bs = nif_path.find_last_of('\\');
                if (bs != std::string::npos) {
                    base_folder = nif_path.substr(0, bs);
                }
            }

            // 2026-05-06 evening — UNCONDITIONALLY clear extra_mods at the
            // start of every blob receive. Was: gated behind `any_mod` so
            // a blob carrying ZERO mod descriptors didn't trigger cleanup.
            // Bug exposed by live test: user equipped 10mm-with-silencer,
            // then switched to a different 10mm-without-silencer instance
            // from inventory. Second blob had no mods → any_mod=false →
            // clear skipped → silencer from first equip remained attached
            // to the cached base. Now we always clear; the per-blob
            // attach loop below re-attaches whatever mods THIS blob
            // describes (possibly zero). User reported: "cambio arma
            // senza silenziatore ma il silenziatore ora permane".
            fw::native::clear_ghost_extra_mods(blob.peer_id);
            bool any_mod = false;
            for (const auto& m : blob.meshes) {
                if (!m.parent_placeholder.empty()) { any_mod = true; break; }
            }
            if (any_mod) {
                fw::native::dump_ghost_weapon_subtree(blob.peer_id, 6);
                // 2026-05-06 evening — CULL DISABLED. Was culling EVERY
                // BSGeometry leaf inside the base BSFadeNode → killed
                // not just stock-mod-default leaves but also the
                // ALWAYS-VISIBLE body parts (receiver casting, slide,
                // frame, hand-grip stock). User reported: "manca la
                // base dove si attaccano, la pistola non c'è".
                //
                // The original intent was to hide stock defaults inside
                // placeholder NiNodes that were going to be REPLACED by
                // mod attachments (e.g. cull the default-short-barrel
                // BSTriShape under "PistolMuzzle" before attaching the
                // suppressor mod). But our cull walker treated all
                // base-stock leaves uniformly — no distinction between
                // "always-visible body part" vs "default that mod
                // replaces". To do this properly we'd need per-
                // placeholder cull info: only cull leaves whose parent
                // placeholder is targeted by an incoming mod.
                //
                // For now: NO cull. Mods overlay on full stock weapon.
                // Some defaults may show through under mods (e.g.
                // default-short-barrel sticking out from suppressor) —
                // visually imperfect but at least the body is visible.
                // Selective placeholder-aware cull is a follow-up.
                //
                // const int culled = fw::native::
                //     cull_base_geometry_for_modded_weapon(blob.peer_id);
                // FW_LOG("[mesh-rx] base-cull peer=%s form=0x%X "
                //        "culled %d BSGeometry leaves (stock geom hidden, "
                //        "mods attach on top)",
                //        blob.peer_id, blob.item_form_id, culled);
            }

            // === M9 closure (Phase 1, 2026-05-06) — OMOD-derived path attach ===
            //
            // 2026-05-06 PM — DISABLED. The OMOD-derive path attaches
            // every mod as a direct child of base_root with no
            // positioning info (no slot placeholder, no transform).
            // The pre-existing resmgr-share path (above this block) does
            // proper placeholder-aware attach via slot_name +
            // find_node_by_name_w4 against the loaded base, with the
            // sender's captured local_transform.
            //
            // 2026-05-06 PM landings that make resmgr-share self-sufficient:
            //   • name-reader bug fixed (was reading wrong offset → ALL
            //     placeholder lookups silently failed → fell back to
            //     attaching at base_root → "tutte uguali e troppo moddate").
            //   • cull walker stops at BSFadeNode/BSLeafAnimNode for
            //     non-root nodes (was descending into mod children and
            //     culling THEIR geometry → growing-cull-count bug).
            //   • clone_nif_subtree replaced with vt[26] dispatch — every
            //     peer's loaded base + each attached mod is now an
            //     independent deep-clone (engine-grade, with GPU buffer
            //     AddRef on BSTriShape leaves). No more cache-share
            //     mutation across peers / across equips.
            //
            // Keep OMOD-derive gated off as a clean default. If the live
            // test reveals MISSING mods (e.g. mods whose geometry was
            // capture-culled at sender side), re-enable as a transform-
            // less fallback below.
            int mods_omod_attached = 0;
            std::unordered_set<std::string> seen_omod_paths;
            std::uint32_t peer_omod_forms[32]{};
            const std::uint8_t peer_omod_count = 0;  // FORCED 0 — keep declaration for log compat
            (void)seen_omod_paths;
            (void)peer_omod_forms;
            // const std::uint8_t peer_omod_count =
            //     fw::native::snapshot_peer_omod_forms_public(
            //         blob.peer_id, peer_omod_forms, 32);
            if (peer_omod_count > 0) {
                FW_LOG("[mesh-rx] OMOD-derive peer=%s has %u OMODs to resolve",
                       blob.peer_id,
                       static_cast<unsigned>(peer_omod_count));
                // 2026-05-06 v2 — self-attach guard. Some OMODs (the
                // "stock" / default components) have their TESModel.modelPath
                // pointing to the BASE weapon NIF itself rather than a
                // distinct mod NIF. Live test caught
                //   OMOD 0x148337 → 'Weapons\\10mmPistol\\10MMPistol.nif'
                // which equals the loaded base; nif_load_by_path returns
                // the cached base node, attach_child_direct then makes the
                // base its OWN child → cycle in scene graph → AV on next
                // render walk (the user's "saw it for half a second then
                // crashed" symptom). Detect via case-insensitive equality
                // against the slot's stored nif_path.
                auto path_eq_ci = [](const char* a, const char* b) -> bool {
                    if (!a || !b) return false;
                    while (*a && *b) {
                        char ca = *a, cb = *b;
                        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca - 'A' + 'a');
                        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb - 'A' + 'a');
                        if (ca != cb) return false;
                        ++a; ++b;
                    }
                    return *a == 0 && *b == 0;
                };

                for (std::uint8_t i = 0; i < peer_omod_count; ++i) {
                    const std::uint32_t fid = peer_omod_forms[i];
                    if (fid == 0) continue;
                    const char* path =
                        fw::native::resolve_omod_model_path(fid);
                    if (!path || !path[0]) {
                        FW_DBG("[mesh-rx]   OMOD 0x%X: no NIF (numeric-only "
                               "or unresolved)", fid);
                        continue;
                    }
                    // Self-attach guard: skip if this OMOD's modelPath is
                    // the base weapon NIF itself. Such OMODs are stock
                    // components that the engine bakes into the base —
                    // there's nothing extra to attach.
                    if (!nif_path.empty() && path_eq_ci(path, nif_path.c_str())) {
                        FW_DBG("[mesh-rx]   OMOD 0x%X path='%s' EQUALS base — "
                               "stock mod, skip (would self-attach)",
                               fid, path);
                        continue;
                    }
                    // Dedupe — same NIF path attached more than once would
                    // waste refbumps and pile up duplicate geometry.
                    if (!seen_omod_paths.insert(path).second) {
                        FW_DBG("[mesh-rx]   OMOD 0x%X path='%s' DUP — skip",
                               fid, path);
                        continue;
                    }
                    if (fw::native::attach_extra_nif_to_ghost_weapon(
                            blob.peer_id, path)) {
                        ++mods_omod_attached;
                        FW_LOG("[mesh-rx]   OMOD 0x%X path='%s' ATTACHED",
                               fid, path);
                    } else {
                        FW_DBG("[mesh-rx]   OMOD 0x%X path='%s' attach FAILED",
                               fid, path);
                    }
                }
                FW_LOG("[mesh-rx] OMOD-derive: %d/%u attached for peer=%s "
                       "(form=0x%X)",
                       mods_omod_attached,
                       static_cast<unsigned>(peer_omod_count),
                       blob.peer_id, blob.item_form_id);
            }

            // 2026-05-05 — pre-pass: group meshes by parent_placeholder
            // and pick a BEST representative per group. The criteria:
            // a mesh whose bgsm_path starts with "Materials\\Weapons\\"
            // gives us the actual weapon-mod NIF filename (e.g.
            // "Materials\\Weapons\\10mmPistol\\10mmReflexSight.BGSM"
            // → derive "Weapons\\10mmPistol\\10mmReflexSight.nif"),
            // whereas a leaf using an EFFECTS material like the reflex
            // glass overlay (Materials\\Effects\\ReflexGlass10mm.BGSM
            // .BGEM) is a sub-mesh useless for path derivation.
            //
            // Without this pre-pass the simple "first wins" dedupe was
            // grabbing whatever leaf appeared first in clone-factory
            // order and missing the canonical mod NIF.
            struct BestMod {
                const PendingMeshRecord* mesh        = nullptr;
                bool                     weapons_bgsm = false;
            };
            std::unordered_map<std::string, BestMod> mods_by_parent;
            mods_by_parent.reserve(blob.meshes.size());
            int mods_dup = 0;
            for (const auto& m : blob.meshes) {
                if (m.parent_placeholder.empty()) continue;
                auto& slot = mods_by_parent[m.parent_placeholder];
                // Case-insensitive prefix check for "Materials\\Weapons\\".
                auto starts_ci = [](const std::string& s, const char* pre) {
                    const std::size_t pl = std::strlen(pre);
                    if (s.size() < pl) return false;
                    for (std::size_t i = 0; i < pl; ++i) {
                        char a = s[i]; char b = pre[i];
                        if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
                        if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
                        if (a != b) return false;
                    }
                    return true;
                };
                const bool this_is_weapons =
                    starts_ci(m.bgsm_path, "Materials\\Weapons\\");
                if (!slot.mesh ||
                    (this_is_weapons && !slot.weapons_bgsm)) {
                    if (slot.mesh) ++mods_dup;
                    slot.mesh = &m;
                    slot.weapons_bgsm = this_is_weapons;
                } else {
                    ++mods_dup;
                }
            }

            // Helper: derive NIF path from a bgsm_path. Bethesda's
            // weapon mod authoring puts the NIF and the BGSM next to
            // each other with the same basename — only the extension
            // differs. We strip the leading "Materials\\" subfolder and
            // swap the trailing extension. Returns empty on
            // un-derivable input.
            auto derive_nif_from_bgsm =
                [](const std::string& bgsm) -> std::string {
                if (bgsm.size() < 11) return {};
                // Case-insensitive strip of "Materials\\".
                std::string p;
                {
                    std::string head = bgsm.substr(0, 10);
                    std::string lower;
                    lower.reserve(10);
                    for (char c : head) {
                        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
                        lower.push_back(c);
                    }
                    if (lower == "materials\\") p = bgsm.substr(10);
                    else                         p = bgsm;
                }
                // Replace trailing extension. Bethesda chains like
                // "*.BGSM.BGEM" exist — take the LAST dot's content
                // and swap if it's BGSM/BGEM/BGSM.BGEM/etc.
                auto rfind_ext = p.rfind('.');
                if (rfind_ext == std::string::npos) return {};
                std::string ext = p.substr(rfind_ext + 1);
                // lowercase
                for (auto& c : ext) {
                    if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
                }
                if (ext != "bgsm" && ext != "bgem") return {};
                return p.substr(0, rfind_ext) + ".nif";
            };

            int mods_share_attached  = 0;
            int mods_bgsm_attached   = 0;
            int mods_disk_attached   = 0;
            int mods_total_miss      = 0;
            for (const auto& [parent, info] : mods_by_parent) {
                const auto& m = *info.mesh;

                // Step 1: try resmgr-share (free if already cached).
                // - parent_placeholder = mod NIF root m_name → resmgr KEY
                // - slot_name          = base NIF slot name → attach point
                // - local_transform    = sender-captured leaf transform
                //                        (written to mod node so it lands
                //                        at the same offset within slot)
                void* cached_node = fw::native::find_loaded_nif_by_m_name(
                    m.parent_placeholder.c_str());
                if (cached_node) {
                    if (fw::native::attach_extra_node_to_ghost_weapon(
                            blob.peer_id, cached_node,
                            m.parent_placeholder.c_str(),
                            m.slot_name.empty() ? nullptr : m.slot_name.c_str(),
                            m.local_transform)) {
                        ++mods_share_attached;
                        continue;
                    }
                }

                // Step 2: bgsm-derived disk path. Bethesda-naming
                // convention says the mod NIF and its BGSM share a
                // basename — so converting the bgsm_path into a NIF
                // path lets us locate the actual file even when the
                // mod's runtime m_name (parent_placeholder) doesn't
                // match the file basename — e.g. when the engine
                // renames the loaded BSFadeNode root via OMOD INNT
                // ("10mmReflexSight.nif" loads with m_name set to
                // "10mmReflexDot" at runtime, so resmgr-by-name lookup
                // for "10mmReflexDot" misses while the file IS
                // available on disk under its real basename).
                //
                // SKIP if the derived path equals the loaded base — the
                // sender ships parent_placeholder="Pistol10mmReceiver"
                // for the 10mm receiver mod whose bgsm_path also points
                // at "10mmPistol.bgsm" (= base file). Loading that
                // would just re-load the base nested inside itself.
                if (!m.bgsm_path.empty()) {
                    std::string derived = derive_nif_from_bgsm(m.bgsm_path);
                    bool same_as_base = false;
                    if (!derived.empty() && !nif_path.empty()) {
                        // Case-insensitive match against the loaded
                        // base path.
                        if (derived.size() == nif_path.size()) {
                            same_as_base = true;
                            for (std::size_t i = 0; i < derived.size(); ++i) {
                                char a = derived[i], b = nif_path[i];
                                if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
                                if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
                                if (a != b) { same_as_base = false; break; }
                            }
                        }
                    }
                    if (!derived.empty() && !same_as_base) {
                        // 2026-05-06 evening — pass slot_name so the
                        // disk-loaded mod routes to the right placeholder
                        // (same multi-tier resolver as resmgr-share path).
                        const char* slot_cstr = m.slot_name.empty()
                            ? nullptr
                            : m.slot_name.c_str();
                        if (fw::native::attach_extra_nif_to_ghost_weapon(
                                blob.peer_id, derived.c_str(),
                                slot_cstr)) {
                            ++mods_bgsm_attached;
                            continue;
                        }
                    }
                }

                // Step 3: heuristic disk fallback — try multiple path
                // patterns. The first that loads is attached. Cache
                // populates as side effect (next equip of same combo
                // will hit step 1 or step 2).
                if (base_folder.empty()) {
                    ++mods_total_miss;
                    continue;
                }
                static const char* const kSubfolders[] = {
                    "",                        // <folder>\<name>.nif
                    "Mods\\",
                    "Mods\\Barrels\\",
                    "Mods\\Barrel\\",
                    "Mods\\Muzzles\\",
                    "Mods\\Muzzle\\",
                    "Mods\\Sights\\",
                    "Mods\\Sight\\",
                    "Mods\\Iron\\",
                    "Mods\\Receivers\\",
                    "Mods\\Receiver\\",
                    "Mods\\Magazines\\",
                    "Mods\\Magazine\\",
                    "Mods\\Mag\\",
                    "Mods\\Grips\\",
                    "Mods\\Grip\\",
                    "Mods\\Stocks\\",
                    "Mods\\Stock\\",
                };
                bool disk_ok = false;
                {
                    const char* slot_cstr = m.slot_name.empty()
                        ? nullptr
                        : m.slot_name.c_str();
                    for (const char* sub : kSubfolders) {
                        std::string p = base_folder + "\\" + sub +
                                        m.parent_placeholder + ".nif";
                        if (fw::native::attach_extra_nif_to_ghost_weapon(
                                blob.peer_id, p.c_str(), slot_cstr)) {
                            disk_ok = true;
                            ++mods_disk_attached;
                            break;
                        }
                    }
                }
                if (!disk_ok) ++mods_total_miss;
            }
            FW_LOG("[mesh-rx] resmgr-hybrid: peer=%s form=0x%X "
                   "share=%d bgsm=%d disk=%d miss=%d dup=%d (of %zu meshes)",
                   blob.peer_id, blob.item_form_id,
                   mods_share_attached, mods_bgsm_attached,
                   mods_disk_attached,
                   mods_total_miss, mods_dup, blob.meshes.size());

            // ATTEMPT #6 diagnostic — see scene_inject.cpp.
            // Dump the WEAPON state right after we finished attaching
            // all mods for this blob. This is the canonical "what does
            // the engine actually see" snapshot for this equip cycle.
            fw::native::dump_weapon_attach_state("post-mesh-blob-attach");

            /* Path Y disk-load (kept for fallback diagnostic).
            const int n_loaded =
                fw::native::attach_mod_nifs_via_disk(
                    blob.peer_id, blob.item_form_id,
                    views.data(), views.size());
            FW_LOG("[mesh-rx] mod-nif: peer=%s form=0x%X loaded=%d of "
                   "%zu candidate meshes (grouped by parent_placeholder)",
                   blob.peer_id, blob.item_form_id,
                   n_loaded, views.size());
            */

            /* DISABLED: factory-reconstruct path (Phase 3 base).
            // Useful for diagnostics: logs what WOULD be reconstructed
            // from raw geometry. Disabled until shader binding (Phase 3.2)
            // resolves the vertex format mismatch that blocks visibility.
            const int n_attached =
                fw::native::attach_captured_meshes_to_ghost_weapon(
                    blob.peer_id, blob.item_form_id,
                    views.data(), views.size());
            FW_LOG("[mesh-rx] reconstruct: peer=%s form=0x%X attached=%d "
                   "of %zu candidate meshes",
                   blob.peer_id, blob.item_form_id,
                   n_attached, views.size());
            */
        } else {
            FW_WRN("[mesh-rx] ghost_set_weapon FAILED peer=%s form=0x%X "
                   "(no candidate loaded; existing slot left untouched)",
                   blob.peer_id, blob.item_form_id);
        }
    }
    FW_LOG("dispatch: drained %zu mesh-blob ops, applied=%zu blobs (pivot to "
           "NIF-load path)", local.size(), applied_blobs);
}

void drain_equip_apply_queue() {
    std::deque<PendingEquipOp> local;
    {
        std::lock_guard lk(g_equip_mtx);
        local.swap(g_equip_queue);
    }
    if (local.empty()) {
        FW_DBG("dispatch: equip drain with empty queue — no-op");
        return;
    }

    // We're on the main thread. Each equip op resolves the item form via
    // lookup_by_form_id and dispatches to the appropriate attach path:
    //
    //   1. Try ARMOR first — walks TESObjectARMO addon array → ARMA →
    //      TESModel → BSFixedString. Returns false if the form isn't ARMO
    //      (no addon array at +0x2A8) — silently, no AV.
    //   2. If ARMOR returns false AND ghost is live, try WEAPON — walks
    //      TESObjectWEAP TESModel directly (no addon array). Returns
    //      false if it isn't WEAP either, or if the path doesn't match
    //      the "Weapons\\" heuristic.
    //
    // The dual-attempt avoids needing to RE the FormType byte for ARMO vs
    // WEAP on this build (FO4 1.11.191 next-gen has a remapped formType
    // table — see door_hook for similar reasoning). The per-form struct
    // walks act as their own type-detection.
    //
    // Boot race note: if ghost isn't spawned yet, BOTH ghost_attach_armor
    // and ghost_attach_weapon will queue (one in armor's pending queue,
    // one in weapon's pending queue). On ghost spawn, the right-type
    // flush succeeds and the wrong-type flush silently fails — net cost
    // a few tens of bytes RAM during boot. Trade-off accepted to keep
    // the dispatcher form-agnostic.
    //
    // No ApplyingRemoteGuard needed here — we are NOT calling any engine
    // function that the equip_hook detour intercepts. Both attach paths
    // use g_r.nif_load_by_path + g_r.attach_child_direct, which are
    // NIF/scene primitives unrelated to ActorEquipManager.
    std::size_t applied_ok = 0, failed = 0;
    for (const auto& op : local) {
        // EquipOpKind: 1=EQUIP, 2=UNEQUIP. See net/protocol.h.
        const bool is_equip = (op.kind == 1);

        // Pass 1 — try as ARMOR.
        // M9.w2 PROPER (v10): pass effective_priority from the wire so
        // resolve_armor_nif_path's PrioritySelect filter picks the right
        // ARMA tier (Lite/Mid/Heavy) when OMOD upgrade is attached.
        bool ok = is_equip
            ? fw::native::ghost_attach_armor(op.peer_id, op.item_form_id,
                                              op.effective_priority)
            : fw::native::ghost_detach_armor(op.peer_id, op.item_form_id);

        // Pass 2 — if armor returned false, try as WEAPON. The armor
        // path returning false means either:
        //   (a) Form isn't ARMO (struct walk failed, path didn't match
        //       armor heuristics) — weapon attempt is the right next step.
        //   (b) Ghost not spawned yet (form was queued for armor flush
        //       on next ghost spawn) — weapon attempt will ALSO queue
        //       (harmlessly; see boot-race note above).
        //   (c) Genuine attach failure (NIF load error) — weapon attempt
        //       will likely also fail at the same step; logs both errors,
        //       not great but not harmful.
        // Cost of always attempting weapon on armor-false is one extra
        // form lookup + offset probe. Cheap.
        //
        // M9 w4 v9.1: route weapons through the unified state machine.
        //   - EQUIP: ghost_set_weapon with NO candidate list (forces use
        //            of legacy resolve_weapon_nif_path, which after the
        //            Dummy filter usually picks the proper NIF).
        //   - UNEQUIP: ghost_clear_weapon with expected_form_id guard
        //              (no-op if peer has already switched to a different
        //              weapon by the time UNEQUIP arrives).
        //
        // Mesh-blob path (drain_mesh_blob_apply_queue) provides the high-
        // priority candidate list for the SAME form_id. State machine's
        // downgrade protection ensures placeholder paths from this
        // path never overwrite the proper paths from mesh-blob.
        if (!ok) {
            if (is_equip) {
                // 2026-05-07 — Receiver applies each EQUIP_BCAST normally.
                // The off-by-one render lag (first equip displays as
                // stock or as previous weapon) is fixed sender-side via
                // the auto re-equip cycle in equip_hook.cpp: 50 ms after
                // the user's equip, the sender fires UnequipObject +
                // EquipObject for the same form. Receiver gets EQUIP-X,
                // UNEQUIP-X, EQUIP-X on the wire and applies each in
                // order — the second EQUIP-X is the "magic re-equip"
                // that renders the modded weapon correctly on the ghost.
                ok = fw::native::ghost_attach_assembled_weapon(
                    op.peer_id, op.item_form_id,
                    op.omod_form_ids, op.omod_count);
                if (!ok) {
                    FW_DBG("[equip-drain] name-match failed for peer=%s "
                           "form=0x%X — falling back to ghost_set_weapon",
                           op.peer_id, op.item_form_id);
                    ok = fw::native::ghost_set_weapon(
                        op.peer_id, op.item_form_id,
                        /*no candidates*/ nullptr, 0);
                }
            } else {
                // 2026-05-07 — TRANSIENT-SWAP-SLOT FILTER.
                //
                // The engine's ActorEquipManager internally fires
                //   Equip(new, slot=DefaultEquipSlot)
                //   Unequip(new, slot=0x4334D, force=1)   ← THIS LINE
                //   Unequip(old, slot=0x4334D)
                // as part of the "swap-into-slot" sequence. The middle
                // Unequip is targeting a TRANSIENT internal slot
                // (form id 0x4334D, the kReadiedWeapon BGSEquipSlot).
                // It does NOT mean "the player no longer has this
                // weapon equipped" — the engine immediately routes the
                // ready-state into the real slot afterwards.
                //
                // Pre-fix, our ghost_clear_weapon was matching this
                // Unequip's form_id against our slot's form_id and
                // wiping the freshly-attached weapon, leaving the
                // ghost empty. Live test 2026-05-07 06:34:47 showed
                // EQUIP 0x4822 followed 7ms later by UNEQUIP 0x4822
                // slot=0x4334D, instantly cancelling the visible weapon.
                //
                // Filter: Unequip with slot_form_id == 0x4334D is a
                // transient bookkeeping op, ignore it on the receiver.
                // Real "player put the weapon away" UNEQUIPs use
                // slot_form_id = 0x0 (DefaultEquipSlot) and survive
                // this filter.
                constexpr std::uint32_t TRANSIENT_SWAP_SLOT = 0x4334D;
                if (op.slot_form_id == TRANSIENT_SWAP_SLOT) {
                    FW_DBG("[equip-drain] skip transient-swap UNEQUIP "
                           "peer=%s form=0x%X slot=0x%X (engine internal)",
                           op.peer_id, op.item_form_id, op.slot_form_id);
                    ok = true;  // treat as handled — no action needed
                } else {
                    ok = fw::native::ghost_clear_weapon(
                        op.peer_id, op.item_form_id);
                }
            }
        }

        if (ok) ++applied_ok; else ++failed;
    }
    FW_LOG("dispatch: drained %zu equip ops (applied=%zu failed=%zu)",
           local.size(), applied_ok, failed);
}

void drain_door_apply_queue() {
    std::deque<PendingDoorOp> local;
    {
        std::lock_guard lk(g_door_mtx);
        local.swap(g_door_queue);
    }
    if (local.empty()) {
        FW_DBG("dispatch: door drain with empty queue — no-op");
        return;
    }

    // Main thread + ApplyingRemoteGuard scope so the door_hook detour
    // sees tls_applying_remote=true on the re-entry caused by our own
    // call to engine_activate (Activate worker fires its anim graph
    // notify which may re-enter the same hook). Without the guard we'd
    // echo the remote door op back to the server.
    fw::hooks::ApplyingRemoteGuard guard;

    std::size_t applied_ok = 0, failed = 0;
    for (const auto& op : local) {
        const bool ok = fw::engine::apply_door_op_to_engine(
            op.door_form_id,
            op.door_base_id,
            op.door_cell_id);
        if (ok) ++applied_ok; else ++failed;
    }
    FW_LOG("dispatch: drained %zu door ops (applied=%zu failed=%zu)",
           local.size(), applied_ok, failed);
}

void drain_container_apply_queue() {
    std::deque<PendingContainerOp> local;
    {
        std::lock_guard lk(g_mtx);
        local.swap(g_queue);
    }
    if (local.empty()) {
        FW_DBG("dispatch: drain called with empty queue — no-op");
        return;
    }

    // We're on the main thread here (WndProc dispatch). Set the feedback-
    // loop guard so any vt[0x7A] / TransferItem re-entry triggered by
    // AddItem/RemoveItem internals does NOT re-emit to the network.
    fw::hooks::ApplyingRemoteGuard guard;

    std::size_t applied_ok = 0, failed = 0;
    for (const auto& op : local) {
        const bool ok = fw::engine::apply_container_op_to_engine(
            op.kind,
            op.container_form_id,
            op.container_base_id,
            op.container_cell_id,
            op.item_base_id,
            op.count);
        if (ok) ++applied_ok; else ++failed;
    }
    FW_LOG("dispatch: drained %zu container ops (applied=%zu failed=%zu)",
           local.size(), applied_ok, failed);
}

void set_target_hwnd(HWND hwnd) {
    g_hwnd.store(hwnd, std::memory_order_release);
    FW_LOG("dispatch: target hwnd set to %p", hwnd);
    // Flush whatever accumulated before the subclass was installed.
    std::size_t pending = 0;
    {
        std::lock_guard lk(g_mtx);
        pending = g_queue.size();
    }
    if (pending > 0) {
        FW_LOG("dispatch: flushing %zu pre-hwnd queued ops", pending);
        post_wakeup_container();
    }
    // B6.1: also flush any door ops accumulated pre-subclass.
    std::size_t pending_doors = 0;
    {
        std::lock_guard lk(g_door_mtx);
        pending_doors = g_door_queue.size();
    }
    if (pending_doors > 0) {
        FW_LOG("dispatch: flushing %zu pre-hwnd queued door ops", pending_doors);
        post_wakeup_door();
    }
    // M9 wedge 2: flush any equip ops accumulated pre-subclass.
    std::size_t pending_equips = 0;
    {
        std::lock_guard lk(g_equip_mtx);
        pending_equips = g_equip_queue.size();
    }
    if (pending_equips > 0) {
        FW_LOG("dispatch: flushing %zu pre-hwnd queued equip ops", pending_equips);
        post_wakeup_equip();
    }
    // M9 wedge 4 v9: flush any mesh blob ops accumulated pre-subclass.
    std::size_t pending_mesh_blobs = 0;
    {
        std::lock_guard lk(g_mesh_blob_mtx);
        pending_mesh_blobs = g_mesh_blob_queue.size();
    }
    if (pending_mesh_blobs > 0) {
        FW_LOG("dispatch: flushing %zu pre-hwnd queued mesh-blob ops",
               pending_mesh_blobs);
        post_wakeup_mesh_blob();
    }
}

std::size_t pending_count() {
    std::lock_guard lk(g_mtx);
    return g_queue.size();
}

HWND get_target_hwnd() {
    return g_hwnd.load(std::memory_order_acquire);
}

} // namespace fw::dispatch
