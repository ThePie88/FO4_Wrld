#include "main_thread_dispatch.h"

#include <atomic>
#include <deque>
#include <mutex>

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
        FW_LOG("[mesh-rx] APPLY peer=%s form=0x%X equip_seq=%u meshes=%zu",
               blob.peer_id, blob.item_form_id, blob.equip_seq,
               blob.meshes.size());

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
        bool ok = is_equip
            ? fw::native::ghost_attach_armor(op.peer_id, op.item_form_id)
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
                ok = fw::native::ghost_set_weapon(
                    op.peer_id, op.item_form_id,
                    /*no candidates*/ nullptr, 0);
            } else {
                ok = fw::native::ghost_clear_weapon(
                    op.peer_id, op.item_form_id);
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
