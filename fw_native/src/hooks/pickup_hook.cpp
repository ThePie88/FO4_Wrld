#include "pickup_hook.h"

#include <windows.h>
#include <atomic>
#include <cstdint>

#include "container_hook.h"   // extern tls_applying_remote
#include "../engine/engine_calls.h"
#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"
#include "../ref_identity.h"
#include "../net/client.h"
#include "../net/protocol.h"
#include "../native/world_spawn.h"   // L5 stage 2: on_local_pickup; R1b: note_local_pickup, cancel_pending_drop
#include "../persist/inventory_capture.h"   // R1b: read_refr_record (the line of the REFR)
#include "../persist/instance_fp.h"         // R1b: fp_of_record

namespace fw::hooks {

namespace {

// sub_140500430 @ RVA 0x500430 — inventory-add helper.
//   dst_actor : TESObjectREFR* (typically the player) receiving the item
//   src_refr  : TESObjectREFR* — the WORLD REFR being absorbed (direct ptr!)
//   count     : uint32 instance count
//
// Called internally by PC::PickUp (vt[0xEC]) and possibly by other
// inventory-insert paths (sub-ref rollup when looting a container with
// attached children). The source is a REFR* directly, so we skip all
// the handle-resolution pain that doomed attempts #1..#3.
using InvAddFromWorldFn = void (*)(
    void* dst_actor, void* src_refr, std::uint32_t count);

InvAddFromWorldFn g_orig_inv_add = nullptr;
std::atomic<std::uintptr_t> g_module_base{0};   // R1b: for read_refr_record

std::atomic<std::uint64_t> g_fire_count{0};

// POD observation result — populated inside SEH-caged observe, read by
// the detour (non-trivial types outside __try).
struct PickupObserveResult {
    bool emit;                       // true → fire ACTOR_EVENT DISABLE
    fw::net::ActorEventPayload aep;  // valid if emit
    std::uint32_t item_refr_form_id;
    std::uint32_t item_base_id;
    std::uint32_t cell_id;
};

static void observe_pickup(
    void* dst_actor, void* src_refr, std::uint32_t count,
    PickupObserveResult* out)
{
    (void)dst_actor;
    out->emit = false;
    out->item_refr_form_id = 0;
    out->item_base_id = 0;
    out->cell_id = 0;

    __try {
        if (!src_refr || count == 0) return;

        g_fire_count.fetch_add(1, std::memory_order_relaxed);

        // Filter (a): feedback protection. If we're applying a remote
        // ACTOR_EVENT DISABLE right now (set by client dispatch RAII),
        // any engine calls that cascade into sub_140500430 must NOT
        // re-emit to the network.
        if (tls_applying_remote) {
            FW_DBG("[pickup] tls_applying_remote=true — skip (feedback guard)");
            return;
        }

        // Filter (b): parentCell must be non-null. A genuine world
        // pickup has the REFR placed in a world/interior cell. Some
        // transient inventory-reshuffle paths (ExtraContainerChanges
        // rebuild) may call sub_140500430 with refs that have no
        // parentCell — skip those.
        const auto* rb = reinterpret_cast<const std::uint8_t*>(src_refr);
        void* parent_cell = *reinterpret_cast<void* const*>(
            rb + offsets::PARENT_CELL_OFF);
        if (!parent_cell) {
            FW_DBG("[pickup] parentCell=null — not a world pickup (src=%p)", src_refr);
            return;
        }

        // Read full identity (form_id, base_id, cell_id) via existing
        // SEH-caged helper.
        const auto id = fw::read_ref_identity(src_refr);
        if (id.form_id == 0 || id.base_id == 0 || id.cell_id == 0) {
            FW_WRN("[pickup] incomplete identity (form=0x%X base=0x%X cell=0x%X) src=%p — skip",
                   id.form_id, id.base_id, id.cell_id, src_refr);
            return;
        }

        // Read position from REFR+0xD0 (best-effort; zero on SEH).
        float x = 0.f, y = 0.f, z = 0.f;
        __try {
            x = *reinterpret_cast<const float*>(rb + offsets::POS_OFF + 0);
            y = *reinterpret_cast<const float*>(rb + offsets::POS_OFF + 4);
            z = *reinterpret_cast<const float*>(rb + offsets::POS_OFF + 8);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            x = y = z = 0.f;
        }

        // Populate payload.
        out->aep.kind          = static_cast<std::uint32_t>(
            fw::net::ActorEventKind::DISABLE);
        out->aep.form_id       = id.form_id;
        out->aep.actor_base_id = id.base_id;
        out->aep.x             = x;
        out->aep.y             = y;
        out->aep.z             = z;
        out->aep.extra         = 0;
        out->aep.cell_id       = id.cell_id;

        out->emit             = true;
        out->item_refr_form_id = id.form_id;
        out->item_base_id      = id.base_id;
        out->cell_id           = id.cell_id;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[pickup] SEH in observation (src_refr=%p)", src_refr);
        out->emit = false;
    }
}

void __fastcall detour_inv_add_from_world(
    void* dst_actor, void* src_refr, std::uint32_t count)
{
    FW_DBG("[pickup] ENTRY dst=%p src=%p count=%u", dst_actor, src_refr, count);

    PickupObserveResult r{};
    observe_pickup(dst_actor, src_refr, count, &r);

    if (r.emit) {
        // L5 realtime R1b (2026-10-05) — the pickup is an op of the record,
        // said NOW, while the REFR is still alive (the engine destroys it
        // inside the original): its line read from the REFR, its wid when it
        // is an object of ours, its form id otherwise; the server does the
        // world side and the record side in one journal record and answers
        // with a verdict (a refusal destroys the item: someone else took it
        // first). A drop of ours still falling, taken back: the drop is
        // cancelled and nothing is sent, the record never saw it. When no op
        // can be made (the client is stopping) the legacy path runs: the
        // reason-5 despawn for an object of ours, the DISABLE event otherwise.
        if (fw::native::world_spawn::cancel_pending_drop(src_refr)) {
            FW_LOG("[pickup] form=0x%X base=0x%X is a drop of ours still falling: taken back, "
                   "the drop never happened", r.item_refr_form_id, r.item_base_id);
        } else {
            const std::uint32_t wid =
                fw::native::world_spawn::wid_for_refr(src_refr, r.item_refr_form_id);
            fw::persist::inventory::StackRecord rec;
            const bool read_ok = fw::persist::inventory::read_refr_record(
                g_module_base.load(std::memory_order_relaxed), src_refr, &rec);
            fw::net::WorldItemOpPayload op{};
            op.kind         = fw::net::kWorldItemPickup;
            op.client_op_id = fw::net::client().begin_world_item_op();
            op.item_base_id = r.item_base_id;
            op.count        = (read_ok && rec.count > 0) ? rec.count
                            : (count > 0 && count < 0x7FFFFFFFu) ? static_cast<std::int32_t>(count)
                            : 1;
            op.item_fp      = read_ok ? fw::persist::instance::fp_of_record(rec, &op.instance)
                                      : fw::net::kFpUnknown;
            op.ref_form_id  = r.item_refr_form_id;
            op.wid          = wid;
            op.cell_id      = r.cell_id;
            op.pos[0] = r.aep.x; op.pos[1] = r.aep.y; op.pos[2] = r.aep.z;
            op.timestamp_ms = static_cast<std::uint64_t>(GetTickCount64());
            const bool sent = op.client_op_id != 0
                           && fw::net::client().submit_world_item_op(op, 0);
            if (sent) {
                fw::native::world_spawn::note_local_pickup(src_refr);
                FW_LOG("[pickup] WORLD_ITEM_OP op_id=%u: %d x 0x%X fp=%016llX form=0x%X wid=%u "
                       "cell=0x%X pos=(%.1f %.1f %.1f) (hook count=%u, instance %s)",
                       op.client_op_id, op.count, op.item_base_id,
                       static_cast<unsigned long long>(op.item_fp), op.ref_form_id, op.wid,
                       op.cell_id, r.aep.x, r.aep.y, r.aep.z, count,
                       read_ok ? "read" : "UNREAD, unknown");
            } else {
                fw::native::world_spawn::on_local_pickup(src_refr);
                fw::net::client().enqueue_actor_event(r.aep);
                FW_LOG("[pickup] WORLD_PICKUP (legacy event, no op could be made) form=0x%X "
                       "base=0x%X cell=0x%X pos=(%.1f %.1f %.1f) count=%u",
                       r.item_refr_form_id, r.item_base_id, r.cell_id,
                       r.aep.x, r.aep.y, r.aep.z, count);
            }
        }
    }

    // ALWAYS call through — trust-client pickup, the local player must
    // still absorb the item on this side.
    if (!g_orig_inv_add) {
        FW_ERR("[pickup] g_orig_inv_add NULL — hook install broken");
        return;
    }
    g_orig_inv_add(dst_actor, src_refr, count);
    FW_DBG("[pickup] g_orig returned");
}

} // namespace

bool install_pickup_hook(std::uintptr_t module_base) {
    g_module_base.store(module_base, std::memory_order_relaxed);
    const auto target_ea = module_base + offsets::INV_ADD_FROM_WORLD_RVA;
    void* target = reinterpret_cast<void*>(target_ea);

    const bool ok = install(
        target,
        reinterpret_cast<void*>(&detour_inv_add_from_world),
        reinterpret_cast<void**>(&g_orig_inv_add));
    if (ok) {
        FW_LOG("[pickup] hook installed at 0x%llX "
               "(sub_140500430 inv-add-from-world @ RVA 0x%lX)",
               static_cast<unsigned long long>(target_ea),
               static_cast<unsigned long>(offsets::INV_ADD_FROM_WORLD_RVA));
    } else {
        FW_ERR("[pickup] hook install FAILED at 0x%llX",
               static_cast<unsigned long long>(target_ea));
    }
    return ok;
}

} // namespace fw::hooks
