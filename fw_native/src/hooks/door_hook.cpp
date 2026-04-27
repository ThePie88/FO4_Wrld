#include "door_hook.h"

#include <windows.h>
#include <atomic>
#include <chrono>
#include <cstdint>

#include "container_hook.h"      // tls_applying_remote (feedback-loop guard)
#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"
#include "../ref_identity.h"
#include "../net/client.h"

namespace fw::hooks {

namespace {

// Engine Activate worker = sub_140514180 (validated phase 1.b: fires
// 1× per E keypress, no save-load noise, supports 2 distinct REFRs).
//
// Signature inferred from Papyrus SetOpen callsite + observed args:
//   char sub_140514180(REFR* refr, REFR* activator,
//                      void* a3, void* a4, void* a5, void* a6, void* a7);
// Args 5-7 in our phase 1.b log were stack-residue (e.g. arg6 was the
// FO4 image base 0x7FF600000000 — clearly noise, not a real arg). Real
// arg count is 4; we keep 7 in the signature so the trampoline frame
// matches the original calling convention and stack cleanup is correct.
using ActivateWorkerFn = char (*)(void* refr, void* activator,
                                  void* a3, void* a4,
                                  void* a5, void* a6, void* a7);

ActivateWorkerFn g_orig_activate = nullptr;

// Form-type filter: Activate worker fires for ALL Activate dispatches
// (terminals, NPCs, switches, levers, weapons-on-ground, etc). For door
// sync we only want the door-like form types observed during phase 1.b
// + Agent A's enumeration:
//   0x1F = TESObjectDOOR (cell-transition doors)
//   0x20 = TESObjectACTI activator-style door (most house doors in
//          Sanctuary — confirmed empirically)
//   0x24 = TESObjectACTI explicit
//   0x29 = TESObjectDOOR alt
// Other form types are dropped silently (no broadcast).
//
// We keep this LIBERAL during phase 2 testing — if non-door fires leak
// through, we'll see them in the log and tighten the filter post-hoc.
constexpr bool is_door_like_formtype(std::uint8_t ftype) {
    return ftype == 0x1F || ftype == 0x20 || ftype == 0x24 || ftype == 0x29;
}

// Monotonic fire counter for diagnostics + matching tx ↔ rx in the log.
std::atomic<std::uint64_t> g_fire_count{0};

struct DoorObserveResult {
    std::uint32_t form_id;
    std::uint32_t base_id;
    std::uint32_t cell_id;
    std::uint8_t  form_type;
    bool          door_like;
    bool          identity_ok;
};

static void observe_target(void* refr, DoorObserveResult* out) {
    out->form_id = 0;
    out->base_id = 0;
    out->cell_id = 0;
    out->form_type = 0xFF;
    out->door_like = false;
    out->identity_ok = false;

    __try {
        if (!refr) return;

        const auto cid = read_ref_identity(refr);
        out->form_id = cid.form_id;
        out->base_id = cid.base_id;
        out->cell_id = cid.cell_id;
        out->identity_ok = (cid.base_id != 0 && cid.cell_id != 0);

        const auto* refr_bytes = reinterpret_cast<const std::uint8_t*>(refr);
        void* base_form = *reinterpret_cast<void* const*>(
            refr_bytes + offsets::BASE_FORM_OFF);
        if (base_form) {
            out->form_type = *reinterpret_cast<const std::uint8_t*>(
                reinterpret_cast<const std::uint8_t*>(base_form)
                + offsets::FORMTYPE_OFF);
            out->door_like = is_door_like_formtype(out->form_type);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

char __fastcall detour_activate_worker(void* refr,
                                       void* activator, void* a3, void* a4,
                                       void* a5, void* a6, void* a7)
{
    const auto fire = g_fire_count.fetch_add(1, std::memory_order_relaxed) + 1;

    // B6.1 feedback-loop guard: when the local main thread is mid-apply
    // of a remote DOOR_BCAST (drain_door_apply_queue calls Activate
    // worker which lands here), tls_applying_remote is true and we MUST
    // skip broadcast — otherwise A's open propagates back to A as a
    // fresh DOOR_OP, ping-pong forever.
    if (tls_applying_remote) {
        FW_DBG("[door-act] FIRE #%llu — applying_remote, passthrough",
               static_cast<unsigned long long>(fire));
        if (g_orig_activate) {
            return g_orig_activate(refr, activator, a3, a4, a5, a6, a7);
        }
        return 0;
    }

    DoorObserveResult r{};
    observe_target(refr, &r);

    if (!r.identity_ok || !r.door_like) {
        // Activate fired for a non-door (terminal, NPC, switch, etc).
        // Drop silently — but log at DEBUG so we can see what fires
        // unexpectedly. Pass-through to engine unchanged.
        FW_DBG("[door-act] FIRE #%llu skip (id_ok=%d door_like=%d ftype=0x%X)",
               static_cast<unsigned long long>(fire),
               int(r.identity_ok), int(r.door_like), r.form_type);
        if (g_orig_activate) {
            return g_orig_activate(refr, activator, a3, a4, a5, a6, a7);
        }
        return 0;
    }

    // Door-like activation by local player. Broadcast to peers.
    using namespace std::chrono;
    const std::uint64_t ts_ms = duration_cast<milliseconds>(
        system_clock::now().time_since_epoch()).count();

    fw::net::client().enqueue_door_op(r.form_id, r.base_id, r.cell_id, ts_ms);

    FW_LOG("[door-act] FIRE #%llu BROADCAST form=0x%X base=0x%X cell=0x%X "
           "ftype=0x%X ts=%llu",
           static_cast<unsigned long long>(fire),
           r.form_id, r.base_id, r.cell_id, r.form_type,
           static_cast<unsigned long long>(ts_ms));

    if (g_orig_activate) {
        return g_orig_activate(refr, activator, a3, a4, a5, a6, a7);
    }
    FW_ERR("[door-act] g_orig_activate NULL — engine call dropped");
    return 0;
}

} // namespace

bool install_door_hook(std::uintptr_t module_base) {
    const auto target_ea = module_base + offsets::ENGINE_ACTIVATE_WORKER_RVA;
    void* target = reinterpret_cast<void*>(target_ea);

    const bool ok = install(
        target,
        reinterpret_cast<void*>(&detour_activate_worker),
        reinterpret_cast<void**>(&g_orig_activate));
    if (ok) {
        FW_LOG("[door-act] hook installed at 0x%llX "
               "(Activate worker = sub_140514180 @ RVA 0x%lX) — "
               "phase 2 BROADCAST",
               static_cast<unsigned long long>(target_ea),
               static_cast<unsigned long>(offsets::ENGINE_ACTIVATE_WORKER_RVA));
    } else {
        FW_ERR("[door-act] hook install FAILED at 0x%llX",
               static_cast<unsigned long long>(target_ea));
    }
    return ok;
}

} // namespace fw::hooks
