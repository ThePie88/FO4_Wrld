#include "put_hook.h"

#include <windows.h>
#include <atomic>
#include <chrono>
#include <cstdint>

#include "container_hook.h"   // extern tls_applying_remote + ApplyingRemoteGuard
#include "../engine/engine_calls.h"
#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"
#include "../ref_identity.h"
#include "../net/client.h"
#include "../net/protocol.h"

namespace fw::hooks {

namespace {

// ContainerMenu::TransferItem signature (vt[21] of ContainerMenu vtable).
//   this      : ContainerMenu*
//   inv_idx   : index into the menu's inventory entry array
//   count     : number of items to transfer
//   side      : 1 = DEPOSIT (player→container), 0 = WITHDRAW (container→player)
using TransferItemFn = std::int64_t (*)(void* this_menu,
                                         std::int32_t inv_idx,
                                         std::uint32_t count,
                                         std::uint8_t side);

TransferItemFn g_orig_transfer = nullptr;

std::atomic<std::uint64_t> g_fire_count{0};

// POD-only observation result (so SEH works without C++ unwinding).
struct PutObserveResult {
    bool should_submit;     // true → caller runs blocking submit
    bool passthrough;       // true → caller runs g_orig unconditionally
    fw::net::ContainerOpPayload opp;
    // Debug copy fields for post-SEH logging:
    std::uint32_t item_id;
    std::uint32_t base_id;
    std::uint32_t cell_id;
    std::uint32_t container_form_id;
};

// Observe: extract (container REFR, item form_id, count) from the menu state.
// Runs SEH-caged on the hot path — all raw memory reads through __try/__except
// so a bad pointer doesn't crash the game.
static void observe_transfer(
    void* this_menu, std::int32_t inv_idx, std::uint32_t count,
    std::uint8_t side, PutObserveResult* out)
{
    out->should_submit = false;
    out->passthrough   = true;
    out->item_id = 0; out->base_id = 0; out->cell_id = 0;
    out->container_form_id = 0;

    __try {
        // Sanity.
        if (!this_menu) return;
        if (count == 0) return;

        g_fire_count.fetch_add(1, std::memory_order_relaxed);

        // B1.k.3 CORRECTED: live log proved side=1 is WITHDRAW (container→
        // player), side=0 is DEPOSIT (player→container). Agent summary had
        // these swapped. See offsets.h CMENU_SIDE_* comments.
        //
        // WITHDRAW is already captured by the vt[0x7A] AddObjectToContainer
        // detour (dest=player, source=container). We only capture DEPOSIT
        // here to avoid double-sending.
        if (side != offsets::CMENU_SIDE_DEPOSIT) {
            FW_DBG("[put] WITHDRAW direction (side=%u) — ignored "
                   "(vt[0x7A] handles it) this=%p idx=%d cnt=%u",
                   side, this_menu, inv_idx, count);
            return;
        }

        const auto* this_bytes = reinterpret_cast<const std::uint8_t*>(this_menu);

        // Validate index against the PLAYER array count (DEPOSIT source).
        const std::uint32_t player_count = *reinterpret_cast<const std::uint32_t*>(
            this_bytes + offsets::CMENU_PLAYER_COUNT_OFF);
        if (inv_idx < 0 || static_cast<std::uint32_t>(inv_idx) >= player_count) {
            FW_WRN("[put] DEPOSIT inv_idx out of range (idx=%d player_count=%u)",
                   inv_idx, player_count);
            return;
        }

        // Fetch player-side array base pointer (the DEPOSIT source rows).
        void* player_array = *reinterpret_cast<void* const*>(
            this_bytes + offsets::CMENU_PLAYER_ARRAY_OFF);
        if (!player_array) {
            FW_WRN("[put] player_array ptr is null — skipping");
            return;
        }

        // Locate entry in the array: base + inv_idx * 32. The entry is an
        // opaque 32-byte struct; its first qword is NOT a direct TESForm
        // pointer (that's what caused all B1.k.2 tests to log
        // "item form_id unreadable"). We need the engine's decoder.
        void* entry = reinterpret_cast<std::uint8_t*>(player_array)
                      + static_cast<std::size_t>(inv_idx)
                        * offsets::CMENU_ENTRY_STRIDE;

        // Decode entry → something (wrapper struct / TESForm / TESObjectREFR)
        // via sub_1403478E0. The return type depends on item kind:
        //   - Regular MISC/WEAP/ARMO template → wrapper with TESBoundObject*
        //     at offset 0; form_id is at *(wrapper) + 0x14.
        //   - Persistent unique REFR (e.g. wedding ring) → the REFR directly;
        //     form_id at +0x14 is the REFR's own id (runtime-unstable across
        //     saves); we want to resolve to its BASE form at +0xE0.
        //
        // B1.k.3 live test (coffee) showed direct +0x14 read returned 0, so
        // we cascade: (1) direct, (2) single deref, (3) if result looks
        // like a REFR, fetch baseForm. Each step is SEH-caged.
        void* raw = fw::engine::resolve_inventory_entry_form(entry);
        if (!raw) {
            FW_WRN("[put] DEPOSIT entry[%d]: resolve_inventory_entry_form "
                   "returned null (entry=%p) — skipping",
                   inv_idx, entry);
            return;
        }

        std::uint32_t item_id = 0;
        void*         resolved_form = nullptr;  // final TESForm we'll emit

        // B1.k.3.3 (2026-04-21 live log proof): sub_1403478E0 returns a
        // wrapper struct whose first qword is the actual TESForm*. The
        // wrapper's own +0x14 field is a CONSTANT type tag (always 0x2A9
        // in observed data), not the form_id. Direct-read is garbage.
        // Previous attempts ("direct then deref", "try direct, fallback
        // deref") were both wrong — direct's 0x2A9 passed validation and
        // got used, producing bogus op payloads.
        //
        // Correct policy: **always deref first**. Use direct only as a
        // last-resort fallback (for the theoretical case where the
        // decoder returns a TESForm directly without wrapper).
        //
        // FormType validation is tightened to ft < 0x80. FO4 next-gen
        // form types don't exceed ~0x7F in practice, and the observed
        // wrapper's tag (0xA0) is outside this range.
        auto is_valid_formtype = [](std::uint8_t ft) {
            return ft >= 1 && ft < 0x80;
        };
        __try {
            const auto* rb = reinterpret_cast<const std::uint8_t*>(raw);
            const std::uint8_t  ft_direct = *(rb + offsets::FORMTYPE_OFF);
            const std::uint32_t id_direct = *reinterpret_cast<const std::uint32_t*>(
                rb + offsets::FORMID_OFF);

            void* deref = *reinterpret_cast<void* const*>(raw);
            std::uint8_t  ft_deref = 0;
            std::uint32_t id_deref = 0;
            if (deref) {
                const auto* db = reinterpret_cast<const std::uint8_t*>(deref);
                ft_deref = *(db + offsets::FORMTYPE_OFF);
                id_deref = *reinterpret_cast<const std::uint32_t*>(
                    db + offsets::FORMID_OFF);
            }

            FW_DBG("[put] entry[%d] decode: raw=%p direct(id=0x%X ft=0x%X) "
                   "deref=%p deref(id=0x%X ft=0x%X)",
                   inv_idx, raw, id_direct, ft_direct,
                   deref, id_deref, ft_deref);

            // DEREF FIRST (observed: always wrapper → dereference required).
            if (deref && is_valid_formtype(ft_deref)
                && id_deref != 0 && id_deref != 0xFFFFFFFFu)
            {
                item_id = id_deref;
                resolved_form = deref;
            }
            // Fallback only (unlikely to ever fire in practice).
            else if (is_valid_formtype(ft_direct)
                     && id_direct != 0 && id_direct != 0xFFFFFFFFu)
            {
                item_id = id_direct;
                resolved_form = raw;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            FW_WRN("[put] DEPOSIT entry[%d]: SEH while extracting form_id "
                   "(raw=%p) — skipping", inv_idx, raw);
            return;
        }

        if (item_id == 0) {
            FW_WRN("[put] DEPOSIT entry[%d]: could not extract form_id from "
                   "raw=%p (tried direct+deref, both 0) — skipping",
                   inv_idx, raw);
            return;
        }

        // If the resolved form looks like a TESObjectREFR (persistent unique
        // item e.g. wedding ring), the form_id we got is runtime-unstable.
        // Swap to the REFR's baseForm at +0xE0 so receivers can lookup via
        // the ESM-stable template id.
        __try {
            const std::uint8_t formtype = *reinterpret_cast<const std::uint8_t*>(
                reinterpret_cast<const std::uint8_t*>(resolved_form)
                + offsets::FORMTYPE_OFF);
            // formType 0x3F = kTESObjectREFR in FO4 next-gen (best known).
            // If the resolved form is a REFR, pivot to its base.
            if (formtype == 0x3F) {
                void* base = *reinterpret_cast<void* const*>(
                    reinterpret_cast<const std::uint8_t*>(resolved_form)
                    + offsets::BASE_FORM_OFF);
                if (base) {
                    const std::uint32_t base_id = *reinterpret_cast<const std::uint32_t*>(
                        reinterpret_cast<const std::uint8_t*>(base)
                        + offsets::FORMID_OFF);
                    if (base_id != 0 && base_id != 0xFFFFFFFFu) {
                        FW_DBG("[put] DEPOSIT entry[%d]: REFR 0x%X → baseForm 0x%X",
                               inv_idx, item_id, base_id);
                        item_id = base_id;
                    }
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // Non-fatal — keep the original item_id.
            FW_DBG("[put] DEPOSIT entry[%d]: SEH in REFR→base pivot, "
                   "keeping item_id=0x%X", inv_idx, item_id);
        }

        // Resolve container REFR from the handle at this+1064.
        // We pass a pointer INTO the menu struct; the engine's resolver
        // increments a refcount internally and writes the REFR* to *out.
        void* container_handle_slot = const_cast<std::uint8_t*>(
            this_bytes + offsets::CMENU_CONTAINER_HANDLE_OFF);
        void* container_refr = fw::engine::resolve_refhandle(container_handle_slot);
        if (!container_refr) {
            FW_WRN("[put] container handle at this+%zu resolved to null "
                   "(stale handle? menu state weird?) — skipping",
                   offsets::CMENU_CONTAINER_HANDLE_OFF);
            return;
        }

        // Container identity (form_id, base_id, cell_id).
        const auto cid = fw::read_ref_identity(container_refr);
        if (cid.base_id == 0 || cid.cell_id == 0) {
            FW_WRN("[put] container identity incomplete "
                   "(form=0x%X base=0x%X cell=0x%X item=0x%X) — skipping",
                   cid.form_id, cid.base_id, cid.cell_id, item_id);
            return;
        }

        // Populate output payload.
        out->should_submit = true;
        out->passthrough   = false;   // caller gates on ACK
        out->item_id = item_id;
        out->base_id = cid.base_id;
        out->cell_id = cid.cell_id;
        out->container_form_id = cid.form_id;

        out->opp.kind              = static_cast<std::uint32_t>(
            fw::net::ContainerOpKind::PUT);
        out->opp.container_base_id = cid.base_id;
        out->opp.container_cell_id = cid.cell_id;
        out->opp.item_base_id      = item_id;
        out->opp.count             = static_cast<std::int32_t>(count);
        // timestamp written in non-SEH caller
        out->opp.container_form_id = cid.form_id;

        FW_LOG("[put] PUT container form=0x%X base=0x%X cell=0x%X "
               "item=0x%X count=%u (idx=%d this=%p)",
               cid.form_id, cid.base_id, cid.cell_id,
               item_id, count, inv_idx, this_menu);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[put] SEH in observation");
        out->should_submit = false;
        out->passthrough   = true;
    }
}

std::int64_t __fastcall detour_transfer_item(
    void* this_menu,
    std::int32_t inv_idx,
    std::uint32_t count,
    std::uint8_t side)
{
    FW_DBG("[put] ENTRY this=%p idx=%d cnt=%u side=%u",
           this_menu, inv_idx, count, side);

    // Feedback-loop guard: if WE triggered this (unlikely for TransferItem
    // since engine AddItem doesn't route through the UI, but defensive) —
    // skip observation and just run the original.
    if (tls_applying_remote) {
        FW_DBG("[put] tls_applying_remote=true — passthrough");
        if (g_orig_transfer) {
            return g_orig_transfer(this_menu, inv_idx, count, side);
        }
        return 0;
    }

    PutObserveResult r{};
    observe_transfer(this_menu, inv_idx, count, side, &r);

    FW_DBG("[put] OBSERVE done should_submit=%d passthrough=%d "
           "item=0x%X base=0x%X cell=0x%X cfid=0x%X",
           int(r.should_submit), int(r.passthrough),
           r.item_id, r.base_id, r.cell_id, r.container_form_id);

    if (r.should_submit) {
        using namespace std::chrono;
        r.opp.timestamp_ms = duration_cast<milliseconds>(
            system_clock::now().time_since_epoch()).count();

        FW_DBG("[put] SUBMIT kind=2(PUT) container=0x%X/0x%X item=0x%X count=%d",
               r.base_id, r.cell_id, r.item_id, r.opp.count);
        auto ack_opt = fw::net::client().submit_container_op_blocking(r.opp, 100);
        if (!ack_opt) {
            FW_WRN("[put] PUT BLOCKED — no verdict from server (timeout/disconnect) "
                   "container=0x%X/0x%X item=0x%X count=%d",
                   r.base_id, r.cell_id, r.item_id, r.opp.count);
            return 0;
        }
        const auto& ack = *ack_opt;
        FW_DBG("[put] ACK op_id=%u status=%u final_count=%d",
               ack.client_op_id, ack.status, ack.final_count);
        if (ack.status == static_cast<std::uint8_t>(
                fw::net::ContainerOpAckStatus::ACCEPTED))
        {
            FW_LOG("[put] PUT ACCEPTED final=%d (op_id=%u) — calling g_orig",
                   ack.final_count, ack.client_op_id);
            // fall through
        } else {
            FW_WRN("[put] PUT REJECTED status=%u final=%d (op_id=%u) "
                   "container=0x%X/0x%X item=0x%X count=%d — MUTATION BLOCKED",
                   ack.status, ack.final_count, ack.client_op_id,
                   r.base_id, r.cell_id, r.item_id, r.opp.count);
            return 0;
        }
    } else if (!r.passthrough) {
        FW_WRN("[put] observe error state — skipping g_orig_transfer");
        return 0;
    }

    if (!g_orig_transfer) {
        FW_ERR("[put] g_orig_transfer NULL — mutation WILL NOT happen, "
               "hook install was broken");
        return 0;
    }
    FW_DBG("[put] calling g_orig_transfer(this=%p, idx=%d, cnt=%u, side=%u)",
           this_menu, inv_idx, count, side);
    const auto rc = g_orig_transfer(this_menu, inv_idx, count, side);
    FW_DBG("[put] g_orig_transfer returned %lld",
           static_cast<long long>(rc));
    return rc;
}

} // namespace

bool install_put_hook(std::uintptr_t module_base) {
    const auto target_ea = module_base + offsets::CONTAINER_MENU_TRANSFER_ITEM_RVA;
    void* target = reinterpret_cast<void*>(target_ea);

    const bool ok = install(
        target,
        reinterpret_cast<void*>(&detour_transfer_item),
        reinterpret_cast<void**>(&g_orig_transfer));
    if (ok) {
        FW_LOG("[put] hook installed at 0x%llX "
               "(ContainerMenu::TransferItem = sub_14103E950 @ RVA 0x%lX)",
               static_cast<unsigned long long>(target_ea),
               static_cast<unsigned long>(offsets::CONTAINER_MENU_TRANSFER_ITEM_RVA));
    } else {
        FW_ERR("[put] hook install FAILED at 0x%llX",
               static_cast<unsigned long long>(target_ea));
    }
    return ok;
}

} // namespace fw::hooks
