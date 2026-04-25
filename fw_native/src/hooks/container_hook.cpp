#include "container_hook.h"

#include <windows.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <unordered_set>
#include <vector>

#include "../engine/engine_calls.h"
#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"
#include "../ref_identity.h"
#include "../net/client.h"
#include "../net/protocol.h"

namespace fw::hooks {

namespace {

using AddObjectFn = void (*)(
    void* dest_this,
    void* bound_obj,
    void* extra_data_sp,   // sp<ExtraDataList>* — opaque to us
    int count,
    void* source_old,
    std::uint32_t reason);

AddObjectFn g_orig_add = nullptr;

std::atomic<std::uint64_t> g_fire_count{0};

// B1.e / B1.h: containers we've already successfully seeded this session.
// Key packs (base_id << 32 | cell_id). The set only grows when a SEND
// happens — a null/empty scan does NOT mark seeded, so we'll try again
// next touch (the engine may have materialized the list by then).
//
// Importantly: the server enforces first-seed-wins (B1.h). Subsequent
// SEEDs for a container the server already knows are REJECTED server-
// side, so even if we re-send after a re-scan, server state is safe.
std::mutex g_seeded_mtx;
std::unordered_set<std::uint64_t> g_seeded_keys;

// Try to scan the container's BGSInventoryList and ship a CONTAINER_SEED.
// Returns nothing; logs its own outcome.
//
// Behavior:
//   - If (base, cell) already in our seeded set: skip entirely.
//   - Scan the runtime list at REFR+0xF8. If null/empty, DON'T mark as
//     seeded (so a later touch, when the list has been materialized, gets
//     another chance to seed).
//   - On non-zero scan: send the seed and mark as seeded.
//
// Note: we no longer "optimistically" insert before sending — that was the
// B1.h pre-fix bug where a pre-PUT empty scan would mark the container as
// seeded forever, so we'd never re-seed after the PUT materialized items.
static void maybe_seed_container(
    void* container_ref, std::uint32_t base_id, std::uint32_t cell_id)
{
    if (!container_ref || base_id == 0 || cell_id == 0) return;
    const std::uint64_t key =
        (static_cast<std::uint64_t>(base_id) << 32) | cell_id;
    {
        std::lock_guard lk(g_seeded_mtx);
        if (g_seeded_keys.count(key)) {
            FW_DBG("[container] seed: already seeded base=0x%X cell=0x%X",
                   base_id, cell_id);
            return;
        }
    }

    // Scan up to N entries. 128 fits nicely in one CONTAINER_SEED chunk
    // (max 87 entries/chunk; scan returns at most MAX). Most containers
    // are <30 items.
    constexpr std::size_t MAX = 128;
    std::uint32_t ids[MAX];
    std::int32_t  cnts[MAX];
    const std::size_t n = fw::engine::scan_container_inventory(
        container_ref, ids, cnts, MAX);
    if (n == 0) {
        // List not materialized or empty. Do NOT mark seeded — retry next
        // touch. Server will lazy-create the container on first TAKE/PUT
        // that reaches it, which is still correct.
        FW_DBG("[container] seed: scan returned 0 entries base=0x%X cell=0x%X "
               "— NOT marking seeded, will retry next touch",
               base_id, cell_id);
        return;
    }

    std::vector<fw::net::ContainerStateEntry> entries(n);
    for (std::size_t i = 0; i < n; ++i) {
        entries[i].container_base_id = base_id;
        entries[i].container_cell_id = cell_id;
        entries[i].item_base_id      = ids[i];
        entries[i].count             = cnts[i];
    }
    fw::net::client().enqueue_container_seed(base_id, cell_id,
                                             entries.data(), entries.size());

    // Only mark seeded AFTER successful send.
    {
        std::lock_guard lk(g_seeded_mtx);
        g_seeded_keys.insert(key);
    }
    FW_LOG("[container] SEED sent base=0x%X cell=0x%X entries=%zu",
           base_id, cell_id, n);
}

// Outcome of the SEH-gated observation phase. Plain-old-data so the caller
// can freely use std::optional / shared_ptr afterward (MSVC disallows C++
// object unwinding in a function that also uses __try — we split them).
struct ObserveResult {
    bool     should_submit;   // true → caller must do the blocking submit
    bool     passthrough;     // true → caller should unconditionally run g_orig
    fw::net::ContainerOpPayload opp;  // populated when should_submit=true
    // Debug-log fields (copied for post-SEH logging at REJ/timeout path)
    std::uint32_t item_id;
    std::uint32_t base_id;
    std::uint32_t cell_id;
    char     op_tag[8];
};

// Pure SEH-guarded observation. Runs with no C++ objects that have
// destructors — so MSVC accepts __try here (POD-only locals, fixed arrays).
static void observe(
    void* dest_this, void* bound_obj, int count, void* source_old,
    ObserveResult* out)
{
    out->should_submit = false;
    out->passthrough   = true;   // safe default
    out->item_id = 0; out->base_id = 0; out->cell_id = 0;
    out->op_tag[0] = '\0';

    __try {
        if (!(count > 0 && bound_obj)) {
            return;  // passthrough=true
        }
        g_fire_count.fetch_add(1, std::memory_order_relaxed);

        const bool dest_is_player   = is_player(dest_this);
        const bool source_is_player = is_player(source_old);

        void* container = nullptr;
        const char* op_tag = nullptr;
        if (dest_is_player && source_old) {
            op_tag = "TAKE"; container = source_old;
        } else if (source_is_player && dest_this) {
            op_tag = "PUT";  container = dest_this;
        } else {
            // Non-player transfer (NPC loot, vendor restock, scripted).
            // We don't mediate these — passthrough with DBG log.
            std::uint32_t iid = 0;
            const auto* base = reinterpret_cast<const std::uint8_t*>(bound_obj);
            __try {
                iid = *reinterpret_cast<const std::uint32_t*>(
                    base + offsets::FORMID_OFF);
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
            FW_DBG("[container] non-player transfer dest=%p source=%p "
                   "item=0x%X count=%d",
                   dest_this, source_old, iid, count);
            return;  // passthrough=true
        }

        // Read item formID
        std::uint32_t item_id = 0;
        const auto* bo = reinterpret_cast<const std::uint8_t*>(bound_obj);
        __try {
            item_id = *reinterpret_cast<const std::uint32_t*>(
                bo + offsets::FORMID_OFF);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}

        // Container identity (form_id, base_id, cell_id)
        const auto cid = read_ref_identity(container);
        if (cid.base_id == 0 || cid.cell_id == 0) {
            FW_WRN("[container] %s but container identity incomplete "
                   "(form=0x%X base=0x%X cell=0x%X) — skipping",
                   op_tag, cid.form_id, cid.base_id, cid.cell_id);
            return;  // passthrough=true
        }

        // Populate output for the submit phase.
        out->should_submit = true;
        out->passthrough   = false;  // caller decides based on ACK
        out->item_id = item_id;
        out->base_id = cid.base_id;
        out->cell_id = cid.cell_id;
        // manual copy of op_tag (no strcpy_s; fixed tiny string)
        out->op_tag[0] = op_tag[0];
        out->op_tag[1] = op_tag[1];
        out->op_tag[2] = op_tag[2];
        out->op_tag[3] = op_tag[3];
        out->op_tag[4] = '\0';

        out->opp.kind = (op_tag[0] == 'T')
            ? static_cast<std::uint32_t>(fw::net::ContainerOpKind::TAKE)
            : static_cast<std::uint32_t>(fw::net::ContainerOpKind::PUT);
        out->opp.container_base_id = cid.base_id;
        out->opp.container_cell_id = cid.cell_id;
        out->opp.item_base_id      = item_id;
        out->opp.count             = count;
        // v5: include sender's form_id for the container REFR so receivers
        // can find their local REFR via lookup_by_form_id + identity check,
        // and invoke engine::apply_container_op_to_engine (B1.g).
        out->opp.container_form_id = cid.form_id;
        // timestamp written in the non-SEH caller (chrono has non-trivial types)

        FW_LOG("[container] %s container form=0x%X base=0x%X cell=0x%X "
               "item=0x%X count=%d",
               op_tag, cid.form_id, cid.base_id, cid.cell_id, item_id, count);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[container] SEH in observation");
        out->should_submit = false;
        out->passthrough   = true;  // let engine proceed — don't block on our bug
    }
}

void __fastcall detour_add_object(
    void* dest_this,
    void* bound_obj,
    void* extra_data_sp,
    int count,
    void* source_old,
    std::uint32_t reason)
{
    // B1.h.2 DIAGNOSTIC TRACE. We log at DEBUG level the full decision
    // tree so we can diagnose bugs like "PUT-then-TAKE sparisce": each
    // TAKE/PUT produces a paper trail showing whether observe classified
    // the op, whether the submit went through, whether g_orig_add was
    // actually called, and whether it returned. Toggle log_level=debug
    // in fw_config.ini to see the full trace.
    FW_DBG("[container] ENTRY dest=%p bound=%p count=%d source=%p reason=%u",
           dest_this, bound_obj, count, source_old, reason);

    // B1.g feedback-loop guard. If this vt[0x7A] invocation is a side-
    // effect of us applying a remote peer's op (inside apply_container_
    // op_to_engine), bypass the observe/submit path entirely — we MUST
    // NOT re-emit this to the network as a fresh CONTAINER_OP.
    // Fall through to g_orig_add so the engine's internal call still
    // completes normally (if anything downstream expects it).
    if (tls_applying_remote) {
        FW_DBG("[container] tls_applying_remote=true — passthrough "
               "(dest=%p bound=%p count=%d source=%p)",
               dest_this, bound_obj, count, source_old);
        if (g_orig_add) {
            g_orig_add(dest_this, bound_obj, extra_data_sp, count, source_old, reason);
        }
        return;
    }

    ObserveResult r{};
    observe(dest_this, bound_obj, count, source_old, &r);

    FW_DBG("[container] OBSERVE done should_submit=%d passthrough=%d "
           "op_tag='%s' item=0x%X base=0x%X cell=0x%X",
           int(r.should_submit), int(r.passthrough),
           r.op_tag, r.item_id, r.base_id, r.cell_id);

    if (r.should_submit) {
        // B1.e: seed the container's ground truth before asking server to
        // validate. maybe_seed_container is idempotent (tracked via
        // g_seeded_keys) and now correctly skips marking seeded if the
        // scan returned 0 entries (B1.h fix) so a later touch retries.
        //
        // Direction picks the correct REFR: on TAKE source_old is the
        // container; on PUT dest_this is.
        void* container = (r.opp.kind ==
            static_cast<std::uint32_t>(fw::net::ContainerOpKind::TAKE))
                ? source_old
                : dest_this;

        // B1.j.1: force-materialize the runtime BGSInventoryList BEFORE
        // scanning. The engine normally lazy-materializes it inside
        // sub_140502940 (AddObject worker) via vtable[167], but that
        // fires AFTER g_orig_add — too late for our pre-op scan. If we
        // skip this, scan sees null/partial list → incomplete SEED →
        // subsequent TAKEs rejected with INSUFFICIENT_ITEMS (live bug
        // diagnosed 2026-04-20). Idempotent: skips if list already
        // present.
        const bool mat_ok = fw::engine::force_materialize_inventory(container);
        FW_DBG("[container] pre-scan materialize: %s",
               mat_ok ? "ok (list populated)" : "skipped / failed");

        maybe_seed_container(container, r.base_id, r.cell_id);

        // Fill the clock outside the SEH (chrono has non-trivial types).
        using namespace std::chrono;
        r.opp.timestamp_ms = duration_cast<milliseconds>(
            system_clock::now().time_since_epoch()).count();

        // B1.d: blocking pre-mutation submit. Wait up to 100ms for verdict.
        //   ACCEPTED  → proceed (g_orig_add below)
        //   REJ_*     → return (mutation blocked)
        //   timeout   → return conservative (server dead / disconnected)
        FW_DBG("[container] SUBMIT kind=%u container=0x%X/0x%X item=0x%X count=%d",
               r.opp.kind, r.base_id, r.cell_id, r.item_id, count);
        auto ack_opt = fw::net::client().submit_container_op_blocking(r.opp, 100);
        if (!ack_opt) {
            FW_WRN("[container] %s BLOCKED — no verdict from server "
                   "(timeout/disconnect) container=0x%X/0x%X item=0x%X count=%d",
                   r.op_tag, r.base_id, r.cell_id, r.item_id, count);
            return;  // skip g_orig_add
        }
        const auto& ack = *ack_opt;
        FW_DBG("[container] ACK op_id=%u status=%u final_count=%d",
               ack.client_op_id, ack.status, ack.final_count);
        if (ack.status == static_cast<std::uint8_t>(
                fw::net::ContainerOpAckStatus::ACCEPTED))
        {
            FW_LOG("[container] %s ACCEPTED final=%d (op_id=%u) — "
                   "calling g_orig_add",
                   r.op_tag, ack.final_count, ack.client_op_id);
            // fall through to g_orig_add
        } else {
            FW_WRN("[container] %s REJECTED status=%u final=%d (op_id=%u) "
                   "container=0x%X/0x%X item=0x%X count=%d — MUTATION BLOCKED",
                   r.op_tag, ack.status, ack.final_count, ack.client_op_id,
                   r.base_id, r.cell_id, r.item_id, count);
            return;  // skip g_orig_add — the dup close
        }
    } else if (!r.passthrough) {
        // should_submit=false AND passthrough=false means observe set an
        // error state; don't run the engine in that case.
        FW_WRN("[container] observe error state — skipping g_orig_add");
        return;
    }

    // ACCEPTED or passthrough: run the original engine code.
    if (!g_orig_add) {
        FW_ERR("[container] g_orig_add is NULL — mutation WILL NOT happen, "
               "hook install was broken");
        return;
    }
    FW_DBG("[container] calling g_orig_add(dest=%p, bound=%p, count=%d, "
           "source=%p, reason=%u)",
           dest_this, bound_obj, count, source_old, reason);
    g_orig_add(dest_this, bound_obj, extra_data_sp, count, source_old, reason);
    FW_DBG("[container] g_orig_add returned");
}

} // namespace

// B1.g / B1.k.2 feedback-loop guard. When we apply a remote peer's op via
// engine::apply_container_op_to_engine (real AddItem/RemoveItem), or when
// the engine may otherwise re-enter our hooked functions as a side-effect
// of our own call, we flip this flag. Both container_hook's vt[0x7A]
// detour AND put_hook's ContainerMenu::TransferItem detour check it on
// entry and take the passthrough branch (run g_orig only, no submit).
//
// Thread-local because:
//   - The client net thread does the apply in its CONTAINER_BCAST handler.
//   - Engine calls downstream are synchronous on the same thread.
//   - Cross-thread atomics would race; TLS is the right scope.
//
// NOTE: definition is at non-anonymous namespace scope so put_hook.cpp
// can see the same storage via the extern declaration in container_hook.h.
thread_local bool tls_applying_remote = false;

// B1.g / B1.k.2 feedback-loop guard — RAII.
ApplyingRemoteGuard::ApplyingRemoteGuard() {
    tls_applying_remote = true;
}
ApplyingRemoteGuard::~ApplyingRemoteGuard() {
    tls_applying_remote = false;
}

bool install_container_hook(std::uintptr_t module_base) {
    // Resolve the virtual slot: vtable is at fixed RVA, slot index 0x7A,
    // 8 bytes per entry on x64 → vtable[0x7A * 8] = the function pointer.
    const auto vtable_addr = module_base + offsets::TESOBJECTREFR_VTABLE_RVA;
    void** vtable = reinterpret_cast<void**>(vtable_addr);

    void* target = nullptr;
    __try {
        target = vtable[offsets::VT_ADD_TO_CONTAINER_SLOT];
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[container] vtable read at 0x%llX failed",
               static_cast<unsigned long long>(vtable_addr));
        return false;
    }

    if (!target) {
        FW_ERR("[container] vtable[0x%zX] is null", offsets::VT_ADD_TO_CONTAINER_SLOT);
        return false;
    }

    const bool ok = install(
        target,
        reinterpret_cast<void*>(&detour_add_object),
        reinterpret_cast<void**>(&g_orig_add));
    if (ok) {
        FW_LOG("[container] hook installed at 0x%llX (vt[0x%zX] of REFR vtable @ RVA 0x%lX)",
               static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(target)),
               offsets::VT_ADD_TO_CONTAINER_SLOT,
               static_cast<unsigned long>(offsets::TESOBJECTREFR_VTABLE_RVA));
    }
    return ok;
}

} // namespace fw::hooks
