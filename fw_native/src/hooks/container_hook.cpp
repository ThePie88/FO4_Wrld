#include "container_hook.h"

#include <windows.h>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <vector>

#include "../engine/engine_calls.h"
#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"
#include "../ref_identity.h"
#include "../native/world_spawn.h"
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

// B1.e / B1.h: scan the container's BGSInventoryList and ship a
// CONTAINER_SEED, the server's first full view of it. Returns nothing; logs
// its own outcome.
//
// Who is seeded (loot rework L3, 2026-09-24): a container the server does
// NOT know. The client's mirror says whether it does, fed by the bootstrap
// and by the live push the server sends whenever a record is created,
// replaced or refilled; a seed the server rejects (it knew the container
// first) is answered with its view, so the mirror learns it either way.
// Until the answer lands, `seed_in_flight` keeps one seed per container per
// session. Before L3 a process-lifetime set did this job and a server that
// had lost its state was never seeded again by a running client.
//
// Behavior:
//   - Materialize the runtime list first (B1.j.1): the engine normally does
//     it inside the AddObject worker, AFTER this detour, and a null list
//     scans as empty -> incomplete SEED -> every later take rejected with
//     INSUFFICIENT_ITEMS (live bug diagnosed 2026-04-20). Idempotent.
//   - Scan the runtime list at REFR+0xF8. If the list could not be built,
//     or the walk faulted, DON'T mark as in flight (so a later touch, when
//     the list exists, gets another chance to seed).
//   - A list that is present and holds nothing is sent as the sentinel
//     entry (item 0, count 0): the server records a known-empty container
//     (loot rework L3.4, 2026-09-24). Until then the deposit into an empty
//     container the server did not know made a partial record.
//   - On non-zero scan: send the seed and mark it in flight.
//
// Called from the take detour (vt[0x7A]) and, since 2026-09-24, from the
// deposit detour (ContainerMenu::TransferItem), both BEFORE the engine
// moves anything: the scan is the pre-op ground truth and the server
// applies the op that follows on top of it.
//
// Note: we no longer "optimistically" insert before sending — that was the
// B1.h pre-fix bug where a pre-PUT empty scan would mark the container as
// seeded forever, so we'd never re-seed after the PUT materialized items.
void seed_container_impl(
    void* container_ref, std::uint32_t form_id,
    std::uint32_t base_id, std::uint32_t cell_id)
{
    if (!container_ref || form_id == 0 || base_id == 0 || cell_id == 0) return;
    auto& c = fw::net::client();
    if (c.container_known(form_id)) {
        FW_DBG("[container] seed: the server knows form=0x%X, no seed", form_id);
        return;
    }
    if (c.seed_in_flight(form_id, /*mark=*/false)) {
        FW_DBG("[container] seed: already sent this session for form=0x%X", form_id);
        return;
    }
    const bool mat_ok = fw::engine::force_materialize_inventory(container_ref);
    FW_DBG("[container] pre-scan materialize: %s",
           mat_ok ? "ok (list populated)" : "skipped / failed");

    // Scan up to N entries. 128 spans two CONTAINER_SEED chunks at most
    // (69 entries/chunk since v27; scan returns at most MAX). Most
    // containers are <30 items.
    constexpr std::size_t MAX = 128;
    std::uint32_t ids[MAX];
    std::int32_t  cnts[MAX];
    bool faulted = false;
    const std::size_t n = fw::engine::scan_container_inventory(
        container_ref, ids, cnts, MAX, &faulted);
    if (n == 0) {
        if (!mat_ok || faulted || !fw::engine::inventory_list_present(container_ref)) {
            // No list to scan, or a walk that faulted: unknown, not empty.
            // Not marked, the next touch retries; the server lazy-creates a
            // partial record from the op that follows.
            FW_DBG("[container] seed: nothing scanned for form=0x%X "
                   "(base=0x%X cell=0x%X, list %s, walk %s) — not marked, the "
                   "next touch retries",
                   form_id, base_id, cell_id,
                   mat_ok ? "present" : "absent", faulted ? "faulted" : "clean");
            return;
        }
        // The list exists and holds nothing: a known-empty container. The
        // sentinel is the same shape CONTAINER_STATE uses for one.
        fw::net::ContainerStateEntry sentinel{};
        sentinel.container_form_id = form_id;
        sentinel.container_base_id = base_id;
        sentinel.container_cell_id = cell_id;
        sentinel.item_base_id      = 0;
        sentinel.count             = 0;
        c.enqueue_container_seed(form_id, base_id, cell_id, &sentinel, 1);
        (void)c.seed_in_flight(form_id, /*mark=*/true);
        FW_LOG("[container] SEED sent form=0x%X (base=0x%X cell=0x%X): known "
               "empty (sentinel)", form_id, base_id, cell_id);
        return;
    }

    std::vector<fw::net::ContainerStateEntry> entries(n);
    for (std::size_t i = 0; i < n; ++i) {
        entries[i].container_form_id = form_id;
        entries[i].container_base_id = base_id;
        entries[i].container_cell_id = cell_id;
        entries[i].item_base_id      = ids[i];
        entries[i].count             = cnts[i];
    }
    c.enqueue_container_seed(form_id, base_id, cell_id,
                             entries.data(), entries.size());

    // Only mark in flight AFTER the send.
    (void)c.seed_in_flight(form_id, /*mark=*/true);
    FW_LOG("[container] SEED sent form=0x%X (base=0x%X cell=0x%X) entries=%zu",
           form_id, base_id, cell_id, n);
}

// Outcome of the SEH-gated observation phase. Plain-old-data so the caller
// can freely use std::optional / shared_ptr afterward (MSVC disallows C++
// object unwinding in a function that also uses __try — we split them).
struct ObserveResult {
    bool     should_submit;   // true → caller sends the op after g_orig ran
    bool     passthrough;     // true → caller should unconditionally run g_orig
    fw::net::ContainerOpPayload opp;  // populated when should_submit=true
    // Debug-log fields (copied for post-SEH logging at REJ/timeout path)
    std::uint32_t item_id;
    std::uint32_t base_id;
    std::uint32_t cell_id;
    char     op_tag[8];
    // v23 — set when the container is a PA frame (loot-exempt): after
    // g_orig runs, the caller rescans and ships the frame's full state.
    void*         pa_frame_ref;
    std::uint32_t pa_frame_fid;
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
    out->pa_frame_ref = nullptr; out->pa_frame_fid = 0;

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
        // ====================================================================
        // 2026-08-16 — THE POWER-ARMOR FRAME IS NOT LOOT. Measured cost of
        // treating it as one: the engine's own enter transfer drains the
        // frame's pieces through this vt[0x7A] path, so each piece became a
        // TAKE op keyed (0x2079E, cell). Cycle 1 seeded the key and took all
        // six -> server state for that key = EMPTY. Re-entering in the SAME
        // cell later made the server reject every take (status=5) and the
        // block left the native transfer half-done: pieces out of the frame,
        // never on the actor — DESTROYED. Six X-01 pieces lost live at
        // 14:31:25, and the previous session's loss was the same mechanism
        // (the core survived because enter never takes it). The exit's
        // deposit does NOT route through this hook, so the server key could
        // never refill — every re-enter in a seeded cell was a death
        // sentence.
        //
        // The frame's inventory has its own semantics (native enter/exit
        // transfers, and the wid-keyed pieces replication being built in
        // this milestone) — the loot layer must never mediate or seed it.
        // Base-id test: every frame in our world is the vanilla FURN
        // 0x2079E (the same constant the world-spawn PA flow keys on); a
        // modded frame base would need the FurnitureTypePowerArmor keyword
        // check instead.
        // ====================================================================
        // 2026-09-28 — THIS TEST COMES BEFORE THE IDENTITY TEST BELOW. The
        // loot rework (L1, v0.9.0) put the runtime-ref exit above it, and
        // every frame this project handles is a runtime ref: a console
        // spawn, a replica placed by world_spawn, a frame reborn at an exit.
        // From then on no manual take or put on a frame reached the pieces
        // report, and no peer saw a frame's pieces change (live test of
        // 2026-09-28 23:43: five pieces into wid 69, nothing on the wire,
        // "runtime ref ... no shared identity yet" at every piece). A frame
        // is identified by its wid through world_spawn, not by the loot
        // layer's shared identity, so the order is: the frame, then the
        // identity. A frame that is not ours is dropped by the report with
        // its own log line ("no wid bound").
        if (cid.base_id == 0x0002079Eu) {
            FW_DBG("[container] %s on a power-armor frame — passthrough, "
                   "frames are not loot", op_tag);
            // v23 — but a manual mutation IS state: after the engine runs,
            // the caller rescans and ships the frame's piece list (the
            // report helper itself ignores enter-drain mutations).
            out->pa_frame_ref = container;
            out->pa_frame_fid = cid.form_id;
            return;  // passthrough=true, and no seed either
        }

        // Loot rework L1 (2026-09-23): the shared identity of a container is
        // its placed form_id. A runtime ref (0xFF prefix: a corpse of an NPC
        // spawned at runtime, a dropped item) names another object on every
        // other client, and the (base, cell) key that used to stand in for
        // it merged every twin. Until such refs carry an identity of their
        // own (L4, L6) the engine keeps them local: no seed, no op.
        if (cid.form_id == 0 || (cid.form_id >> 24) == 0xFF) {
            FW_DBG("[container] %s on a runtime ref form=0x%X (base=0x%X "
                   "cell=0x%X) — passthrough, no shared identity yet",
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

// =============================================================================
// Loot rework L2 (2026-09-23) — APPLY FIRST, ASK AFTER.
//
// From B1.d (2026-04-20) to v0.8.1 this detour waited up to 100 ms on the
// main thread for the server's verdict and skipped g_orig_add on a refusal
// or a timeout. That was HALF a transaction: vt[0x7A] is the add into the
// destination, and the engine has already taken the items out of the source
// when it runs, so a skipped g_orig_add did not cancel the take, it
// destroyed the items. Measured: six X-01 pieces on 2026-08-16 (the frame
// exemption above), a take with the server down on 2026-09-23. And every
// take froze the game for the round trip, which with a server on another
// machine is the whole 100 ms budget.
//
// Now the engine runs first, unconditionally, and the op is queued reliable
// with no wait. The verdict arrives on the network thread; a refusal is
// undone on the main thread by engine::rollback_container_op_to_engine (the
// opposite transfer between the container and the player), and an op whose
// ACK died with the session is sent again on the rejoin, where the server
// answers a repeat with the stored verdict. Nothing is ever destroyed and
// nothing ever waits.
// =============================================================================
void __fastcall detour_add_object(
    void* dest_this,
    void* bound_obj,
    void* extra_data_sp,
    int count,
    void* source_old,
    std::uint32_t reason)
{
    // B1.h.2 DIAGNOSTIC TRACE. The whole decision tree at DEBUG level so
    // a report like "put then take, the item vanished" has a paper trail:
    // whether observe classified the op, whether g_orig_add ran and
    // returned, whether the op was sent. Toggle log_level=debug in
    // fw_config.ini to see the full trace.
    FW_DBG("[container] ENTRY dest=%p bound=%p count=%d source=%p reason=%u",
           dest_this, bound_obj, count, source_old, reason);

    // B1.g feedback-loop guard. If this vt[0x7A] invocation is a side-
    // effect of us applying a remote peer's op or undoing one of ours
    // (inside apply/rollback_container_op_to_engine), bypass the observe
    // path entirely — we MUST NOT re-emit this to the network as a fresh
    // CONTAINER_OP. Fall through to g_orig_add so the engine's internal
    // call still completes normally.
    if (tls_applying_remote) {
        FW_DBG("[container] tls_applying_remote=true — passthrough "
               "(dest=%p bound=%p count=%d source=%p)",
               dest_this, bound_obj, count, source_old);
        if (g_orig_add) {
            g_orig_add(dest_this, bound_obj, extra_data_sp, count, source_old, reason);
        }
        return;
    }
    // Stage 0 of L5 (2026-09-27): a menu deposit into an ACTOR lands here
    // too (Actor and PlayerCharacter share slot 0x7A), and put_hook has
    // already reported it. See tls_menu_transfer in the header.
    if (tls_menu_transfer) {
        FW_DBG("[container] menu deposit in flight — passthrough, put_hook "
               "owns it (dest=%p bound=%p count=%d source=%p)",
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
        // B1.e: seed the container's ground truth before the op reaches the
        // server. seed_container_if_unknown is idempotent per session
        // (Client::seed_in_flight) and does not mark a container whose list
        // could not be scanned (B1.h fix) so a later touch retries.
        //
        // Direction picks the correct REFR: on TAKE source_old is the
        // container; on PUT dest_this is.
        void* container = (r.opp.kind ==
            static_cast<std::uint32_t>(fw::net::ContainerOpKind::TAKE))
                ? source_old
                : dest_this;

        seed_container_impl(container, r.opp.container_form_id,
                            r.base_id, r.cell_id);

        // Fill the clock outside the SEH (chrono has non-trivial types).
        using namespace std::chrono;
        r.opp.timestamp_ms = duration_cast<milliseconds>(
            system_clock::now().time_since_epoch()).count();
    } else if (!r.passthrough) {
        // should_submit=false AND passthrough=false means observe set an
        // error state; don't run the engine in that case.
        FW_WRN("[container] observe error state — skipping g_orig_add");
        return;
    }

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

    if (r.should_submit) {
        const std::uint32_t op_id = fw::net::client().submit_container_op(r.opp);
        if (op_id != 0) {
            FW_LOG("[container] %s applied, op_id=%u sent for a verdict "
                   "container=0x%X (base=0x%X cell=0x%X) item=0x%X count=%d",
                   r.op_tag, op_id, r.opp.container_form_id,
                   r.base_id, r.cell_id, r.item_id, count);
        } else {
            FW_WRN("[container] %s applied but NOT sent: the client is "
                   "shutting down (container=0x%X item=0x%X count=%d)",
                   r.op_tag, r.opp.container_form_id, r.item_id, count);
        }
    }

    // v23 — a mutation went through on a PA frame: ship its full state
    // (no-op inside PA transitions or for frames without a wid).
    if (r.pa_frame_ref) {
        fw::native::world_spawn::report_frame_pieces(r.pa_frame_ref,
                                                     r.pa_frame_fid);
    }
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
thread_local bool tls_menu_transfer   = false;

// B1.g / B1.k.2 feedback-loop guard — RAII, nestable (see the header).
ApplyingRemoteGuard::ApplyingRemoteGuard() : prev_(tls_applying_remote) {
    tls_applying_remote = true;
}
ApplyingRemoteGuard::~ApplyingRemoteGuard() {
    tls_applying_remote = prev_;
}

// The deposit detour's entry (put_hook.cpp); the take detour calls the
// implementation directly. See the header.
void seed_container_if_unknown(void* container_ref, std::uint32_t form_id,
                               std::uint32_t base_id, std::uint32_t cell_id)
{
    seed_container_impl(container_ref, form_id, base_id, cell_id);
}

// Loot rework L3.4 (2026-09-24): containers activated before the engine
// built their runtime list. The alignment at the activation scans them as
// empty and can remove nothing (measured on 0x5DC4F, whose base the
// engine's component getter refuses); the activation itself builds the
// list, possibly on a later frame (the ContainerMenu opens through the UI
// message queue). Each entry is polled by container_activation_tick until
// the list exists, then aligned once more, or dropped at the deadline with
// a warning. Main thread only in practice; the mutex costs nothing.
namespace {
struct ActivationWatch {
    std::uint32_t form_id;
    std::uint32_t base_id;
    std::uint32_t cell_id;
    std::uint64_t deadline_ms;
};
std::mutex g_activation_watch_mtx;
std::vector<ActivationWatch> g_activation_watch;
constexpr std::uint64_t kActivationWatchMs = 2000;

std::uint64_t wall_ms_now() {
    using namespace std::chrono;
    return static_cast<std::uint64_t>(
        duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
}
} // namespace

void on_container_activation(void* refr, std::uint32_t form_id,
                             std::uint32_t base_id, std::uint32_t cell_id)
{
    if (!refr || form_id == 0 || base_id == 0 || cell_id == 0) return;
    if ((form_id >> 24) == 0xFF) return;        // runtime ref: local only (L1)
    if (base_id == 0x0002079Eu) return;         // the power-armor frame is not loot
    auto& c = fw::net::client();
    if (!c.container_known(form_id)) {
        FW_DBG("[container] activation of 0x%X (base=0x%X cell=0x%X): the "
               "server does not know it yet, the first take will seed it",
               form_id, base_id, cell_id);
        return;
    }
    c.reconverge_container(form_id);
    if (fw::engine::inventory_list_present(refr)) return;

    FW_LOG("[container] activation of 0x%X (base=0x%X cell=0x%X): no runtime "
           "list before the engine's activation, aligned again once it exists",
           form_id, base_id, cell_id);
    std::lock_guard lk(g_activation_watch_mtx);
    for (auto& w : g_activation_watch) {
        if (w.form_id == form_id) {
            w.deadline_ms = wall_ms_now() + kActivationWatchMs;
            return;
        }
    }
    if (g_activation_watch.size() >= 64) return;  // never unbounded
    g_activation_watch.push_back(ActivationWatch{
        form_id, base_id, cell_id, wall_ms_now() + kActivationWatchMs});
}

void container_activation_tick() {
    std::vector<ActivationWatch> due;
    {
        std::lock_guard lk(g_activation_watch_mtx);
        if (g_activation_watch.empty()) return;
        due = g_activation_watch;
    }
    const std::uint64_t now = wall_ms_now();
    std::vector<std::uint32_t> done;
    for (const auto& w : due) {
        void* refr = fw::engine::lookup_by_form_id(w.form_id);
        if (refr && fw::engine::inventory_list_present(refr)) {
            FW_LOG("[container] 0x%X (base=0x%X cell=0x%X): runtime list built "
                   "by the activation, aligned to the server now",
                   w.form_id, w.base_id, w.cell_id);
            fw::net::client().reconverge_container(w.form_id);
            done.push_back(w.form_id);
        } else if (now >= w.deadline_ms) {
            FW_WRN("[container] 0x%X (base=0x%X cell=0x%X): no runtime list "
                   "%llu ms after the activation; the engine did not build it "
                   "either, the menu shows the save until an item moves",
                   w.form_id, w.base_id, w.cell_id,
                   static_cast<unsigned long long>(kActivationWatchMs));
            done.push_back(w.form_id);
        }
    }
    if (done.empty()) return;
    std::lock_guard lk(g_activation_watch_mtx);
    g_activation_watch.erase(
        std::remove_if(g_activation_watch.begin(), g_activation_watch.end(),
                       [&](const ActivationWatch& w) {
                           return std::find(done.begin(), done.end(), w.form_id)
                                  != done.end();
                       }),
        g_activation_watch.end());
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
