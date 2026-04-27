#include "main_thread_dispatch.h"

#include <atomic>
#include <deque>
#include <mutex>

#include "engine/engine_calls.h"
#include "hooks/container_hook.h"   // ApplyingRemoteGuard + tls_applying_remote
#include "log.h"

namespace fw::dispatch {

namespace {

std::mutex g_mtx;
std::deque<PendingContainerOp> g_queue;

// B6.1: door queue — separate mutex so doors don't contend with container
// ops. Doors are toggle-only and high-frequency (one per E press).
std::mutex g_door_mtx;
std::deque<PendingDoorOp> g_door_queue;

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
}

std::size_t pending_count() {
    std::lock_guard lk(g_mtx);
    return g_queue.size();
}

HWND get_target_hwnd() {
    return g_hwnd.load(std::memory_order_acquire);
}

} // namespace fw::dispatch
