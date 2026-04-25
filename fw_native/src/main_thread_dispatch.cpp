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

// The FO4 main window handle. Set exactly once by main_menu_hook after
// it subclasses WndProc (post-B3.b-registrar detection). Read lock-free
// thereafter; atomic for publish/acquire ordering.
std::atomic<HWND> g_hwnd{nullptr};

// Post the wake-up message. Swallows failures (HWND missing at boot is
// expected; the queue will flush on next post after set_target_hwnd).
void post_wakeup() noexcept {
    HWND h = g_hwnd.load(std::memory_order_acquire);
    if (!h) return;
    if (!PostMessageW(h, FW_MSG_CONTAINER_APPLY, 0, 0)) {
        FW_DBG("dispatch: PostMessage(FW_MSG_CONTAINER_APPLY) failed (err=%lu)",
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
    post_wakeup();
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
        post_wakeup();
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
