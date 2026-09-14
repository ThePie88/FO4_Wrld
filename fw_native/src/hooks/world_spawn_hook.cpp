#include "world_spawn_hook.h"

#include <windows.h>

#include <atomic>
#include <mutex>
#include <unordered_set>

#include "../hook_manager.h"
#include "../engine/engine_calls.h"
#include "../native/world_spawn.h"
#include "../net/client.h"
#include "../offsets.h"
#include "../ref_identity.h"
#include "../log.h"

namespace fw::hooks {

namespace {

using PlaceAtMeFn = void* (*)(void* vm, std::uint32_t stack_id,
                              void** form_pair, void* anchor_refr,
                              std::uint32_t count, std::uint64_t persistent);

PlaceAtMeFn                 g_orig = nullptr;
std::atomic<std::uintptr_t> g_base{0};

// THE CONSOLE DOES NOT USE THE PAPYRUS NATIVE, measured the hard way: the
// first live test ran `player.placeatme`, the object appeared locally, and
// the Papyrus detour below never fired once on either client. The console
// command (opcode 0x1025, handler sub_1405C4DE0) goes through its own worker
// instead:
//
//   sub_1405E05D0(u32* out_handle, TESObjectREFR* target, TESForm* base,
//                 int count, int, int, float scale, char persist)
//
// which delegates to the 0xD50-byte sub_1405E0800 for the actual creation
// and writes the new REFR's HANDLE into *out_handle. The handler resolves
// the target BEFORE calling it (`player.placeatme` arrives with target ==
// the player singleton), so the player-anchored filter works here exactly
// as it does on the Papyrus path. Both detours feed one reporter.
using ConsolePlaceFn = std::uint32_t* (*)(std::uint32_t* out_handle,
                                          void* target_refr, void* base_form,
                                          int count, int a5, int a6,
                                          float scale, char persist);
ConsolePlaceFn g_orig_console = nullptr;

// REFRs already reported, so a double-fire (engine re-entry, script loops)
// cannot double-spawn remotely. Bounded: cleared wholesale past a cap that no
// legitimate session approaches.
std::mutex                       g_seen_mx;
std::unordered_set<std::uint32_t> g_seen;
constexpr std::size_t             kSeenCap = 4096;

// POD SEH readers — the SEH lives here and not in the detour body because the
// detour owns unwindable objects (C2712, learned twice).
bool seh_read_vec3(const void* at, float out[3]) noexcept {
    if (!at) return false;
    __try {
        const float* f = reinterpret_cast<const float*>(at);
        out[0] = f[0]; out[1] = f[1]; out[2] = f[2];
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

bool seh_or_u32(void* at, std::uint32_t bits) noexcept {
    if (!at) return false;
    __try {
        *reinterpret_cast<std::uint32_t*>(at) |= bits;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}

void* seh_ptr_at(std::uintptr_t at) noexcept {
    __try { return *reinterpret_cast<void* const*>(at); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return nullptr; }
}

// One reporter for every creation path. `via` names the path in the log so
// the filter-widening decisions stay data-driven.
void report_spawn(void* refr, void* anchor_refr, const char* via) {
    if (!refr) return;
    if (fw::engine::in_internal_place()) return;   // our own call

    const std::uintptr_t base = g_base.load(std::memory_order_relaxed);
    if (!base) return;

    void* player = seh_ptr_at(base + fw::offsets::PLAYER_SINGLETON_RVA);
    const auto id = fw::read_ref_identity(refr);

    if (!player || anchor_refr != player) {
        // Not the gate for this wedge — but say what passed through, because
        // the next widening of this filter should be chosen from data.
        FW_DBG("[world-spawn-tx] %s NOT anchored at the player (anchor=%p): "
               "form=0x%08X base=0x%08X cell=0x%08X — observed, not broadcast",
               via, anchor_refr, id.form_id, id.base_id, id.cell_id);
        return;
    }
    if (id.form_id == 0 || id.base_id == 0) return;

    {
        std::lock_guard<std::mutex> lk(g_seen_mx);
        if (g_seen.size() > kSeenCap) g_seen.clear();
        if (!g_seen.insert(id.form_id).second) return;   // double fire
    }

    float pos[3] = {0}, rot[3] = {0};
    auto* rb = reinterpret_cast<std::uint8_t*>(refr);
    (void)seh_read_vec3(rb + fw::offsets::POS_OFF, pos);
    (void)seh_read_vec3(rb + fw::offsets::ROT_OFF, rot);

    // TEMPORARY from this moment: the server owns the object's lifetime now,
    // and a save that kept the original would duplicate it against the join
    // replay next session. Same flag, same reason as the ghost donor.
    const bool tmp_ok = seh_or_u32(rb + fw::offsets::FLAGS_OFF,
                                   fw::offsets::REFR_FLAG_TEMPORARY);

    // v23 — a PA frame's announce carries its content (a fresh console
    // spawn is empty, but a re-announce of a stocked frame must not lose
    // its pieces).
    fw::net::PaPieceEntry pieces[12] = {};
    const std::uint8_t pn = fw::native::world_spawn::capture_frame_pieces(
        refr, id.base_id, pieces);
    fw::net::client().enqueue_world_spawn_op(
        id.base_id, id.form_id, pos, rot, id.cell_id, /*flags=*/0,
        static_cast<std::uint64_t>(GetTickCount64()),
        pn ? pieces : nullptr, pn);

    FW_LOG("[world-spawn-tx] observed player-anchored spawn via %s: "
           "base=0x%08X local fid=0x%08X cell=0x%08X at (%.1f, %.1f, %.1f) "
           "-> WORLD_SPAWN_OP sent (TEMPORARY %s)",
           via, id.base_id, id.form_id, id.cell_id, pos[0], pos[1], pos[2],
           tmp_ok ? "patched" : "PATCH FAILED");
}

void* detour_place_at_me(void* vm, std::uint32_t stack_id, void** form_pair,
                         void* anchor_refr, std::uint32_t count,
                         std::uint64_t persistent) {
    void* refr = g_orig(vm, stack_id, form_pair, anchor_refr, count,
                        persistent);
    report_spawn(refr, anchor_refr, "Papyrus PlaceAtMe");
    return refr;
}

std::uint32_t* detour_console_place(std::uint32_t* out_handle,
                                    void* target_refr, void* base_form,
                                    int count, int a5, int a6,
                                    float scale, char persist) {
    std::uint32_t* ret = g_orig_console(out_handle, target_refr, base_form,
                                        count, a5, a6, scale, persist);
    // The worker hands back a HANDLE, not a pointer; the in-house resolver
    // from the N2 aggro fix turns it into the REFR.
    if (out_handle && *out_handle != 0 && *out_handle != 0xFFFFFFFFu) {
        void* refr = fw::engine::resolve_refhandle(out_handle);
        report_spawn(refr, target_refr, "console PlaceAtMe");
    }
    return ret;
}

}  // namespace

bool install_world_spawn_hook(std::uintptr_t module_base) {
    if (!module_base) return false;
    g_base.store(module_base, std::memory_order_relaxed);
    void* target = reinterpret_cast<void*>(module_base
                                           + fw::offsets::PLACE_AT_ME_RVA);
    const bool ok = fw::hooks::install(
        target, reinterpret_cast<void*>(&detour_place_at_me),
        reinterpret_cast<void**>(&g_orig));
    if (ok) {
        FW_LOG("[world-spawn-tx] PlaceAtMe detour installed at %p — "
               "player-anchored spawns broadcast, everything else observed",
               target);
    } else {
        FW_ERR("[world-spawn-tx] PlaceAtMe detour FAILED to install");
    }

    // The console's own worker — the path the first live test proved the
    // Papyrus native never sees.
    void* ctarget = reinterpret_cast<void*>(module_base
                                            + fw::offsets::CONSOLE_PLACE_WORKER_RVA);
    const bool cok = fw::hooks::install(
        ctarget, reinterpret_cast<void*>(&detour_console_place),
        reinterpret_cast<void**>(&g_orig_console));
    if (cok) {
        FW_LOG("[world-spawn-tx] console place worker detour installed at %p",
               ctarget);
    } else {
        FW_ERR("[world-spawn-tx] console place worker detour FAILED");
    }
    return ok && cok;
}

}  // namespace fw::hooks
