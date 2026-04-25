#include "kill_hook.h"

#include <windows.h>
#include <atomic>

#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"
#include "../ref_identity.h"
#include "../net/client.h"
#include "../net/protocol.h"

namespace fw::hooks {

namespace {

// Original function trampoline. Populated by MinHook during install.
using KillFn = void (*)(void* victim, void* killer, void* unk2, std::uint8_t silent, int unk4);
KillFn g_orig_kill = nullptr;

std::atomic<std::uint64_t> g_fire_count{0};

void __fastcall detour_kill(
    void* victim, void* killer, void* unk2, std::uint8_t silent, int unk4)
{
    __try {
        if (victim) {
            const auto vi = read_ref_identity(victim);
            const auto ki = killer
                ? read_ref_identity(killer)
                : RefIdentity{};
            g_fire_count.fetch_add(1, std::memory_order_relaxed);
            FW_LOG("[kill] victim form=0x%X base=0x%X cell=0x%X  killer form=0x%X base=0x%X cell=0x%X",
                   vi.form_id, vi.base_id, vi.cell_id,
                   ki.form_id, ki.base_id, ki.cell_id);

            // Enqueue to network. Filter: don't report kills of the local
            // player (formid 0x14) — matches Python client semantics.
            if (vi.form_id != offsets::PLAYER_FORMID &&
                vi.base_id != 0 && vi.cell_id != 0)
            {
                fw::net::ActorEventPayload a{};
                a.kind          = static_cast<std::uint32_t>(fw::net::ActorEventKind::KILL);
                a.form_id       = vi.form_id;
                a.actor_base_id = vi.base_id;
                a.cell_id       = vi.cell_id;
                a.x = 0; a.y = 0; a.z = 0;
                a.extra         = ki.form_id;  // killer ref id (Python compat)
                fw::net::client().enqueue_actor_event(a);
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[kill] SEH in detour observation (victim=%p, killer=%p)",
               victim, killer);
    }

    // ALWAYS call through. The engine needs Kill to actually kill.
    if (g_orig_kill) {
        g_orig_kill(victim, killer, unk2, silent, unk4);
    }
}

} // namespace

bool install_kill_hook(std::uintptr_t module_base) {
    void* target = reinterpret_cast<void*>(module_base + offsets::KILL_ENGINE_RVA);
    const bool ok = install(
        target,
        reinterpret_cast<void*>(&detour_kill),
        reinterpret_cast<void**>(&g_orig_kill));
    if (ok) {
        FW_LOG("[kill] hook installed at 0x%llX (RVA 0x%lX)",
               static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(target)),
               static_cast<unsigned long>(offsets::KILL_ENGINE_RVA));
    }
    return ok;
}

} // namespace fw::hooks
