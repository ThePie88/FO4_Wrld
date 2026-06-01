#include "kill_hook.h"

#include <windows.h>
#include <atomic>
#include <cstring>

#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"
#include "../ref_identity.h"
#include "../net/client.h"
#include "../net/protocol.h"
#include "container_hook.h"        // Build 65.c.47 WEDGE3 — tls_applying_remote (no-echo)
#include "ownership_manager.h"     // Build 65.c.47 WEDGE3 — is_owner_of (owner-emit gate)

namespace fw::hooks {

namespace {

// Original function trampoline. Populated by MinHook during install.
using KillFn = void (*)(void* victim, void* killer, void* unk2, std::uint8_t silent, int unk4);
KillFn g_orig_kill = nullptr;

std::atomic<std::uint64_t> g_fire_count{0};
std::atomic<std::uint64_t> g_death_emits{0};  // Build 65.c.47 — NPC_DEATH_FROM_OWNER emits

// Build 65.c.47 WEDGE3 — KILL-SWITCH for the owner-side death emit. Default
// true. Paired with the same-named switch gating the non-owner apply in
// main_thread_dispatch.cpp::drain_npc_death_apply_queue. Flip to false to stop
// emitting deaths (and thus disable the whole feature end-to-end if both off).
constexpr bool kDeathSyncEnabled = true;

// Build 65.c.47 — SEH-caged read of the victim's world pos (Actor+0xD0).
// Returns true + fills out[3] on success; false (out untouched) on fault.
bool read_actor_pos(void* actor, float out[3]) noexcept {
    if (!actor) return false;
    __try {
        const float* p = reinterpret_cast<const float*>(
            reinterpret_cast<const std::uint8_t*>(actor) + offsets::POS_OFF);
        out[0] = p[0];
        out[1] = p[1];
        out[2] = p[2];
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

void __fastcall detour_kill(
    void* victim, void* killer, void* unk2, std::uint8_t silent, int unk4)
{
    // Build 65.c.47 WEDGE3 — NO-ECHO. When WE invoke Actor::Kill on a relayed
    // owner death (engine::kill_actor inside drain_npc_death_apply_queue, under
    // an ApplyingRemoteGuard → tls_applying_remote=true), this detour re-enters.
    // We MUST NOT observe + re-report that kill (it would bounce back to the
    // server as a fresh NPC_DEATH_FROM_OWNER and loop). Pass straight through.
    if (tls_applying_remote) {
        if (g_orig_kill) {
            g_orig_kill(victim, killer, unk2, silent, unk4);
        }
        return;
    }

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

            // Build 65.c.33 — ROLLED BACK the c.32 proxy-ghost teardown call:
            // the deregister was a no-op (log: removed=0 — the proxy is keyed
            // in the form table by the engine_fid 0xFF001393, not 0xFF000001),
            // and the only part that ran (nulling g_ghost_actor /
            // g_ghost_duplicate_ptr mid-death) is the prime suspect for the new
            // A-side AV 0x2A007D during the reload teleport. No benefit + risk,
            // so removed. (The teardown fn stays defined-but-unused in
            // actor_hijack.cpp for a future, correctly-keyed approach.)

            // Enqueue to network. Filter: don't report kills of the local
            // player (formid 0x14) — matches Python client semantics.
            // c.49.1 — SKIP the legacy KILL ActorEvent for TRACKED raiders. The
            // legacy path → server → set_disabled_validated DISABLES the ref (it
            // VANISHES). For PLACED refs (0x00______) the c.40a vanish guard does
            // NOT protect them (it only refuses 0xFF dynamic spawns), so a placed
            // tracked NPC killed cross-client DISAPPEARED instead of corpsing
            // (user 2026-06-01). The c.47/c.49 death-sync (NPC_DEATH → kill_actor)
            // corpses tracked entities properly — don't ALSO disable them. Old
            // ghost-era untracked NPCs (Codsworth/Dogmeat) keep the legacy path.
            if (vi.form_id != offsets::PLAYER_FORMID &&
                vi.base_id != 0 && vi.cell_id != 0 &&
                !fw::ownership::is_owner_of(vi.form_id) &&
                !fw::ownership::is_non_owner_tracked(vi.form_id))
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

            // Build 65.c.47 WEDGE3 — DEATH-EMIT. If the killed victim is a
            // TRACKED raider, tell the server so it relays NPC_DEATH_FROM_OWNER
            // to the other client(s) → they corpse their copy.
            // c.49 — BIDIRECTIONAL: emit on owner-kill OR non-owner-kill.
            // Original c.47 gated on is_owner_of only → when the NON-owner dealt
            // the lethal blow (e.g. B shoots a mosquito OWNED by A), B never
            // emitted → A's real copy stayed ALIVE ("killed on B, alive on A",
            // user 2026-06-01). Now any tracked-side kill propagates. The relayed
            // Kill we apply runs under ApplyingRemoteGuard, so this detour bails
            // (tls_applying_remote, top of fn) → no echo. Gate still excludes the
            // ghost (never tracked) + the player 0x14. ragdoll dir = 0 (minimal).
            if (kDeathSyncEnabled &&
                vi.form_id != offsets::PLAYER_FORMID &&
                vi.form_id != 0 && vi.form_id != 0xFFFFFFFFu &&
                (fw::ownership::is_owner_of(vi.form_id) ||
                 fw::ownership::is_non_owner_tracked(vi.form_id)))
            {
                fw::net::NPCDeathFromOwnerPayload p{};
                p.form_id        = vi.form_id;
                p.killer_form_id = ki.form_id;   // 0 if no killer
                float pos[3] = { 0.0f, 0.0f, 0.0f };
                read_actor_pos(victim, pos);     // SEH-caged; leaves 0 on fault
                p.pos_x      = pos[0];
                p.pos_y      = pos[1];
                p.pos_z      = pos[2];
                p.ragdoll_x  = 0.0f;             // minimal: no directional impulse
                p.ragdoll_y  = 0.0f;
                p.ragdoll_z  = 0.0f;
                p.damage     = 0.0f;
                p.hit_zone   = 0;
                p.flags      = 0;
                p._pad       = 0;
                p.ts_ms      = static_cast<std::uint64_t>(GetTickCount64());
                fw::net::client().enqueue_npc_death_from_owner(p);

                const auto en = g_death_emits.fetch_add(1, std::memory_order_relaxed);
                FW_LOG("[kill] OWNER-DEATH-EMIT #%llu fid=0x%X killer=0x%X "
                       "pos=(%.1f,%.1f,%.1f)",
                       static_cast<unsigned long long>(en), vi.form_id,
                       ki.form_id, pos[0], pos[1], pos[2]);
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
