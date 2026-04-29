#include "install_all.h"

#include "kill_hook.h"
#include "container_hook.h"
#include "put_hook.h"
#include "pickup_hook.h"
#include "player_pos_hook.h"
#include "main_menu_hook.h"
#include "worldstate_hook.h"
#include "door_hook.h"
#include "equip_cycle.h"     // B8: post-LoadGame BipedAnim normalize
#include "equip_hook.h"      // M9 wedge 1: equipment-event sender hook
#include "engine_tracer.h"

#include "../log.h"

namespace fw::hooks {

InstallSummary install_all(std::uintptr_t module_base,
                           const fw::config::Settings& cfg)
{
    InstallSummary s{};
    FW_LOG("hooks: installing set on module base 0x%llX",
           static_cast<unsigned long long>(module_base));

    s.kill_ok        = install_kill_hook(module_base);
    s.container_ok   = install_container_hook(module_base);
    // B1.k: must run after install_container_hook (shares MinHook manager);
    // captures PUT which vt[0x7A] doesn't see (live test 2026-04-21).
    s.put_ok         = install_put_hook(module_base);
    // B1.n: PlayerCharacter::vt[0xEC] world pickup. Orthogonal to vt[0x7A]
    // (no feedback loop confirmed by BFS in RE agent); shares the
    // ApplyingRemoteGuard TLS flag with container_hook for feedback safety.
    s.pickup_ok      = install_pickup_hook(module_base);
    s.player_pos_ok  = start_player_pos_poll(module_base);
    s.main_menu_ok   = install_main_menu_hook(module_base, cfg);
    s.worldstate_ok  = install_worldstate_hooks(module_base);
    // B6.1: door SetOpenState observation (phase 1).
    s.door_ok        = install_door_hook(module_base);
    // M9 wedge 1: ActorEquipManager Equip + Unequip detours (OBSERVE-only).
    //   Detect local-player equip changes → broadcast EQUIP_OP. Receivers
    //   in wedge 1 just log RX; wedge 2 will swap visuals on the M8P3
    //   ghost. Critical: this hook is OBSERVE-only — no nullify of skin
    //   bindings, no cull-flag manipulation, no detach-from-SSN. Yesterday's
    //   M9 attempts that did those things crashed in 3 different walkers
    //   (re/M9_y_post_bmod_crash_dossier.txt). Pure observation + broadcast
    //   is safe; B8 force-equip-cycle (above, fired post-LoadGame) handles
    //   the BipedAnim normalize that lets the ghost subsequently coexist
    //   with equip changes.
    s.equip_ok       = install_equip_hook(module_base);
    // B8: NOTE — arm call MOVED to main_menu_hook::fw_wndproc post-LoadGame
    //   callback (instead of armed here at install time). Reason:
    //   the prior install-time arm with 20s delay was measured from DLL
    //   inject (T+0), which yielded "10s post in-world" — too long.
    //   User requested earlier firing ("Prima cazzo, fai 10 secondi o 5
    //   dopo il loading nel mondo" 2026-04-28). Solution: arm AFTER
    //   load_game_by_name() returns, so the worker delay is measured
    //   from LoadGame call time. With 10s delay we get ~5s in-world.
    //   See main_menu_hook.cpp + offsets.h "B8" block.
    // M6.3: engine_tracer disabled post-discovery.
    //   2026-04-24 enabled → captured vanilla head NIF paths
    //     (BaseMaleHead.nif, MaleHeadRear.nif) during Museum gameplay.
    //   Re-enable if we need to observe other engine calls for M7
    //   animations or M8 facegen.
    // (void)install_engine_tracer(module_base);

    FW_LOG("hooks: install summary kill=%d container=%d put=%d pickup=%d "
           "pos=%d main_menu=%d worldstate=%d door=%d equip=%d (total %zu/9)",
           int(s.kill_ok), int(s.container_ok), int(s.put_ok), int(s.pickup_ok),
           int(s.player_pos_ok), int(s.main_menu_ok), int(s.worldstate_ok),
           int(s.door_ok), int(s.equip_ok), s.success_count());
    return s;
}

void stop_all() {
    stop_player_pos_poll();
    // kill / container / main_menu hooks are torn down by MinHook's global
    // shutdown in hook_manager::shutdown() — no per-hook cleanup needed.
}

} // namespace fw::hooks
