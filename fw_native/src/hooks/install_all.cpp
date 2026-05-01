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
#include "../native/nif_path_cache.h"  // M9 w4 witness pattern step 1
#include "../native/bsgeo_input_cache.h" // M9 w4 Path B-alt-1: factory input capture
#include "../native/ni_alloc_tracker.h"   // M9 w4 Path B-alt-2: alloc caller-RIP tracker
#include "../native/clone_factory_tracker.h" // M9 w4: clone factory hex-dump + source map

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
    //
    // ⚠ engine_tracer also hooks sub_1417B3E90 — it conflicts with the
    //   M9 w4 nif_path_cache below. Re-enabling engine_tracer requires
    //   either folding its trace logic into the cache detour, or
    //   uninstalling the cache first.
    // (void)install_engine_tracer(module_base);

    // M9 wedge 4 (witness pattern, step 1) — RE-ENABLED 2026-04-30 22:00.
    //
    // The witness pipeline is now structured as a TWO-stage broadcast:
    //   1. enqueue_equip_op fires BEFORE g_orig_equip with mods only
    //      (no nif_descs). Receiver does base attach. Crash-safe.
    //   2. After g_orig_equip returns successfully, walker queries the
    //      cache and produces a DELTA enqueue with nif_descs. Receiver
    //      sees "already attached + nif_descs present" and applies just
    //      the mod-attach loop on the existing weapon node.
    //
    // If g_orig_equip SEH AVs (engine bug, see equip_cycle.cpp:367), the
    // delta enqueue is skipped — peers see the base weapon attached but
    // not the mods. Acceptable degraded mode; never a crash, never a
    // missing weapon. The SEH-wrap on the chain itself is a separate
    // hardening task tracked in the todo list.
    const bool nif_cache_ok =
        fw::native::nif_path_cache::install(module_base);
    if (!nif_cache_ok) {
        FW_WRN("hooks: nif_path_cache install FAILED (witness pattern "
               "won't see mod NIFs — sender extraction will be empty)");
    }

    // M9 wedge 4 Path B-alt-1 — capture geometry factory inputs at the
    // moment of NIF parse, BEFORE positions get freed (iter 11c finding).
    // Diagnostic-only first: confirms whether weapon NIFs trigger the
    // factory at all. If they do, mesh data is in our cache for later
    // walker query keyed on BSTriShape*.
    const bool bsgeo_cache_ok =
        fw::native::bsgeo_input_cache::install(module_base);
    if (!bsgeo_cache_ok) {
        FW_WRN("hooks: bsgeo_input_cache install FAILED");
    }

    // M9 wedge 4 Path B-alt-2 — capture caller RIPs of every BSTriShape /
    // BSDynamicTriShape allocation. After 4 layers of hook misses (public
    // API, worker, cache resolver, factory), we go to the ROOT: the pool
    // allocator that every NiObject derives from. The RIP tells us who
    // is constructing each shape — from there we identify the secret
    // weapon NIF parser.
    const bool alloc_trk_ok =
        fw::native::ni_alloc_tracker::install(module_base);
    if (!alloc_trk_ok) {
        FW_WRN("hooks: ni_alloc_tracker install FAILED");
    }

    // M9 wedge 4 — hook the BSTriShape CLONE FACTORY (sub_1416D99E0).
    // The alloc tracker (above) identified ALL weapon BSTriShape leaves
    // come from caller_rva 0x16D9A5C, which is inside this clone factory.
    // This hook captures the SOURCE TEMPLATE pointer (a1) and dumps hex
    // bytes of the mysterious +0x148 struct for layout discovery.
    const bool clone_trk_ok =
        fw::native::clone_factory_tracker::install(module_base);
    if (!clone_trk_ok) {
        FW_WRN("hooks: clone_factory_tracker install FAILED");
    }

    FW_LOG("hooks: install summary kill=%d container=%d put=%d pickup=%d "
           "pos=%d main_menu=%d worldstate=%d door=%d equip=%d "
           "nif_cache=%d (total %zu/9)",
           int(s.kill_ok), int(s.container_ok), int(s.put_ok), int(s.pickup_ok),
           int(s.player_pos_ok), int(s.main_menu_ok), int(s.worldstate_ok),
           int(s.door_ok), int(s.equip_ok), int(nif_cache_ok),
           s.success_count());
    return s;
}

void stop_all() {
    stop_player_pos_poll();
    // kill / container / main_menu hooks are torn down by MinHook's global
    // shutdown in hook_manager::shutdown() — no per-hook cleanup needed.
}

} // namespace fw::hooks
