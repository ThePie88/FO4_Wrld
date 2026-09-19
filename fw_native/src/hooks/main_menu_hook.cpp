#include "main_menu_hook.h"

#include <windows.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <string>
#include <thread>

#include "../config.h"
#include "../diag/crash_veh.h"  // Build 69r — note_user_shutdown (ALT+F4 marker)
#include "../engine/engine_calls.h"
#include "../ghost/actor_hijack.h"
#include "equip_hook.h"  // M9 w4 v9: FW_MSG_DEFERRED_MESH_TX
#include "../native/weapon_capture.h"  // M9.w4 PROPER (v0.4.2+): FW_MSG_WEAPON_CAPTURE_FINALIZE
#include "../native/spai_prewarm.h"    // SPAI Tier 1: FW_MSG_SPAI_PREWARM
// (synthetic_refr's earlier WM_APP message has been removed; the API is sync)
#include "../hook_manager.h"
#include "../log.h"
#include "../native/world_spawn.h"
#include "../native/ghost_lifecycle.h"
#include "../net/client.h"   // l'addio alla chiusura della finestra
#include "../main_thread_dispatch.h"
#include "../native/scene_inject.h"
#include "../native/chargen_dump.h"    // character-creation catalogue capture
#include "../native/anatomy_probe.h"   // read-only local player 3D walk
#include "../native/chargen_selftest.h" // one-shot appearance apply from our code
#include "../native/appearance_recipe.h" // v20: publish my appearance on change
#include "../render/editor_overlay.h"  // the panel, and its input capture
#include "../native/chargen_stage.h"     // 2026-08-08: stage the player for creation
#include "../native/face_borrow.h"       // v20: build peers' faces locally
#include "../offsets.h"
#include "equip_cycle.h"  // B8: WndProc dispatches FW_MSG_FORCE_EQUIP_CYCLE_*

namespace fw::hooks {

namespace {

// ----------------------------------------------------------------- hook #1
// sub_140B01290 — MainMenu Scaleform registrar. Binds AS3→C++ callbacks
// for the main menu. Called on the main thread while the menu is being
// constructed. We use this as a "main menu is starting up" trigger; we do
// NOT call LoadGame from here directly — that fires before the menu is
// input-ready and leaves the engine's render state stuck on the menu
// background ("black screen" observed in v3 live test).
//
// Instead the detour sets g_menu_detected; a background worker waits N
// seconds then PostMessage's a custom WM_APP to the FO4 window. A WndProc
// subclass we install on that window catches the message (on the main
// thread, which dispatches WndProc) and performs the real LoadGame call
// — by then the menu is fully visible and idle.
using MainMenuRegisterFn = void* (*)(void* menu_obj);
MainMenuRegisterFn g_orig_main_menu_register = nullptr;

// Fire-once guard for the dispatch pipeline.
std::atomic<bool> g_menu_detected{false};
std::atomic<bool> g_load_queued{false};
std::atomic<bool> g_load_dispatched{false};

// Settings snapshot captured at install time.
std::string g_save_name;
std::uint32_t g_delay_ms = 4000;   // v4 default: 4s after registrar hit
// 2026-08-08 — virtual-key code that toggles the character editor, cached from
// the ini at install. Read on the main thread from the subclass below; there is
// no global config accessor in this project, every module is handed what it
// needs at init. 0 = the key is not configured.
std::uint32_t g_editor_key = 0;

// ----------------------------------------------------------------- WndProc subclass
//
// We replace the FO4 main-window WndProc. Our proc forwards all unrelated
// messages to the original via CallWindowProcW; when it sees our custom
// WM_APP it invokes LoadGame — guaranteed on the main thread because
// Win32 dispatches WndProc on whichever thread owns the window's message
// pump, and the main FO4 window is pumped by the engine's main thread.
constexpr UINT  FW_MSG_LOAD_GAME = WM_APP + 0x42;
HWND           g_fo4_hwnd        = nullptr;
WNDPROC        g_orig_wndproc    = nullptr;

// Find the FO4 main top-level window owned by our (this) process.
HWND find_fo4_hwnd() {
    struct Ctx { DWORD pid; HWND found; };
    Ctx ctx{ GetCurrentProcessId(), nullptr };
    EnumWindows([](HWND hwnd, LPARAM lp) -> BOOL {
        auto* c = reinterpret_cast<Ctx*>(lp);
        DWORD wpid = 0;
        GetWindowThreadProcessId(hwnd, &wpid);
        if (wpid != c->pid) return TRUE;
        if (!IsWindowVisible(hwnd)) return TRUE;
        wchar_t cls[64] = {};
        GetClassNameW(hwnd, cls, 63);
        if (std::wcscmp(cls, L"Fallout4") == 0) {
            c->found = hwnd;
            return FALSE;
        }
        return TRUE;
    }, reinterpret_cast<LPARAM>(&ctx));
    return ctx.found;
}

// Il battito del WndProc.
//
// Il blocco di tick qui sotto e' l'unico posto in cui questo progetto
// tocca il grafo di scena, e gira a ogni MESSAGGIO della finestra. Il
// 2026-09-18 si e' scoperto cosa vuol dire davvero: il client A, entrato
// per primo e fermo sul posto, ha ricevuto l'ingresso di B dalla rete alle
// 15:03:14.462 e il thread principale l'ha guardato alle 15:03:29.166.
// Quattordici secondi e sette in coda, perche' un giocatore immobile non
// genera messaggi e il rendering non ne genera affatto. Il ghost di B e'
// arrivato tre secondi DOPO quello di A sull'altro client, che nel
// frattempo aveva fatto un caricamento intero.
//
// WM_TIMER e' la risposta giusta proprio per come Windows lo tratta: e'
// sintetizzato solo quando la coda e' vuota, quindi non puo' aggiungere
// carico quando c'e' gia' traffico. Alza il PAVIMENTO — da zero a trenta
// al secondo — e lascia il soffitto dov'era. I moduli del blocco sono
// tutti scritti come sondaggi (autolimitati, idempotenti, uno dice
// testualmente di riprovare "while the save is still loading") e gia'
// vedevano 26-40 messaggi al secondo quando qualcosa si muoveva: questo
// fa somigliare l'inattivita' al movimento, non il contrario.
constexpr UINT_PTR kHeartbeatTimerId = 0xFA11;
constexpr UINT     kHeartbeatMs      = 33;

// IL BATTITO C'E', MA STA ZITTO MENTRE IL MOTORE CARICA.
//
// La bisezione del 2026-09-18 ha dato una risposta netta: col battito
// acceso il client B moriva 19 secondi dopo il rientro, spento e' rimasto
// vivo oltre due minuti. Trenta tick al secondo in piu' sul thread
// principale, DENTRO la finestra del caricamento, sono quello che
// ammazzava — e quella finestra il progetto originale la teneva vuota con
// una grazia di 15-30 secondi, per la ragione scritta dall'utente:
// caricare roba durante il caricamento iniziale faceva crashare.
//
// Quindi il battito torna dov'e' utile e sparisce dov'e' letale: si spegne
// quando invochiamo LoadGame e si riaccende quando il cancello dichiara la
// scena assestata — 120 tick consecutivi E almeno due secondi veri, senza
// caricamenti in volo e senza cambi di cella. E' la grazia dell'utente,
// misurata invece che a tempo.
//
// Fuori dal caricamento serve eccome: senza, il blocco di tick gira solo
// sui messaggi veri e un giocatore fermo puo' restare 14,7 secondi senza
// un tick — misurati — con l'ingresso di un peer fermo in coda per tutto
// quel tempo.

LRESULT CALLBACK fw_wndproc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    // Armato da qui e non da install_wndproc_subclass perche' qui siamo
    // certi di essere sul thread che possiede la finestra, che e' l'unico
    // posto da cui un timer di finestra si arma senza domande.
    // Lo stato del battito vive qui perche' SetTimer e KillTimer vogliono il
    // thread che possiede la finestra, e questo e' quello.
    static bool s_heartbeat_on = false;
    {
        const bool want = fw::native::ghost_scene_settled();
        if (want && !s_heartbeat_on) {
            if (SetTimer(hwnd, kHeartbeatTimerId, kHeartbeatMs, nullptr)) {
                s_heartbeat_on = true;
                FW_LOG("[main_menu] tick heartbeat ON: the scene is settled, "
                       "WM_TIMER every %u ms so a standing-still player still "
                       "gets a tick", kHeartbeatMs);
            } else {
                FW_WRN("[main_menu] SetTimer failed (err=%lu) — the tick keeps "
                       "running only on real window messages", GetLastError());
            }
        } else if (!want && s_heartbeat_on) {
            KillTimer(hwnd, kHeartbeatTimerId);
            s_heartbeat_on = false;
            FW_LOG("[main_menu] tick heartbeat OFF: the scene is not settled "
                   "(a load, a cell change or a 3D rebuild) — staying out of "
                   "the engine's way until it is");
        }
    }

    // THE TOGGLE KEY COMES FIRST. Before the editor is offered the message,
    // because the editor swallows WM_KEYDOWN while it is open — so handling the
    // toggle after it meant the key that CLOSES the panel could never arrive.
    // That is a trap-the-user bug and it existed for exactly one build.
    if (msg == WM_KEYDOWN && (lp & 0x40000000) == 0) {
        const std::uint32_t want = g_editor_key;
        if (want != 0 && static_cast<std::uint32_t>(wp) == want) {
            const bool now_open = !fw::native::appearance::editing();
            fw::native::appearance::set_editing(now_open);
            FW_LOG("[editor] key 0x%02X -> editor %s",
                   want, now_open ? "OPEN" : "CLOSED");
            // The key only moves the flag here too. editor::on_frame takes and
            // releases the input capture from the flag itself, so a ritual the
            // server asked for gets the same capture a keypress would.
            // The key only moves the FLAG. chargen_stage::sync does the teleport
            // on the next tick, and that is the point: the staging used to hang
            // off this key handler, so a ritual the SERVER asked for opened the
            // panel and left the player on the ground. One driver now, whoever
            // asks.
            return 0;   // swallow it; nothing downstream wants this key
        }
        // CAMERA CALIBRATION KEY (F3), and it is deliberately hard-wired rather
        // than configurable: it is a temporary aid that disappears the moment the
        // camera's yaw offset is known. It sits here beside the toggle for the
        // same reason the toggle is first — the editor swallows WM_KEYDOWN while
        // it is open, so a key handled after it would never arrive.
        if ((static_cast<std::uint32_t>(wp) == VK_F3 ||
             static_cast<std::uint32_t>(wp) == VK_F4) &&
            fw::native::appearance::editing()) {
            fw::native::chargen_stage::nudge_camera_yaw(
                static_cast<std::uint32_t>(wp) == VK_F4);
            return 0;
        }
        if ((static_cast<std::uint32_t>(wp) == VK_F5 ||
             static_cast<std::uint32_t>(wp) == VK_F6) &&
            fw::native::appearance::editing()) {
            // F6 out, F5 in. A larger setting value is further away.
            fw::native::chargen_stage::nudge_camera_zoom(
                /*further=*/static_cast<std::uint32_t>(wp) == VK_F6);
            return 0;
        }
    }

    // THE EDITOR EATS INPUT NEXT, when it is open.
    //
    // Before anything else looks at the message, because while the panel is up
    // the mouse and keyboard belong to it. Returns true only for messages it
    // consumed; everything else falls through untouched, and when the editor is
    // closed this costs one atomic read.
    //
    // WM_ACTIVATE is never handed over: it is the only path that restores the
    // engine's input gate and resumes audio, so swallowing it would strand both.
    if (msg != WM_ACTIVATE &&
        fw::render::editor::wndproc(hwnd, msg, wp, lp)) {
        return (msg == WM_SETCURSOR) ? TRUE : 0;
    }
    // Build 67 — main-thread liveness heartbeat (stall watchdog forensics).
    // Win32 dispatches this proc on the window-owning thread = the game main
    // thread, so a stale heartbeat == the main thread stopped pumping.
    fw::dispatch::note_main_thread_alive();
    // Build 69r (2026-08-04) — user-requested ALT+F4 marker. A force-close
    // tears the process down with threads still running, and our
    // first-priority VEH faithfully logs the dying process's AVs as if they
    // were gameplay crashes (documented teardown signature 0x16632B9,
    // CHANGELOG v0.6.1) — which twice sent a crash hunt down a false trail.
    // Stamp the log the moment the close is requested and tell the VEH, so
    // every later AV line carries teardown=1.
    if (msg == WM_CLOSE ||
        (msg == WM_SYSCOMMAND && (wp & 0xFFF0) == SC_CLOSE)) {
        FW_LOG("ALT+F4 DETECTED BY USER — window close requested; any AV "
               "logged after this line is process-teardown fallout, NOT a "
               "gameplay crash");
        fw::diag::note_user_shutdown();
        // E lo diciamo al server MENTRE possiamo ancora parlare. Da qui in
        // poi il processo scende, e il thread di rete potrebbe non girare
        // piu': l'addio si spedisce subito, su questo thread. Senza, gli
        // altri ci vedono in piedi per altri cinque secondi e la nostra
        // power armor non torna nel mondo fino al timeout.
        fw::net::client().send_goodbye_now(/*reason=*/0);
    }
    // Build 68.4 — bone-cache lifetime sweep. Hosted here because this is the
    // one unconditional main-thread tick we have that keeps running regardless
    // of ownership, cell state or whether any NPC is being mirrored. It
    // self-throttles to ~250 ms internally.
    fw::native::sweep_npc_bone_caches();
    // 2026-08-06 — character-creation catalogue. Self-disarming: it walks
    // TESDataHandler's form arrays once, as soon as they hold anything, and
    // never runs again. A no-op unless the dump was armed from the ini.
    // 2026-08-08 — the editor toggle key. Handled BEFORE the appearance tick
    // below so that opening the editor and face_borrow standing aside happen on
    // the same frame, with no window in which a borrow could start.
    //
    // WM_KEYDOWN is safe to read here and cannot double-fire a game action: the
    // game's own window procedure has no WM_KEYDOWN case, it reads keyboard
    // exclusively through WM_INPUT, and it registers raw input with flags 0 (no
    // RIDEV_NOLEGACY) so the legacy messages are still generated for us.
    //
    // The repeat-count guard matters — holding the key down otherwise flips the
    // flag every auto-repeat.
    // IL BLOCCO DI TICK NON GIRA DENTRO SE STESSO.
    //
    // Trovato il 2026-09-18 con la mappa dei simboli appena aggiunta. Il
    // client B si e' piantato per sempre subito dopo la schermata di
    // caricamento, col thread principale fermo in un'attesa dentro ntdll, e
    // nello stack c'era `fw_wndproc` DUE VOLTE. Questa e' l'unica lettura
    // possibile: qualcosa qui dentro chiama il motore, il motore pompa la
    // coda dei messaggi, e il nostro WndProc rientra mentre il giro
    // precedente e' ancora a meta'. Se quel giro tiene un lucchetto — e qui
    // dentro se ne prendono parecchi, dalla mappa delle armature alla lista
    // canonica — il giro annidato lo richiede, e uno std::mutex non e'
    // rientrante. Fine.
    //
    // Chi pompa, qui dentro: face_borrow chiama Actor::Reset3D,
    // chargen_stage teletrasporta, world_spawn piazza oggetti. Tutte cose
    // che durante un caricamento ci mettono parecchio.
    //
    // E il motivo per cui e' esploso ADESSO e' altrettanto documentato:
    // questo blocco girava solo sui messaggi veri, e con un ghost assente
    // il battito delle ossa non ne mandava. Da oggi arrivano un WM_TIMER
    // ogni 33 ms e un tick delle ossa ogni 50, quindi il blocco gira ANCHE
    // durante il caricamento, che e' esattamente la finestra che la vecchia
    // grazia da trenta secondi teneva sgombra "per sicurezza, perche'
    // caricare durante il caricamento iniziale faceva crashare".
    //
    // La guardia e' una variabile del thread principale e basta: un giro
    // annidato salta il blocco e basta. Non si perde niente, perche' qui
    // dentro e' tutto un sondaggio: quello che non fa questo giro lo fa il
    // prossimo, trentatre millisecondi dopo.
    struct TickReentryGuard {
        static bool& flag() { static bool in_tick = false; return in_tick; }
        bool taken;
        TickReentryGuard() : taken(!flag()) { if (taken) flag() = true; }
        ~TickReentryGuard() { if (taken) flag() = false; }
    } tick_guard;
    if (tick_guard.taken) {
        static const std::uintptr_t s_base = reinterpret_cast<std::uintptr_t>(
            GetModuleHandleW(L"Fallout4.exe"));
        fw::native::chargen_dump::maybe_dump_catalogue(s_base);
        // 2026-08-07 — the anatomy probe MUST run here and nowhere else:
        // it reads the live scene graph, which is main-thread-only. The
        // chargen catalogue moved off this tick because the WndProc is not
        // installed when auto_load_save is empty; the probe does not have
        // that problem, since looking at the player presupposes a loaded
        // game and a loaded game presupposes this subclass.
        fw::native::anatomy_probe::maybe_dump(s_base);
        // 2026-08-08 — same reason as the probe above: it touches
        // engine appearance state and must be on the main thread.
        fw::native::chargen_selftest::maybe_run(s_base);
        // v20 — publish my appearance to the server when it changes.
        // Main thread: it reads the live TESNPC. Self-throttled.
        fw::native::appearance::publish_if_changed(s_base);
        // v20 — build any peer face we have a recipe for but no master.
        // One at a time; cheap when there is nothing to do.
        fw::native::face_borrow::tick(s_base);
        // Bring the staged world into line with the editor's flag: teleport up
        // when it goes on, back down when it goes off, retrying while the save
        // is still loading. Here rather than in Present because it teleports,
        // and the teleport has always run on this tick.
        fw::native::chargen_stage::sync(s_base);
        // And the input capture, for the same reason and in the same place. It is
        // also reconciled from editor::on_frame, but that runs on Present's main
        // thread, which starts late: the log showed the capture landing ten
        // seconds after the server asked for the ritual, and the game reads the
        // mouse for every one of those seconds. This tick runs first. Both call
        // sites are idempotent -- they act only when the state disagrees.
        {
            const bool want = fw::native::appearance::editing();
            if (fw::render::editor::input_captured() != want) {
                fw::render::editor::set_input_captured(s_base, want);
            }
        }
        // Keeps collision off while staged; Reset3D undoes it.
        fw::native::chargen_stage::tick(s_base);
        // B6.14 - place spawned world objects the server relayed. Engine
        // work, so it lives on this tick like everything else that touches
        // the scene.
        fw::native::world_spawn::tick(s_base);
        // Fase 2 - il ghost dei peer nasce e muore col ciclo di vita
        // della sessione invece che con un timer. Vive qui per lo
        // stesso motivo di tutto il resto: ogni mutazione del grafo
        // di scena e' solo main-thread, e questo e' l'unico tick
        // incondizionato che abbiamo.
        fw::native::ghost_lifecycle::tick(s_base);
    }
    // Il nostro battito si ferma qui: il blocco di tick qui sopra l'ha gia'
    // consumato, e il gioco non sa niente di questo timer.
    if (msg == WM_TIMER && wp == kHeartbeatTimerId) return 0;

    if (msg == FW_MSG_LOAD_GAME) {
        // We're on the main (UI) thread — MinHook-level guarantees don't
        // apply here (no MinHook involved), but Win32 semantics do:
        // WndProc is dispatched on the thread that owns the window.
        bool expected = false;
        if (!g_load_dispatched.compare_exchange_strong(expected, true)) {
            FW_DBG("[main_menu] FW_MSG_LOAD_GAME received but already dispatched");
            return 0;
        }
        FW_LOG("[main_menu] WM_APP+0x42 received on WndProc main thread — "
               "invoking engine LoadGame('%s')", g_save_name.c_str());
        // Il ghost non va costruito mentre siamo qui dentro. Questa
        // chiamata BLOCCA per secondi (sei, misurati) e nel frattempo il
        // motore pompa la coda dei messaggi, quindi il blocco di tick qui
        // sopra continua a girare — PEER_JOIN compreso, che viene drenato
        // proprio da li'. Vedi il cancello sopra ghost_scene_is_stable.
        fw::native::ghost_note_load_begin();
        const bool ok = fw::engine::load_game_by_name(g_save_name.c_str());
        fw::native::ghost_note_load_end();
        if (!ok) {
            FW_WRN("[main_menu] LoadGame returned failure — main menu stays up");
            return 0;
        }
        // B8 force-equip-cycle — DISABLED 2026-05-08.
        //
        // Was: post-LoadGame BipedAnim normalize via direct engine call to
        // ActorEquipManager::Unequip + Equip on the Vault Suit. Workaround
        // for an M8P3-era ghost-pointer-sharing bug where the first equip
        // event after peer-connect crashed due to "semi-allocated"
        // BipedAnim state. See `re/B8_force_equip_cycle.log` and the
        // `offsets.h` "B8 force-equip-cycle" comment block for the
        // original architectural rationale.
        //
        // Why disabled: B8's engine call AV'd internally on every boot
        // (caught by our SEH wrapper, hidden from the user). The half-
        // completed equip left engine state subtly corrupted; the
        // corruption was dormant during normal play but surfaced as a
        // deterministic main-thread freeze when crossing the Sanctuary→
        // Red Rocket bridge — heavy exterior cell-streaming re-triggered
        // the corrupted auto-equip code path on a BSJobs PostMainRender
        // worker, killing it silently and wedging JobListMgr+0x60 on an
        // INFINITE wait. Live test 2026-05-08 confirmed: B8 enabled =
        // bridge crashes, B8 disabled = bridge works + clothes change
        // still works (the original M8P3 bug B8 was fixing has been
        // resolved as a side effect of later M9 work).
        //
        // The secondary role B8 played as a side effect — broadcasting
        // initial apparel state to peers via the engine equip events it
        // generated — is replaced by the `equip_announce` scaffold (see
        // `hooks/equip_announce.h`, NON TESTATO).
        //
        // Files left in repo for archeological reference:
        //   - hooks/equip_cycle.{h,cpp} (still compiled but never invoked)
        //   - offsets.h B8 block (rationale + RE'd engine fn signatures)
        //
        // To revive: uncomment the arm call below. Don't, until the
        // engine AV inside sub_140CE5900 is understood and fixed at the
        // arg/timing level — see `re/B8_force_equip_cycle.log` for the
        // deepest level of stack/arg analysis we have.
        // fw::hooks::arm_equip_cycle_after_loadgame(10000);
        return 0;
    }
    // B1.l: CONTAINER_BCAST apply. Drains any container ops that the net
    // thread enqueued via fw::dispatch::enqueue_container_apply. This is
    // the main-thread-safe counterpart to engine::apply_container_op_to_
    // engine — Bethesda's engine requires inventory mutations to happen
    // on the main thread, otherwise stale ContainerMenu view state can
    // corrupt the player's inventory (observed 2026-04-21 live test).
    if (msg == fw::dispatch::FW_MSG_CONTAINER_APPLY) {
        fw::dispatch::drain_container_apply_queue();
        return 0;
    }
    // B6.1: drain remote door-activate queue on main thread. Same rationale
    // as container apply — Activate worker fires anim graph notify which
    // mutates the scene's per-cell anim state; not net-thread-safe.
    if (msg == fw::dispatch::FW_MSG_DOOR_APPLY) {
        fw::dispatch::drain_door_apply_queue();
        return 0;
    }
    // B6.3 v0.5.3: drain remote lock events. Each op resolves form_id +
    // (base, cell) identity, then calls Papyrus binding sub_141158640
    // with ai_notify=0 — no minigame, no key consumption, no AI events.
    if (msg == fw::dispatch::FW_MSG_LOCK_APPLY) {
        fw::dispatch::drain_lock_apply_queue();
        return 0;
    }
    // B6.5w3.b: drain remote NPC state-broadcast entries. Each entry
    // resolves form_id, writes pos/yaw directly to Actor fields, and
    // sets anim graph variables to drive the engine's animation tree
    // (no AI suppression yet — B6.5w4 lands the local-tick filter).
    if (msg == fw::dispatch::FW_MSG_NPC_STATE_APPLY) {
        fw::dispatch::drain_npc_state_apply_queue();
        return 0;
    }
    // Build 65.c.10 — owner-driven STATE_FROM_OWNER apply (receiver side).
    // Drains entries the net thread queued from server-relayed owner state.
    if (msg == fw::dispatch::FW_MSG_NPC_OWNER_STATE_APPLY) {
        fw::dispatch::drain_npc_owner_state_apply_queue();
        return 0;
    }
    // Build 65.c.47 WEDGE3 — owner-driven DEATH_FROM_OWNER apply (non-owner
    // side). Drains relayed owner deaths: un-keyframe → place at synced pos →
    // engine Actor::Kill (under ApplyingRemoteGuard). Main-thread-required:
    // the engine death handler touches cell + anim + Havok state.
    if (msg == fw::dispatch::FW_MSG_NPC_DEATH_APPLY) {
        fw::dispatch::drain_npc_death_apply_queue();
        return 0;
    }
    // HP bar (vita-locale-dal-pool) — set each tracked NPC's LOCAL Health to the
    // shared server pool so the vanilla enemy-health bar reads it. Main-thread-
    // required (AVO getter + the HP funnel are main-thread-affine).
    if (msg == fw::dispatch::FW_MSG_NPC_POOL_HEALTH_APPLY) {
        fw::dispatch::drain_npc_pool_health_queue();
        return 0;
    }
    // B6.6w1: drain remote NPC fire events. Each op resolves form_id →
    // Actor* and calls engine::fire_actor_weapon — Projectile::Launch +
    // muzzle flash + audio + damage. Native fns touch equipManager +
    // projectile lists not lock-protected → main thread required.
    if (msg == fw::dispatch::FW_MSG_NPC_FIRE) {
        fw::dispatch::drain_npc_fire_queue();
        // Build 62 — drain perception trigger queue on the same wake-up.
        // Both queues need main-thread engine calls; sharing the WndProc
        // message avoids a second PostMessage round-trip. Order doesn't
        // matter (perception triggers cause CCF810 alloc, fires use the
        // result — but they're separately enqueued by net thread).
        fw::dispatch::drain_npc_perception_trigger_queue();
        return 0;
    }
    // M9 wedge 2: drain remote equip events. Each op resolves form_id →
    // ARMA → 3rd-person NIF path and attaches/detaches on the ghost.
    // Engine NIF loader + scene graph mutation = main-thread-required.
    // See offsets.h "M9 wedge 2" comment block for layout + flow.
    if (msg == fw::dispatch::FW_MSG_EQUIP_APPLY) {
        fw::dispatch::drain_equip_apply_queue();
        return 0;
    }
    // M9 wedge 4 v9: drain remote mesh-blob events. Each blob carries N
    // BSGeometry leaves (positions + indices + per-mesh metadata) and the
    // main thread reconstructs them on the matching ghost weapon root via
    // the engine's clone factory. Like equip apply, this MUST run on the
    // main thread (scene graph mutation; allocator TLS cookies).
    if (msg == fw::dispatch::FW_MSG_MESH_BLOB_APPLY) {
        fw::dispatch::drain_mesh_blob_apply_queue();
        return 0;
    }
    // M9 w4 v9 deferred mesh-tx: 300ms post-equip walker re-run on the
    // sender side. Lets the engine's runtime weapon assembly complete
    // before we capture mesh data → fixes "walker returned 0 meshes"
    // on rapid/subsequent equips.
    if (msg == fw::hooks::FW_MSG_DEFERRED_MESH_TX) {
        fw::hooks::on_deferred_mesh_tx_message();
        return 0;
    }
    // 2026-05-07 — auto re-equip cycle (sender-side workaround for the
    // off-by-one render bug on the ghost). See equip_hook.cpp on_auto_re_
    // equip_message comment block.
    if (msg == fw::hooks::FW_MSG_AUTO_RE_EQUIP) {
        fw::hooks::on_auto_re_equip_message(wp);
        return 0;
    }
    // SPAI Tier 1: force-prewarm one weapon NIF into the engine resmgr.
    // Posted by spai::prewarm_worker (background thread, throttled 1
    // post per ~10–15 ms) for each entry in the offline-generated weapon
    // catalog. Drives a single internal cursor — past the end is a
    // no-op modulo a one-shot summary log line.
    if (msg == fw::dispatch::FW_MSG_SPAI_PREWARM) {
        fw::native::spai::on_prewarm_message();
        return 0;
    }
    // M9.w4 PROPER (v0.4.2+, 2026-05-04): TTL expiration of a weapon capture
    // window. Worker thread spawned by weapon_capture::arm() posts this msg
    // after `ttl_ms` so finalize_and_ship() runs on the engine main thread
    // (where extraction + wire ship are safe). Phase 1: log-only finalize.
    if (msg == fw::native::weapon_capture::FW_MSG_WEAPON_CAPTURE_FINALIZE) {
        fw::native::weapon_capture::on_finalize_message();
        return 0;
    }
    // M9 closure (2026-05-07) note: an earlier iteration used a
    // FW_MSG_REFR_POLL pump for an async synthetic-REFR design. That
    // design was retired (see re/COLLAB_FOLLOWUP_vt170.md — vt[170]
    // was a flag-setter, not a loader). The current path is fully
    // synchronous (synthetic_refr::assemble_modded_weapon returns
    // BSFadeNode* directly), so no pump is needed here.
    // Z.2 (Path B): spawn ghost actor on main thread. PlaceAtMe is
    // TLS-sensitive and takes the REFR cell-attach lock — must run
    // here, not on the net thread where request_spawn is issued.
    if (msg == fw::ghost::FW_MSG_SPAWN_GHOST) {
        fw::ghost::on_spawn_message();
        return 0;
    }
    // Strada B M1: attach a debug NiNode to the ShadowSceneNode. Main-
    // thread affinity required (scene graph array has implicit locks held
    // by the render walk; our allocator call writes TLS cookies). Posted
    // by fw::native::arm_injection_after_boot's worker ~30s after DLL init.
    if (msg == fw::native::FW_MSG_STRADAB_INJECT) {
        fw::native::on_inject_message();
        return 0;
    }
    // Strada B M3: per-frame cube position update from remote snapshot.
    // Posted by fw::native::arm_worker's tracker loop (up to ~10/sec).
    if (msg == fw::native::FW_MSG_STRADAB_POS_UPDATE) {
        fw::native::on_pos_update_message();
        return 0;
    }
    // Strada B M7.b: bone-copy tick from local player to ghost. Posted
    // by bone_tick_worker at 20Hz. Runs regardless of peer activity.
    if (msg == fw::native::FW_MSG_STRADAB_BONE_TICK) {
        fw::native::on_bone_tick_message();
        return 0;
    }
    // M8P3.15: apply received remote pose (POSE_BROADCAST) to ghost.
    // Posted by net thread after stashing quats into shared slot.
    if (msg == fw::native::FW_MSG_STRADAB_POSE_APPLY) {
        fw::native::on_pose_apply_message();
        return 0;
    }
    // v16: apply received remote crouch (POSE_CROUCH_BROADCAST) to ghost —
    // SEPARATE additive channel beside the rotation pose above. Posted by
    // net thread after stashing the COM/Pelvis translations.
    if (msg == fw::native::FW_MSG_STRADAB_CROUCH_APPLY) {
        fw::native::on_pose_crouch_apply_message();
        return 0;
    }
    // c.37.0: apply received NPC pose (NPC_POSE_FROM_OWNER) to the mirror
    // Actor. Posted by net thread after stashing quats into the per-fid slot.
    if (msg == fw::native::FW_MSG_STRADAB_NPC_POSE_APPLY) {
        fw::native::on_npc_pose_apply_message();
        return 0;
    }
    // B8: post-LoadGame BipedAnim normalize cycle. Two-phase:
    //   - WM_APP+0x4A → unequip Vault Suit
    //   - WM_APP+0x4B → re-equip Vault Suit (500ms later, posted by worker)
    // Both run on this thread (main/UI thread guaranteed by Win32 WndProc
    // dispatch). Engine ActorEquipManager calls take per-actor locks +
    // mutate BipedAnim — main-thread is required.
    // See offsets.h "B8 force-equip-cycle" comment block for rationale.
    if (msg == (WM_APP + 0x4A)) {
        fw::hooks::on_force_equip_cycle_unequip_message();
        return 0;
    }
    if (msg == (WM_APP + 0x4B)) {
        fw::hooks::on_force_equip_cycle_equip_message();
        return 0;
    }
    // Forward everything else to the original WndProc.
    if (g_orig_wndproc) {
        return CallWindowProcW(g_orig_wndproc, hwnd, msg, wp, lp);
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

// Install the WndProc subclass once we have a valid HWND. Called from the
// worker thread after the main menu registrar has fired (by then the
// window definitely exists — it had to exist to render the menu anyway).
bool install_wndproc_subclass() {
    if (g_orig_wndproc) return true;  // already installed
    g_fo4_hwnd = find_fo4_hwnd();
    if (!g_fo4_hwnd) {
        FW_WRN("[main_menu] find_fo4_hwnd returned nullptr — cannot subclass WndProc");
        return false;
    }
    // SetWindowLongPtrW returns the previous value (original WndProc).
    // We save it for CallWindowProcW forwarding.
    const LONG_PTR prev = SetWindowLongPtrW(
        g_fo4_hwnd, GWLP_WNDPROC,
        reinterpret_cast<LONG_PTR>(&fw_wndproc));
    if (prev == 0) {
        FW_ERR("[main_menu] SetWindowLongPtr(GWLP_WNDPROC) failed (err=%lu)",
               GetLastError());
        return false;
    }
    g_orig_wndproc = reinterpret_cast<WNDPROC>(prev);
    FW_LOG("[main_menu] WndProc subclassed on hwnd=%p (orig=%p)",
           g_fo4_hwnd, g_orig_wndproc);

    // B1.l: share the HWND with the main-thread dispatch queue so net
    // thread can post FW_MSG_CONTAINER_APPLY for remote container ops.
    fw::dispatch::set_target_hwnd(g_fo4_hwnd);
    return true;
}

// ----------------------------------------------------------------- worker
//
// Background thread:
//   1) Waits for g_menu_detected (set by the MainMenu registrar detour).
//   2) Sleeps g_delay_ms to let the menu fully render + become idle.
//   3) Installs WndProc subclass on FO4 hwnd.
//   4) PostMessage(FW_MSG_LOAD_GAME) → main thread catches it via WndProc.
std::thread g_worker_thread;
std::atomic<bool> g_worker_should_stop{false};

void worker_thread_main() {
    FW_LOG("[main_menu] worker armed, delay=%ums after registrar hit",
           g_delay_ms);
    while (!g_worker_should_stop.load() && !g_menu_detected.load()) {
        Sleep(50);
    }
    if (g_worker_should_stop.load()) return;

    const auto t0 = std::chrono::steady_clock::now();
    const auto deadline = t0 + std::chrono::milliseconds(g_delay_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (g_worker_should_stop.load()) return;
        Sleep(50);
    }

    // Now the menu should be fully visible and idle. Install subclass +
    // post the message.
    bool expected = false;
    if (!g_load_queued.compare_exchange_strong(expected, true)) {
        FW_DBG("[main_menu] worker: load already queued");
        return;
    }
    if (!install_wndproc_subclass()) {
        FW_ERR("[main_menu] worker: subclass install failed — LoadGame will NOT fire");
        return;
    }
    if (!PostMessageW(g_fo4_hwnd, FW_MSG_LOAD_GAME, 0, 0)) {
        FW_ERR("[main_menu] worker: PostMessage failed (err=%lu)", GetLastError());
    } else {
        FW_LOG("[main_menu] worker: FW_MSG_LOAD_GAME posted to hwnd=%p", g_fo4_hwnd);
    }
}

// ----------------------------------------------------------------- detour

void* __fastcall detour_main_menu_register(void* menu_obj) {
    // Let the original registrar complete first — AS3 bindings must be in
    // place or the menu breaks.
    void* rv = g_orig_main_menu_register(menu_obj);

    // One-shot detection. MinHook invokes the detour on the caller's
    // thread, so this runs on the engine's main UI thread.
    bool expected = false;
    if (!g_menu_detected.compare_exchange_strong(expected, true)) {
        FW_DBG("[main_menu] registrar re-entry (submenu) — ignoring");
        return rv;
    }

    if (g_save_name.empty()) {
        FW_LOG("[main_menu] registrar hit (menu_obj=%p) — auto-load disabled "
               "(auto_load_save empty in fw_config.ini)", menu_obj);
        return rv;
    }

    FW_LOG("[main_menu] registrar hit (menu_obj=%p) — deferred LoadGame "
           "scheduled in %ums (worker thread will post WM_APP to WndProc)",
           menu_obj, g_delay_ms);
    return rv;
}

} // namespace

bool install_main_menu_hook(std::uintptr_t module_base,
                            const fw::config::Settings& cfg)
{
    g_save_name = cfg.auto_load_save;
    g_editor_key = cfg.editor_key;
    if (g_editor_key) {
        FW_LOG("[editor] toggle key armed: virtual-key 0x%02X", g_editor_key);
    }
    // Reuse `auto_continue_delay_ms` as the worker delay. Clamp so a
    // misconfigured 0 doesn't race the menu.
    g_delay_ms = cfg.auto_continue_delay_ms;
    if (g_delay_ms < 1000)  g_delay_ms = 1000;
    if (g_delay_ms > 30000) g_delay_ms = 30000;

    const auto target_ea = module_base + offsets::MAIN_MENU_REGISTRAR_RVA;
    void* target = reinterpret_cast<void*>(target_ea);

    const bool ok = install(
        target,
        reinterpret_cast<void*>(&detour_main_menu_register),
        reinterpret_cast<void**>(&g_orig_main_menu_register));
    if (!ok) {
        FW_ERR("[main_menu] hook install FAILED at 0x%llX",
               static_cast<unsigned long long>(target_ea));
        return false;
    }
    if (g_save_name.empty()) {
        FW_LOG("[main_menu] hook installed at 0x%llX — auto_load_save empty, "
               "no load action configured",
               static_cast<unsigned long long>(target_ea));
        return true;  // don't spin worker if nothing to do
    }

    FW_LOG("[main_menu] hook installed at 0x%llX — auto-load target: '%s' "
           "(delay %ums after registrar hit)",
           static_cast<unsigned long long>(target_ea),
           g_save_name.c_str(), g_delay_ms);

    // Spawn worker thread. Detached; lifecycle tied to process exit.
    g_worker_thread = std::thread(&worker_thread_main);
    g_worker_thread.detach();
    return true;
}

} // namespace fw::hooks
