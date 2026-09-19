// Fase 2 — il ghost nasce e muore col ciclo di vita della sessione.
//
// WHAT THIS IS. The registry that finally makes "that peer's ghost" an
// addressable thing. Until now the remote body was a single global pointer
// born from a one-shot timer thirty seconds after the process started, and
// PEER_LEAVE was a log line: a player who quit stayed standing in the world
// forever, frozen at their last position. The TODO above PEER_LEAVE in
// net/client.cpp names the blocker exactly — "g_injected_cube is a single
// pointer, so 'that peer's ghost' is not yet an addressable thing" — and
// this module is that addressability.
//
// WHY AN EVENT/TICK SPLIT. The shape is prescribed by the comment above
// arm_worker in scene_inject.cpp, written after the crash it describes:
// PEER_JOIN records that a ghost is NEEDED and must never touch the scene
// graph itself; a main-thread worker injects only once the scene is proven
// stable, and it must be re-armed after every LoadGame, because a save or
// cell reload destroys the ShadowSceneNode and every ghost hanging off it.
// The old thirty-second grace existed to guess that moment once. A tick
// checks it every time instead of guessing, which is also the only way a
// peer who joins at minute forty gets a body.
//
// WHY POLLING AND NOT A HOOK. The same reason world_spawn polls for object
// death rather than hooking the engine's teardown: "the death-crash history
// says hooks on destruction paths bite". Scene staleness is detected by
// comparing the ShadowSceneNode pointer against the one a ghost was built
// on, which is the trick the bone-copy cache already uses to notice a
// re-injected body.
//
// THREADING. on_peer_join / on_peer_leave are called from the NETWORK
// thread and only queue. tick() runs on the MAIN thread, from the
// unconditional WndProc tick next to world_spawn::tick, and is the only
// place allowed to touch the scene graph — every mutation in this project
// is main-thread-only.
//
// SCOPE NOTE (2026-09-18, closed 2026-09-19). The registry is per-peer from
// the first line, because the project is aimed at about ten players and every
// structure built for two has had to be rebuilt later.
//
// The three things this note listed as still single are now per-peer, in the
// later step of this phase that it promised: the ghost skeleton is a private
// deep clone that dies with its body, the power-armour graft and bind-save
// live in GhostRecord, and the pose and crouch slots are gone entirely (the
// apply handlers iterate the registry). The single body pointer they all hung
// off, g_injected_cube, no longer exists: no line of code in the ghost path
// reads a single-peer global any more.
#pragma once

#include <cstddef>
#include <cstdint>

namespace fw::native::ghost_lifecycle {

// What the registry knows about one remote player's body.
enum class State : std::uint8_t {
    // The peer is here and wants a body; the scene was not ready yet.
    Requested = 0,
    // The body exists and is attached to the ShadowSceneNode.
    Alive = 1,
    // The body was built on a ShadowSceneNode that no longer exists (a
    // LoadGame happened). It must be rebuilt, not reused.
    Stale = 2,
};

// NETWORK THREAD. A peer joined: remember that a ghost is needed. Never
// touches the scene graph. Safe to call more than once for the same peer —
// a resumed session replays the whole join bootstrap, PEER_JOIN included.
void on_peer_join(const char* peer_id);

// NETWORK THREAD. A peer left, or our own session dropped and the server
// told us. Remember that the ghost must go; the tick performs the teardown
// in the order the ordering law above detach_debug_cube prescribes.
void on_peer_leave(const char* peer_id);

// NETWORK THREAD. E' arrivata una posizione da quel peer. Tiene solo una
// data, e quella data serve soltanto a OSSERVARE il silenzio, non ad
// agire.
//
// Nata come rete di sicurezza per "il PEER_LEAVE si e' perso" e ritirata da
// quel ruolo il giorno stesso: quel messaggio il server lo manda
// ritrasmesso fino all'ack, quindi non si perde, e la rete ha smontato il
// ghost di un giocatore che stava solo respawnando. Chi e' presente lo
// decide il server. Vedi il blocco SILENZIO nel tick.
//
// Mutex suo, NON quello del registro: questa la chiama il thread di rete a
// ~20 Hz per peer, e il mutex del registro resta preso per tutta la durata
// di uno smontaggio, che e' lavoro di scena.
void on_peer_position(const char* peer_id);

// NETWORK THREAD. Our own session dropped or came back. While we are down
// the other players keep playing, so their bodies are hidden rather than
// left standing as statues, and shown again when the presence bootstrap has
// put them back where they belong.
void on_local_session_lost();
void on_local_session_restored();

// MAIN THREAD ONLY. Drains the queued events, notices a ShadowSceneNode
// that has been replaced under us, and drives creation and teardown.
void tick(std::uintptr_t module_base);

// Diagnostics, any thread.
std::size_t live_count();

// MAIN THREAD ONLY. Tear everything down, for DLL_PROCESS_DETACH.
void shutdown();

}  // namespace fw::native::ghost_lifecycle
