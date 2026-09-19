#include "ghost_lifecycle.h"

#include <windows.h>

#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "scene_inject.h"
#include "../log.h"

namespace fw::native::ghost_lifecycle {
namespace {

// One remote player's body and everything that hangs off it.
//
// This step only carries the identity and the state: the node pointers and
// the per-peer caches move in here one at a time in the following steps, so
// that each move is a change that can be compiled, deployed and watched on
// its own. Adding them all at once to a file with this crash history is
// exactly how the past regressions happened.
struct Record {
    std::string   peer_id;
    State         state = State::Requested;
    // The ShadowSceneNode this body was attached to. A LoadGame destroys
    // that node and everything under it, so a pointer that no longer
    // matches the live one means the body is gone whatever we think.
    void*         ssn_at_build = nullptr;
    // Hidden because OUR session is down, not because the peer left.
    bool          hidden_for_local_outage = false;
    // L'avviso "ne rendiamo uno solo" si scrive una volta, non a ogni tick.
    bool          second_peer_logged = false;
    // Idem per il silenzio: una riga quando comincia, una quando finisce.
    bool          silence_logged = false;
    std::uint64_t requested_at_ms = 0;
};

enum class EventKind : std::uint8_t { Join, Leave };

struct Event {
    EventKind   kind;
    std::string peer_id;
};

std::mutex                                     g_mtx;
std::unordered_map<std::string, Record>        g_ghosts;
std::deque<Event>                              g_events;
// Set while our own session is down. The peers are still playing; we simply
// cannot see them, so their bodies are hidden instead of standing frozen.
bool                                           g_local_outage = false;

std::uint64_t now_ms() { return GetTickCount64(); }

// Quanto silenzio da un peer prima di considerarlo andato, quando il
// PEER_LEAVE non e' arrivato. Dieci secondi sono il doppio abbondante del
// timeout del server (cinque): se il server l'ha buttato fuori, il suo
// PEER_LEAVE ha tutto il tempo di arrivare per primo, e questa rete prende
// solo il caso in cui quel messaggio si e' perso davvero.
constexpr std::uint64_t kSilenceBeforeGoneMs = 10000;

// Data dell'ultima posizione vista, per peer. Mutex SUO: vedi l'header.
std::mutex                                     g_pos_mtx;
std::unordered_map<std::string, std::uint64_t> g_last_pos_ms;

}  // namespace

void on_peer_join(const char* peer_id) {
    if (!peer_id || !*peer_id) return;
    std::lock_guard lk(g_mtx);
    g_events.push_back(Event{EventKind::Join, std::string(peer_id)});
}

void on_peer_position(const char* peer_id) {
    if (!peer_id || !*peer_id) return;
    std::lock_guard lk(g_pos_mtx);
    g_last_pos_ms[peer_id] = now_ms();
}

void on_peer_leave(const char* peer_id) {
    if (!peer_id || !*peer_id) return;
    std::lock_guard lk(g_mtx);
    g_events.push_back(Event{EventKind::Leave, std::string(peer_id)});
}

void on_local_session_lost() {
    std::lock_guard lk(g_mtx);
    if (g_local_outage) return;
    g_local_outage = true;
    FW_LOG("[ghost-life] our session is down: %zu ghost(s) will be hidden "
           "until it comes back", g_ghosts.size());
}

void on_local_session_restored() {
    std::lock_guard lk(g_mtx);
    if (!g_local_outage) return;
    g_local_outage = false;
    FW_LOG("[ghost-life] our session is back: %zu ghost(s) will be shown "
           "again once the presence bootstrap has repositioned them",
           g_ghosts.size());
}

std::size_t live_count() {
    std::lock_guard lk(g_mtx);
    std::size_t n = 0;
    for (const auto& [id, r] : g_ghosts) {
        if (r.state == State::Alive) ++n;
    }
    return n;
}

void tick(std::uintptr_t /*module_base*/) {
    // MAIN THREAD. Drain the events the network thread queued, then look at
    // the scene. This step does no scene work at all: it establishes the
    // registry and proves the plumbing, so the first landing cannot break
    // anything that already works.
    // La striscia di stabilita' avanza UNA volta per tick, qui, e non piu'
    // dentro la creazione del ghost: il suo verdetto serve anche al battito
    // del WndProc, che deve sapere quando il caricamento e' finito, e un
    // contatore chiamato da due posti conta il doppio.
    fw::native::ghost_scene_settle_tick();

    std::deque<Event> events;
    {
        std::lock_guard lk(g_mtx);
        events.swap(g_events);
    }

    for (const auto& e : events) {
        std::lock_guard lk(g_mtx);
        if (e.kind == EventKind::Join) {
            auto it = g_ghosts.find(e.peer_id);
            if (it != g_ghosts.end()) {
                // A resumed session replays the whole join bootstrap, so a
                // second PEER_JOIN for a peer we already track is normal and
                // must not rebuild anything.
                FW_DBG("[ghost-life] peer %s already tracked (state=%u) — "
                       "join ignored", e.peer_id.c_str(),
                       static_cast<unsigned>(it->second.state));
                continue;
            }
            Record r;
            r.peer_id         = e.peer_id;
            r.state           = State::Requested;
            r.requested_at_ms = now_ms();
            {
                // La data parte da adesso: un peer appena entrato non ha
                // ancora mandato niente e scadrebbe prima di esistere.
                std::lock_guard pl(g_pos_mtx);
                g_last_pos_ms[e.peer_id] = r.requested_at_ms;
            }
            g_ghosts.emplace(e.peer_id, std::move(r));
            FW_LOG("[ghost-life] peer %s joined: a ghost is needed "
                   "(%zu tracked)", e.peer_id.c_str(), g_ghosts.size());
        } else {
            auto it = g_ghosts.find(e.peer_id);
            if (it == g_ghosts.end()) {
                FW_DBG("[ghost-life] peer %s left but was not tracked",
                       e.peer_id.c_str());
                continue;
            }
            const State was = it->second.state;
            g_ghosts.erase(it);
            {
                std::lock_guard pl(g_pos_mtx);
                g_last_pos_ms.erase(e.peer_id);
            }
            // Corpo, testa e geometrie sono ancora condivisi in questa
            // tappa: si toccano solo quando se ne va l'ULTIMO peer.
            const bool last = g_ghosts.empty();
            FW_LOG("[ghost-life] peer %s left (was state=%u) — tearing its "
                   "ghost down (%zu still tracked)", e.peer_id.c_str(),
                   static_cast<unsigned>(was), g_ghosts.size());
            fw::native::ghost_teardown_for_peer(e.peer_id.c_str(), last);
        }
    }

    // Costruire quello che manca.
    //
    // Un corpo solo, ancora, ma la ragione e' cambiata il 2026-09-19 e va
    // detta giusta. Fino a quel giorno il rifiuto proteggeva da uno stato
    // condiviso: scheletro unico, slot di posa e crouch unici, due ghost che
    // si sarebbero mossi l'uno come l'altro. Quello stato non c'e' piu' — lo
    // scheletro e' un clone privato che muore col suo corpo, gli slot per
    // peer hanno sostituito quelli unici, e il censimento dei globali del
    // percorso ghost e' vuoto.
    //
    // Il cancello resta per una ragione piu' onesta e piu' debole: il percorso
    // a due ghost non e' MAI STATO ESEGUITO. Il collaudo e' a due client, e
    // ognuno dei due vede un peer remoto solo. Spedire un percorso mai girato
    // equivale a non averlo, e qui si preferisce una riga di rifiuto a un
    // difetto che si manifesta la prima volta che entra un terzo giocatore.
    // Si apre quando ci sara' un terzo client con cui provarlo.
    {
        std::lock_guard lk(g_mtx);
        bool someone_alive = false;
        for (const auto& [id, r] : g_ghosts) {
            if (r.state == State::Alive) { someone_alive = true; break; }
        }
        for (auto& [id, r] : g_ghosts) {
            if (r.state != State::Requested) continue;
            if (someone_alive) {
                if (!r.second_peer_logged) {
                    r.second_peer_logged = true;
                    FW_WRN("[ghost-life] peer %s also wants a body, but this "
                           "build renders ONE: the skeleton and the pose "
                           "slots are still shared. Refused on purpose "
                           "instead of served by accident.", id.c_str());
                }
                continue;
            }
            if (fw::native::ghost_create_if_ready(id.c_str())) {
                r.state = State::Alive;
                someone_alive = true;
                FW_LOG("[ghost-life] peer %s: body built", id.c_str());
            }
        }
    }

    // SILENZIO — si OSSERVA e basta. Non si smonta niente.
    //
    // RITIRATO il 2026-09-18, il giorno stesso, dopo un test dal vivo.
    // Qui c'era una "rete di sicurezza": dieci secondi senza posizione da un
    // peer e il suo ghost veniva smontato come se se ne fosse andato.
    //
    // Ha fatto esattamente il danno da cui doveva proteggere. Il client A e'
    // morto dai raider a Concord; durante la sequenza di morte e respawn ha
    // smesso di mandare posizioni per piu' di dieci secondi, e B gli ha
    // smontato il ghost. Il record spariva con lo smontaggio, quindi a
    // ricostruirlo non c'era piu' nessuno: A e' tornato a Sanctuary e B non
    // l'ha piu' visto per il resto della sessione.
    //
    // E la premessa era sbagliata in partenza. La rete doveva coprire "il
    // PEER_LEAVE si e' perso", ma quel messaggio il server lo manda con
    // send_reliable, cioe' registrato e RITRASMESSO fino all'ack: non si
    // perde, al massimo arriva tardi. Proteggevo da una cosa che non puo'
    // succedere e rompevo una cosa che succede eccome.
    //
    // Chi e' presente lo decide il SERVER. Un client non ha nessuna
    // informazione migliore della sua, e il silenzio di dieci secondi non e'
    // un'assenza: e' un caricamento, una morte, un respawn, o un menu.
    //
    // La riga resta perche' era diagnostica utile — e' cosi' che abbiamo
    // capito quanto dura un respawn — ma non tocca piu' niente.
    if (fw::native::ghost_scene_settled()) {
        const std::uint64_t now = now_ms();
        std::lock_guard lk(g_mtx);
        for (auto& [id, r] : g_ghosts) {
            if (r.state != State::Alive) continue;
            std::uint64_t last = 0;
            {
                std::lock_guard pl(g_pos_mtx);
                auto it = g_last_pos_ms.find(id);
                if (it != g_last_pos_ms.end()) last = it->second;
            }
            const bool quiet = (last != 0 && now - last > kSilenceBeforeGoneMs);
            if (quiet && !r.silence_logged) {
                r.silence_logged = true;
                FW_LOG("[ghost-life] peer %s: no position for %llu ms. Non "
                       "si tocca niente — chi e' presente lo dice il server, "
                       "e un silenzio cosi' e' un caricamento o un respawn.",
                       id.c_str(),
                       static_cast<unsigned long long>(now - last));
            } else if (!quiet && r.silence_logged) {
                r.silence_logged = false;
                FW_LOG("[ghost-life] peer %s: positions are back", id.c_str());
            }
        }
    }

    // SCENA STANTIA — il ghost che un caricamento si e' portato via.
    //
    // Si chiede al CORPO, non alla scena: vedi ghost_body_is_orphaned. Un
    // genitore nullo vuol dire che il nodo della scena e' stato distrutto e
    // che quel corpo non e' piu' nel mondo, per quanto la nostra mappa
    // continui a contenerlo.
    //
    // Cosa si fa: lo stesso smontaggio di un PEER_LEAVE, e poi i record
    // tornano in attesa. Non si ricostruisce qui: il cancello di
    // ghost_create_if_ready deve rifare il suo lavoro, e dopo un
    // caricamento ha parecchio da dire — la striscia riparte da zero, la
    // cella e' cambiata, e il corpo non nascera' prima che la scena sia di
    // nuovo assestata. Ricostruire di slancio qui dentro rimetterebbe il
    // ghost esattamente nella finestra che ci e' costata la giornata.
    {
        std::lock_guard lk(g_mtx);
        bool any_alive = false;
        for (const auto& [id, r] : g_ghosts) {
            if (r.state == State::Alive) { any_alive = true; break; }
        }
        if (any_alive && fw::native::ghost_body_is_orphaned()) {
            FW_WRN("[ghost-life] the body's parent went null — a LoadGame "
                   "took the scene node with it. Tearing the ghost(s) down "
                   "and asking for them again; the gate decides when.");
            // Lo smontaggio va fatto una volta sola sulle parti condivise,
            // quindi l'ULTIMO della lista porta last_ghost.
            std::size_t left = g_ghosts.size();
            for (auto& [id, r] : g_ghosts) {
                --left;
                r.state = State::Stale;
                fw::native::ghost_teardown_for_peer(id.c_str(), left == 0);
            }
            for (auto& [id, r] : g_ghosts) {
                r.state = State::Requested;
                r.requested_at_ms = now_ms();
                r.second_peer_logged = false;
            }
        }
    }
}

void shutdown() {
    std::lock_guard lk(g_mtx);
    const std::size_t n = g_ghosts.size();
    g_ghosts.clear();
    g_events.clear();
    if (n) FW_LOG("[ghost-life] shutdown: dropped %zu record(s)", n);
}

}  // namespace fw::native::ghost_lifecycle
