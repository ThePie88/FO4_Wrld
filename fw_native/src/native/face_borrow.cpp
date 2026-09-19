#include "face_borrow.h"

#include <windows.h>

#include <atomic>
#include <map>
#include <string>

#include "../log.h"
#include "appearance_recipe.h"
#include "anatomy_mirror.h"
#include "face_cache.h"
#include "scene_inject.h"
#include "skin_rebind.h"   // ancoraggio della maschera allo scheletro di riferimento

namespace fw::native::face_borrow {

namespace {

enum class State {
    Idle,        // nothing borrowed; free to start
    Applied,     // peer's recipe written, Reset3D issued, waiting for the head
    Restoring,   // giving the local player its own face back
    Wedged,      // a restore could not be verified — refuse to borrow again
};

State       g_state = State::Idle;
std::string g_peer;          // whose face is being built
std::string g_saved_recipe;  // OUR recipe, captured before anything was touched
std::uint64_t g_peer_hash = 0;
void*       g_face_before = nullptr;   // the player's face node before Reset3D
DWORD       g_since_ms    = 0;
DWORD       g_last_try_ms = 0;

std::atomic<std::uint32_t> g_test_hair{0};
bool                       g_test_done = false;
constexpr const char*      TEST_PEER = "__borrowtest";

std::atomic<std::uint32_t> g_completed{0};
std::atomic<std::uint32_t> g_abandoned{0};

// Generous: a head rebuild is a resource load, and a busy frame can push it
// out. The timeout exists to guarantee the restore happens, not to be tight.
constexpr DWORD BUILD_TIMEOUT_MS = 4000;
// Between borrows, so a session joining several peers does not flicker the
// local character continuously.
constexpr DWORD COOLDOWN_MS      = 1500;

// 2026-08-08, after client B died on the first live two-client test.
//
// A borrow that finishes without parking a master leaves the cache in exactly
// the state that selected the peer in the first place, so the next tick picked
// the same peer again — forever. Each cycle is a full head teardown and rebuild
// to put the peer's recipe on, and another to take it off: 25 engine calls and
// two Reset3D per cycle, every 1.5 s. Client B ran three of those in seven
// seconds immediately after a load and died inside the engine's own head
// builder, with no first-chance exception for the VEH to catch.
//
// So a failure has to be REMEMBERED. Two attempts per (peer, recipe) — one for
// a genuine transient, a second to confirm — and then that recipe is left
// alone. A peer that publishes a NEW recipe gets a fresh budget, because the
// hash is part of the key.
constexpr int MAX_ATTEMPTS_PER_RECIPE = 2;

struct Attempts {
    std::uint64_t hash    = 0;   // which recipe these attempts were against
    int           failed  = 0;
};
std::map<std::string, Attempts> g_attempts;

// Nothing may be borrowed until the local player's face has stopped moving.
//
// The borrow that killed B started three seconds after B published its own
// appearance — i.e. while the engine was still settling from the load. The
// existing precondition check (Actor+0x10A) read clean at that moment, so it
// is not sufficient on its own. This one is empirical and cheap: watch the
// player's face node, and refuse to borrow until it has been the SAME node for
// a few seconds. A head that is still being rebuilt cannot hold still.
constexpr DWORD SETTLE_MS = 3000;
void*  g_settle_node  = nullptr;
DWORD  g_settle_since = 0;

// Peers whose recipe is byte-identical to ours, already reported. Keyed by the
// recipe hash so a peer that changes appearance is reported again.
std::map<std::string, std::uint64_t> g_same_as_us;

void enter(State s, const char* why) {
    g_state    = s;
    g_since_ms = GetTickCount();
    FW_LOG("[face-borrow] -> %s (%s)", state_name(), why);
}

// Put OUR appearance back. Called from every exit path, including failures.
// Returns true only if the restore was applied AND read back as ours again;
// anything less wedges the module rather than leaving the player wrong and
// pretending otherwise.
bool restore_local(std::uintptr_t base) {
    if (g_saved_recipe.empty()) {
        FW_ERR("[face-borrow] nothing saved to restore — this should be "
               "impossible: the save happens before the first write");
        return false;
    }
    appearance::Recipe mine;
    if (!appearance::from_line(g_saved_recipe, &mine)) {
        FW_ERR("[face-borrow] our own saved recipe no longer parses: %s",
               g_saved_recipe.c_str());
        return false;
    }
    appearance::apply_to_player(base, mine);
    appearance::rebuild_player_head(base);

    // Verify by reading back, not by trusting the write. This is the one
    // check that decides whether the user is left looking like someone else.
    const std::string now = appearance::to_line(
        appearance::read_from_player(base));
    if (now != g_saved_recipe) {
        FW_ERR("[face-borrow] RESTORE MISMATCH — the local player is NOT back "
               "to its own appearance.\n  saved: %s\n  now  : %s",
               g_saved_recipe.c_str(), now.c_str());
        return false;
    }
    FW_LOG("[face-borrow] local appearance restored and verified");
    return true;
}

// A peer that has a recipe but no master built from it, and that is actually
// worth borrowing for. Returns empty when there is nothing to do, which is the
// normal case. `our_line` is the LOCAL player's current recipe.
std::string next_peer_needing_a_face(const std::string& our_line,
                                     std::uint64_t* hash_out,
                                     std::string* recipe_out) {
    for (const auto& [peer, recipe] : face_cache::all_recipes()) {
        const std::uint64_t h = face_cache::hash_recipe(recipe);
        if (face_cache::get_master(peer, h)) continue;   // already built

        // A peer wearing OUR EXACT appearance needs no borrow. The ghost's
        // fallback face source is the local player's own live face node
        // (scene_inject, "SOURCE=LOCAL player"), and when the recipes match
        // byte for byte that mirror IS the replication — same race, same sex,
        // same hair colour, same twelve parts. Borrowing would spend a head
        // teardown, a rebuild and a flicker to arrive at a node identical to
        // the one already on screen.
        //
        // This is the common case while testing, because both sides run the
        // same save until one of them is deliberately changed. It stays correct
        // afterwards: two players who genuinely look the same share a face.
        if (recipe == our_line) {
            auto it = g_same_as_us.find(peer);
            if (it == g_same_as_us.end() || it->second != h) {
                g_same_as_us[peer] = h;
                FW_LOG("[face-borrow] '%s' is wearing our exact appearance — "
                       "no borrow needed; the ghost mirrors the local player, "
                       "which for an identical recipe is the same face",
                       peer.c_str());
            }
            continue;
        }

        auto it = g_attempts.find(peer);
        if (it != g_attempts.end() && it->second.hash == h
            && it->second.failed >= MAX_ATTEMPTS_PER_RECIPE) {
            continue;   // burnt; see MAX_ATTEMPTS_PER_RECIPE
        }

        *hash_out   = h;
        *recipe_out = recipe;
        return peer;
    }
    return {};
}

// Record that a borrow for (peer, hash) produced nothing, and say out loud when
// that peer is being given up on — a silently abandoned peer is a ghost with
// the wrong face and no explanation in the log.
void note_failure(const std::string& peer, std::uint64_t hash,
                  const char* why) {
    Attempts& a = g_attempts[peer];
    if (a.hash != hash) { a.hash = hash; a.failed = 0; }
    ++a.failed;
    if (a.failed >= MAX_ATTEMPTS_PER_RECIPE) {
        FW_ERR("[face-borrow] giving up on '%s' after %d attempt(s) (%s). Its "
               "ghost will keep whatever face it has. A new recipe from that "
               "peer will be retried; this one will not.",
               peer.c_str(), a.failed, why);
    } else {
        FW_WRN("[face-borrow] attempt %d/%d for '%s' produced no master (%s) — "
               "will retry once", a.failed, MAX_ATTEMPTS_PER_RECIPE,
               peer.c_str(), why);
    }
}

// Build the synthetic peer's recipe from ours, with a different hair colour.
void maybe_arm_test(std::uintptr_t base) {
    const std::uint32_t hair = g_test_hair.load(std::memory_order_relaxed);
    if (hair == 0 || g_test_done) return;

    appearance::Recipe mine = appearance::read_from_player(base);
    if (mine.head_parts.empty()) return;   // player not built yet; try later
    if (mine.hair_colour == hair) {
        FW_WRN("[face-borrow] test peer would be identical to us "
               "(hair already 0x%08X) — pick a different colour or the test "
               "proves nothing", hair);
        g_test_done = true;
        return;
    }
    mine.hair_colour = hair;
    const std::string line = appearance::to_line(mine);
    face_cache::set_recipe(TEST_PEER, line);
    g_test_done = true;
    FW_LOG("[face-borrow] TEST PEER armed: our own face with hair 0x%08X. "
           "Expect a brief flicker to it and back. %s", hair, line.c_str());
}

}  // namespace

void arm_test_peer(std::uint32_t hair_form_id) {
    g_test_hair.store(hair_form_id, std::memory_order_relaxed);
    if (hair_form_id) {
        FW_LOG("[face-borrow] test mode: will synthesise a peer from our own "
               "recipe with hair 0x%08X, once the player is built",
               hair_form_id);
    }
}

bool in_progress() noexcept {
    return g_state == State::Applied || g_state == State::Restoring;
}

const char* state_name() noexcept {
    switch (g_state) {
        case State::Idle:      return "Idle";
        case State::Applied:   return "Applied";
        case State::Restoring: return "Restoring";
        case State::Wedged:    return "Wedged";
    }
    return "?";
}

std::uint32_t completed() noexcept { return g_completed.load(); }
std::uint32_t abandoned() noexcept { return g_abandoned.load(); }

void tick(std::uintptr_t module_base) {
    if (!module_base) return;
    maybe_arm_test(module_base);
    const DWORD now = GetTickCount();

    // THE EDITOR OWNS THE PLAYER WHILE IT IS OPEN.
    //
    // Both this module and the editor write the player's TESNPC. Refusing to
    // START a borrow is the easy half. The half that matters is a borrow already
    // IN FLIGHT: the player is wearing a peer's face right now, and if the
    // editor begins authoring on top of that, the restore below will later write
    // back the snapshot it captured and undo the user's work — or worse, the
    // editor's writes get published as the peer's appearance.
    //
    // So an in-flight borrow is abandoned immediately and driven into Restoring
    // on THIS tick, before the editor can touch anything. Deliberately NOT
    // counted as a failed attempt: being pre-empted is not the peer's fault, and
    // burning its attempt budget would mean giving up on a face that was never
    // actually tried. It gets retried once the editor closes.
    if (appearance::editing()) {
        if (g_state == State::Applied) {
            FW_WRN("[face-borrow] the editor opened while '%s' was being built "
                   "— abandoning it and giving the local player its own face "
                   "back now, before the editor writes anything",
                   g_peer.c_str());
            g_abandoned.fetch_add(1, std::memory_order_relaxed);
            enter(State::Restoring, "pre-empted by the editor");
            // and fall through, so the restore happens on this tick
        } else if (g_state == State::Idle) {
            return;
        }
    }

    switch (g_state) {

    case State::Wedged:
        return;   // deliberate dead end; see restore_local

    case State::Idle: {
        if (g_last_try_ms != 0 && now - g_last_try_ms < COOLDOWN_MS) return;

        // PROBE BEFORE COMMITTING. Without this the borrow wrote a peer's
        // recipe onto the local player, discovered Reset3D was refused
        // (typically Actor+0x10A == 1, "3D mid-load"), and undid it — every
        // 1.5 s for the whole loading screen. Nothing was broken by it, but
        // writing and unwriting a full 25-call recipe on a loop is not
        // something to leave in.
        if (!appearance::can_rebuild_player_head(module_base)) return;

        // SETTLE. The face node must have held still for a while; see
        // SETTLE_MS. Tracked here, in Idle, because during a borrow the node
        // is expected to change and State::Applied is the thing watching it.
        void* face_now_idle = anatomy_mirror::player_face_node(module_base);
        if (face_now_idle != g_settle_node) {
            g_settle_node  = face_now_idle;
            g_settle_since = now;
            return;
        }
        if (!face_now_idle) return;                        // no head at all yet
        if (now - g_settle_since < SETTLE_MS) return;      // still settling

        // Capture OURS first — and before the selection, because the selector
        // needs it to recognise a peer that already looks like us. Everything
        // after this point can fail; nothing after this point may run without
        // a way back.
        const appearance::Recipe mine =
            appearance::read_from_player(module_base);
        if (mine.head_parts.empty()) {
            // The local player is not built yet. Try again later — borrowing
            // against a half-built player would save a useless recipe and
            // restore to it.
            return;
        }
        g_saved_recipe = appearance::to_line(mine);

        std::uint64_t hash = 0;
        std::string   recipe;
        const std::string peer =
            next_peer_needing_a_face(g_saved_recipe, &hash, &recipe);
        if (peer.empty()) return;

        appearance::Recipe theirs;
        if (!appearance::from_line(recipe, &theirs)) {
            FW_WRN("[face-borrow] '%s' sent a recipe that does not parse — "
                   "dropping it so we stop retrying: %s",
                   peer.c_str(), recipe.c_str());
            face_cache::set_recipe(peer, "");   // clears it
            return;
        }

        g_peer         = peer;
        g_peer_hash    = hash;
        g_face_before  = anatomy_mirror::player_face_node(module_base);
        g_last_try_ms  = now;

        FW_LOG("[face-borrow] borrowing the local player to build '%s': %s",
               peer.c_str(), recipe.c_str());
        // apply_to_player is the one place that resolves the player's TESNPC;
        // going through it keeps that resolution in a single spot.
        appearance::apply_to_player(module_base, theirs);

        if (!appearance::rebuild_player_head(module_base)) {
            FW_WRN("[face-borrow] Reset3D refused — undoing immediately");
            note_failure(g_peer, g_peer_hash, "Reset3D refused");
            enter(State::Restoring, "rebuild refused");
            return;
        }
        enter(State::Applied, "waiting for the engine to build the head");
        return;
    }

    case State::Applied: {
        void* face_now = anatomy_mirror::player_face_node(module_base);

        if (face_now && face_now != g_face_before) {
            // A DIFFERENT node: the engine rebuilt, and this is the peer's
            // face standing on our player. Clone it before giving the player
            // back — the clone is the whole point of the borrow.
            void* master = fw::native::clone_nif_subtree(face_now);
            if (!master || master == face_now) {
                FW_ERR("[face-borrow] clone of '%s' returned %s — not parking "
                       "the player's own live node as a master, that would rip "
                       "it out of the player's tree",
                       g_peer.c_str(), master ? "the source" : "null");
                note_failure(g_peer, g_peer_hash,
                             master ? "clone returned the source"
                                    : "clone returned null");
            } else {
                // 2026-09-19 — LE PELLI DELLA MASCHERA DEVONO ESSERE SUE.
                //
                // Il deep-clone del motore non copia le BSSkin::Instance
                // quando lo scheletro non fa parte del sottoalbero clonato, e
                // qui non ne fa mai parte: la maschera esce condividendo le
                // pelli con la testa VIVA del giocatore locale, che e' la
                // cosa che abbiamo appena clonato.
                //
                // Finche' il giocatore non ricostruisce il suo 3D non si
                // vede. Poi entra in una power armor, il motore ricostruisce,
                // e la maschera parcheggiata resta con la radice intatta e le
                // pelli sotto di lei sparite. Da li' il ghost senza testa al
                // rientro successivo, con occhi e denti appesi a mezz'aria.
                //
                // Verificato che NON fosse un problema di vita del nodo: la
                // maschera restava a refcount=1 e children=14 su 65552
                // consegne, prima e dopo la power armor.
                (void)fw::native::privatise_clone_skins(master, face_now,
                                                        "face-master");
                // 2026-09-19 — SI STACCA LA MASCHERA DAL RIG DEL GIOCATORE.
                //
                // Fin qui la maschera e' un clone della testa VIVA del
                // giocatore locale, e le sue pelli conservano puntatori nudi
                // ai nodi-osso di quel rig. Noi la parcheggiamo e la riusiamo
                // per ogni ghost; il rig invece muore e rinasce a ogni
                // entrata e uscita dalla power armor, e il pool riassegna
                // quegli indirizzi ai nodi del telaio.
                //
                // La ricucitura non memorizza i nomi: li legge dal nodo che
                // il puntatore indica ADESSO. Dopo una power armor legge
                // l'inquilino nuovo. Misurato: lo stesso slot della stessa
                // maschera ha letto 'Chest', poi 'Wheel', poi
                // 'Neck_Low_skin', allo stesso indirizzo.
                //
                // Questa riga ri-punta le ossa della maschera a uno scheletro
                // che e' NOSTRO e non muore mai. Da qui in poi i nomi che la
                // ricucitura legge sono veri per tutta la sessione.
                //
                // E' l'UNICO istante in cui si puo' fare: il giocatore e'
                // vivo e appena clonato, quindi i puntatori sono ancora
                // validi e i nomi ancora quelli giusti.
                {
                    void* ref = fw::native::face_reference_skeleton();
                    if (ref) {
                        const int n =
                            fw::native::skin_rebind::swap_skin_bones_to_skeleton(
                                master, ref);
                        FW_LOG("[face-borrow] maschera ancorata allo scheletro "
                               "di riferimento: %d osso/a ora puntano a nodi "
                               "NOSTRI invece che al rig del giocatore", n);
                    } else {
                        FW_WRN("[face-borrow] nessuno scheletro di "
                               "riferimento: la maschera resta agganciata al "
                               "rig del giocatore e marcira' alla prossima "
                               "power armor");
                    }
                }
                face_cache::set_master(g_peer, g_peer_hash, master);
                g_completed.fetch_add(1, std::memory_order_relaxed);
                FW_LOG("[face-borrow] built '%s' -> master %p", g_peer.c_str(),
                       master);
                // The ghost may already be wearing a mirror of OUR face — the
                // race is real and was measured at 57 ms. Tell it to redress
                // now that a proper source exists.
                fw::native::redress_ghost_face(g_peer.c_str());

                // AND THE BODY'S SKIN, which the clone does not carry.
                //
                // The face is a cloned subtree; the body is a separate NIF, so
                // its skin tone is copied from the player's own SkinTint
                // material by copy_skin_tone. That copy runs ONCE, when the
                // ghost body is injected — and at that moment there is no peer
                // appearance yet, so it necessarily copies OUR skin. In the
                // two-client test both ghosts therefore wore the local player's
                // complexion: pale on one screen, dark on the other, on both
                // faces.
                //
                // Right here is the one moment when copying is correct: the
                // local player is still wearing the PEER's recipe and has
                // already been built from it, so the SkinTint material being
                // read is the peer's. It must happen before the restore below.
                // Compute the peer's skin NOW — the only window in which the
                // player's NPC wears the peer's recipe — and STASH it. Whether
                // it can also be painted immediately depends on an ordering
                // this code does not control: the run that found this had the
                // borrow finish 11 and 16 seconds BEFORE the ghost body was
                // injected, so a paint gated on the body existing skipped
                // silently and the inject-time local copy stood unchallenged.
                // The stash survives until the next borrow replaces it; the
                // inject path paints it whenever the body materialises.
                {
                    float col[4];
                    if (fw::native::anatomy_mirror::compute_skin_from_npc(
                            module_base,
                            fw::native::appearance::player_npc(module_base),
                            col)) {
                        fw::native::anatomy_mirror::stash_ghost_skin(col);
                        // Il corpo del peer che stiamo vestendo, non "un ghost".
                        void* body =
                            fw::native::ghost_body_of_peer(g_peer.c_str());
                        if (body) {
                            fw::native::anatomy_mirror::paint_stashed_ghost_skin(
                                module_base, body);
                        } else {
                            FW_LOG("[face-borrow] ghost body not injected yet "
                                   "— '%s' skin stashed, the inject will "
                                   "paint it", g_peer.c_str());
                        }
                    }
                }

                // AND MAKE THE FACE'S COMPOSITED TEXTURES THE CLONE'S OWN.
                //
                // The composite (skin tone, brows, tattoos, paint — everything
                // sub_14065DAB0 carries) is rendered into THREE GLOBAL
                // render-target pool slots, one canvas per process, and every
                // head rebuild repaints them for whoever is being rebuilt. The
                // clone's texture wrappers point at those slots, so without
                // this the restore below — a rebuild of the LOCAL player —
                // instantly redressed the ghost's face in the local player's
                // tints. That is exactly what both clients showed in the
                // two-peer test: each screen had both faces wearing the local
                // complexion, while hair (per-part material, no composite)
                // stayed correctly distinct.
                //
                // It must happen HERE, after the clone and before the restore:
                // this is the only window in which the shared canvas still
                // holds the PEER's face.
                fw::native::anatomy_mirror::own_face_composite(module_base,
                                                               master);
            }
            enter(State::Restoring, "clone done");
            return;
        }

        if (now - g_since_ms > BUILD_TIMEOUT_MS) {
            FW_WRN("[face-borrow] '%s': no new face node after %lu ms "
                   "(before=%p now=%p). Abandoning this build — the local "
                   "player comes first.",
                   g_peer.c_str(), BUILD_TIMEOUT_MS, g_face_before, face_now);
            g_abandoned.fetch_add(1, std::memory_order_relaxed);
            note_failure(g_peer, g_peer_hash, "no new face node before timeout");
            enter(State::Restoring, "timed out");
        }
        return;
    }

    case State::Restoring: {
        if (restore_local(module_base)) {
            g_peer.clear();
            g_saved_recipe.clear();
            g_face_before = nullptr;
            enter(State::Idle, "restored");
        } else {
            FW_ERR("[face-borrow] WEDGED: could not put the local player back. "
                   "No further borrows will be attempted — a second borrow on "
                   "top of a failed restore would bury the evidence and leave "
                   "the character permanently wrong. Saved recipe was: %s",
                   g_saved_recipe.c_str());
            g_abandoned.fetch_add(1, std::memory_order_relaxed);
            enter(State::Wedged, "restore failed");
        }
        return;
    }
    }
}

}  // namespace fw::native::face_borrow
