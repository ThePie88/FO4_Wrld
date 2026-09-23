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
    // The "only one is rendered" warning is written once, not every tick.
    bool          second_peer_logged = false;
    // Same for the silence: one line when it starts, one when it ends.
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

// How much silence from a peer before it counts as gone, when no PEER_LEAVE
// arrived. Ten seconds is twice the server's timeout (five) with margin: if
// the server evicted the peer, its PEER_LEAVE has all the time to arrive
// first, and this net only catches the case where that message truly got
// lost.
constexpr std::uint64_t kSilenceBeforeGoneMs = 10000;

// Time of the last position seen, per peer. Its OWN mutex: see the header.
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
    // The stability streak advances ONCE per tick, here, and no longer
    // inside the ghost's creation: its verdict also serves the WndProc
    // heartbeat, which must know when the load is over, and a counter called
    // from two places counts double.
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
                // The clock starts now: a peer that has just joined has sent
                // nothing yet and would expire before existing.
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
            // Body, head and geometries are still shared at this stage: they
            // are touched only when the LAST peer leaves.
            const bool last = g_ghosts.empty();
            FW_LOG("[ghost-life] peer %s left (was state=%u) — tearing its "
                   "ghost down (%zu still tracked)", e.peer_id.c_str(),
                   static_cast<unsigned>(was), g_ghosts.size());
            fw::native::ghost_teardown_for_peer(e.peer_id.c_str(), last);
        }
    }

    // Build what is missing.
    //
    // Still one body only, but the reason changed on 2026-09-19 and has to
    // be stated right. Until that day the refusal protected shared state: a
    // single skeleton, single pose and crouch slots, two ghosts that would
    // have moved as one. That state is gone: the skeleton is a private clone
    // that dies with its body, per-peer slots replaced the single ones, and
    // the census of globals in the ghost path is empty.
    //
    // The gate stays for a more honest and weaker reason: the two-ghost path
    // has NEVER BEEN EXECUTED. Testing is done with two clients, and each of
    // them sees a single remote peer. Shipping a path that never ran is the
    // same as not having it, and a refusal line is preferred here to a defect
    // that shows up the first time a third player joins. It opens when there
    // is a third client to test it with.
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

    // SILENCE: OBSERVED and nothing more. Nothing is torn down.
    //
    // WITHDRAWN on 2026-09-18, the same day, after a live test. There was a
    // "safety net" here: ten seconds without a position from a peer and its
    // ghost was torn down as if it had left.
    //
    // It did exactly the damage it was meant to prevent. Client A was killed
    // by the raiders at Concord; through the death and respawn sequence it
    // stopped sending positions for more than ten seconds, and B tore its
    // ghost down. The record went with the teardown, so nobody was left to
    // rebuild it: A came back to Sanctuary and B never saw it again for the
    // rest of the session.
    //
    // And the premise was wrong from the start. The net was meant to cover
    // "the PEER_LEAVE got lost", but the server sends that message with
    // send_reliable, recorded and RETRANSMITTED until acked: it does not get
    // lost, at most it arrives late. It protected against something that
    // cannot happen and broke something that does.
    //
    // Who is present is the SERVER's decision. A client has no better
    // information than its own, and ten seconds of silence is not an
    // absence: it is a load, a death, a respawn, or a menu.
    //
    // The line stays because it was useful diagnostics (it is how the length
    // of a respawn was learnt), but it no longer touches anything.
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
                FW_LOG("[ghost-life] peer %s: no position for %llu ms. Nothing "
                       "is touched: who is present is the server's word, and "
                       "a silence like this is a load or a respawn.",
                       id.c_str(),
                       static_cast<unsigned long long>(now - last));
            } else if (!quiet && r.silence_logged) {
                r.silence_logged = false;
                FW_LOG("[ghost-life] peer %s: positions are back", id.c_str());
            }
        }
    }

    // STALE SCENE: the ghost a load took away.
    //
    // The BODY is asked, not the scene: see ghost_body_is_orphaned. A null
    // parent means the scene node was destroyed and that body is no longer in
    // the world, however long the registry keeps holding it.
    //
    // What is done: the same teardown as a PEER_LEAVE, then the records go
    // back to waiting. No rebuild here: the ghost_create_if_ready gate has to
    // do its job again, and after a load it has a lot to say: the streak
    // restarts from zero, the cell changed, and the body will not be born
    // before the scene has settled again. Rebuilding on the spot in here
    // would put the ghost right back into the window that cost a whole day.
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
            // The teardown is done once on the shared parts, so the LAST of
            // the list carries last_ghost.
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
