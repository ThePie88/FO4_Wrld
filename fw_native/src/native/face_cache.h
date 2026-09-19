// Face cache (2026-08-08) — one built head per peer, kept warm.
//
// WHY
//   A ghost's face is produced by cloning a BUILT BSFaceGenNiNode subtree
//   (CHARGEN_PLAN §19). Locally the source is the player's own face and the
//   clone is free. For a peer it is not: the only thing on this machine that
//   can BUILD a head is the engine, from a TESNPC, and the only TESNPC
//   available is the local player's — so producing peer X's face means
//   borrowing the local player for a moment:
//
//       save my recipe -> apply X's -> Reset3D -> clone -> restore mine
//
//   That borrow makes the LOCAL character wear someone else's face for a
//   frame or two. Doing it once per peer is acceptable. Doing it every time
//   the ghost is reassembled — and the ghost is reassembled on every cell
//   change and every respawn — is not.
//
//   Hence the cache: build once, keep the result, re-clone it on demand.
//
// WHAT IS CACHED
//   A MASTER node: a clone that is never attached to anything. Each ghost
//   assembly gets a fresh clone OF THE MASTER. This is deliberate — a NiNode
//   has exactly one parent, so retaining an attached node and moving it
//   between assemblies means fighting parent and refcount bookkeeping every
//   time. Cloning from a parked master sidesteps that entirely, and the
//   engine's DeepClone is cheap.
//
// INVALIDATION
//   Keyed by peer id AND a hash of the recipe that produced it. A character
//   normally never changes, but the creator exists, so an appearance change
//   has to invalidate rather than leave a stale face on the wrong body. A
//   changed recipe hashes differently and misses.
//
// WHERE THE ATTACH LIVES — and why not here
//   This module stores masters and nothing else. The attach itself (clone the
//   master, rebind its skins to the ghost skeleton, cull the head's other
//   children, drop the meatcap) stays in scene_inject.cpp, because every
//   primitive it needs — attach_child_direct, the resolved-function table,
//   the ghost head and body pointers — is file-static there. Moving the
//   attach here would mean exporting that table, which is a bigger and
//   riskier change than this cache is worth. Storage and policy here,
//   scene-graph surgery where the surgery already works.
//
// THREADING
//   MAIN THREAD ONLY, like everything that touches the scene graph.

#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace fw::native::face_cache {

// Park `built_face_node` as the master for `key`. The caller keeps ownership
// of what it passes; the node is stored as-is, so it must be a node the
// caller will not attach elsewhere (in practice: a fresh clone made for this
// purpose). Replaces any previous master for the key.
void set_master(const std::string& key, std::uint64_t recipe_hash,
                void* master_node);

// The parked master for `key`, but only if it was built from exactly this
// recipe hash. Returns null on a miss — including a hash mismatch, which is
// how an appearance change invalidates a stale face.
void* get_master(const std::string& key, std::uint64_t recipe_hash) noexcept;

// Any master for `key`, regardless of hash. For diagnostics and teardown.
void* peek_master(const std::string& key) noexcept;

// The first master held, with the peer it belongs to. Returns null when there
// is none.
//
// Why "any" and not "the one for this ghost": there is exactly ONE ghost in
// the current architecture, shared across peers — POSE_BROADCAST already
// ignores the peer id and applies whatever arrives to it. Keying the face
// lookup on ghost_map's label would ALSO have been wrong: that label
// ("player_B") is not the identity the wire uses (the client_id,
// "fwdaea9b724bd5f"), so the recipe would arrive under one name and be looked
// up under another and never be found. When multi-peer ghosts land, this
// becomes a per-peer lookup and the mismatch has to be resolved then — not
// papered over now with a key that happens to be wrong.
// POD out-parameter on purpose: the caller is inside scene_inject's SEH-caged
// injector, and a std::string there is a hard compiler error (C2712 — __try
// cannot appear in a function needing object unwinding). A char buffer is not
// a style choice here, it is the only shape that compiles at the call site.
void* any_master(char* peer_out, std::size_t peer_out_size) noexcept;

// La maschera di QUESTO peer, costruita dalla ricetta che ha ADESSO.
//
// E' la risposta che any_master non poteva dare, e il suo commento lo diceva:
// "when multi-peer ghosts land, this becomes a per-peer lookup". Ci siamo.
//
// Fa da sola il giro giusto: prende la ricetta corrente del peer, ne calcola
// l'hash e chiede get_master con quello. Quindi un aspetto cambiato invalida
// la maschera vecchia invece di resuscitarla, che e' esattamente cio' che
// peek_master non garantisce (per quello il suo commento dice "diagnostics
// and teardown", non "rendering").
//
// `const char*` e non std::string di proposito: il chiamante vive dentro la
// gabbia SEH dell'iniettore, dove un temporaneo con distruttore e' un errore
// di compilazione (C2712). Stessa ragione del buffer di any_master.
//
// Torna null se quel peer non ha ricetta, o non ha una maschera costruita da
// quella ricetta.
void* master_for_peer(const char* peer_id) noexcept;

// Drop one peer's master (they left), or all of them (session ended).
// Note: the nodes are NOT released here. Releasing a parked NiNode needs the
// engine's refcount path, which lives with the rest of the scene-graph code;
// until a peer-churn case actually demands it, a handful of parked subtrees
// per session is cheaper than a wrong free.
void forget(const std::string& key);
void clear();

// How many masters are parked. For the log line at teardown.
std::size_t size() noexcept;

// ---------------------------------------------------------------- recipes
//
// The RECIPE cache, distinct from the master cache above. Two levels, for two
// different costs:
//   - a recipe is 150 bytes off the wire: cheap to hold, and the server sends
//     each peer's once at join, so this is where it lands;
//   - a MASTER is a built head: expensive, because producing one means
//     borrowing the local player's TESNPC for a moment.
// Keeping them separate means a recipe can arrive long before the ghost that
// needs it exists, which is exactly what happens — appearances bootstrap at
// join, ghosts appear when a peer comes into range.

// Store a peer's recipe line as received. Returns true if it CHANGED, which
// is the signal to invalidate that peer's built master.
bool set_recipe(const std::string& peer_id, const std::string& recipe_line);

// A peer's recipe, or empty if none has arrived yet.
std::string get_recipe(const std::string& peer_id);

// Every held recipe, as a snapshot copy. A copy on purpose: the borrow
// iterates this and mutates the cache while doing so (dropping a bad recipe,
// parking a master), and iterating a live map it is editing is a bug waiting
// for a peer to join at the wrong moment.
std::vector<std::pair<std::string, std::string>> all_recipes();

// Cheap, stable hash of a recipe line. Not cryptographic — it only has to
// change when the appearance changes.
std::uint64_t hash_recipe(const std::string& recipe_line) noexcept;

}  // namespace fw::native::face_cache
