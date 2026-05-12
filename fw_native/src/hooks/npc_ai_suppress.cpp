#include "npc_ai_suppress.h"

#include <windows.h>
#include <atomic>
#include <cstdint>

#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"
#include "../main_thread_dispatch.h"
#include "../engine/engine_calls.h"
#include "ghost_ai_package.h"   // B6.5w12 bridge: write current actor fid for the
                                // ghost-AI predicate hook to consume

#include <mutex>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>

namespace fw::hooks {

namespace {

// Engine signature (from re/B6.5_npc_pipeline_AGENT_A.md):
//   void __fastcall sub_140C636A0(Actor* this, float simTime);
using ActorUpdatePerFrameFn = void (*)(void* actor, float sim_time);

ActorUpdatePerFrameFn g_orig_actor_update_perframe = nullptr;

// Diagnostics. Relaxed because exact ordering doesn't matter; we only
// read these for periodic INFO snapshots. fetch_add at this volume
// (thousands per second) is cheap — single locked-xadd instruction.
std::atomic<std::uint64_t> g_suppress_fires{0};
std::atomic<std::uint64_t> g_passthrough_fires{0};
std::atomic<std::uint64_t> g_seh_failures{0};
std::atomic<bool>          g_installed{false};

// B6.5w17 v3 — SHARED dynamic bail set (file-scope so OTHER hooks can
// query via is_actor_bail_tracked()). Was a function-local static in v2,
// which meant only npc_ai_suppress's detour saw it. Promoting it to
// file-scope lets all 5 ghost-AI hooks bail the same actors uniformly.
//
// v4 (2026-05-12, post-crash): swap std::mutex for std::shared_mutex.
// is_actor_bail_tracked() is called from FIVE hot-path hooks (havok_step
// fires on the physics worker thread, the others on main thread). With a
// plain mutex, contention serializes them all — havok blocked on main,
// main blocked on havok, etc. Under heavy combat (~thousands of
// fires/sec) this could explain the post-2-minute crash. With
// shared_mutex, the rare WRITE path (AUTO-TRACK insert) takes
// std::unique_lock; the hot READ paths take std::shared_lock and run
// concurrently. Atomic size mirror lets stats fetches skip locking
// entirely.
std::shared_mutex                 g_dyn_mtx;
std::unordered_set<std::uint32_t> g_dyn_tracked;
std::atomic<std::uint64_t>        g_dyn_auto_adds{0};
std::atomic<std::uint64_t>        g_dyn_set_size{0};

// B6.6w0 hook #3 support: AIProcess* → form_id reverse map.
// Populated lazily from this detour (every Actor we tick gives us the
// (aiproc, fid) pair). Read by ghost_ai_fire.cpp's DecideAndFire hook
// to identify which raider is making the fire decision.
//
// Sized to hold at most a few hundred entries (= every loaded Actor in
// current cells). No eviction yet — stale entries are harmless misses
// in lookup. If memory pressure ever matters, add a periodic prune on
// actors whose form_id is no longer findable.
std::shared_mutex                                 g_aiproc_mtx;
std::unordered_map<const void*, std::uint32_t>    g_aiproc_to_fid;
std::atomic<std::uint64_t>                        g_aiproc_map_size{0};

// Per disasm of sub_140C5CCE0 (SyncCombatTargetFromAIProcess):
//   mov rcx, [rbx+328h]      ; AIProcess* = *(Actor + 0x328)
// Used here to populate the AIProcess → form_id map.
constexpr std::size_t ACTOR_AIPROCESS_OFFSET = 0x328;

// SEH-safe pointer read at a known offset. Local copy to avoid include
// loops with other hooks (we deliberately don't share these tiny helpers
// via a header).
static const void* safe_read_ptr_at_local(const void* base,
                                          std::size_t off) noexcept {
    if (!base) return nullptr;
    __try {
        return *reinterpret_cast<const void* const*>(
            reinterpret_cast<const std::uint8_t*>(base) + off);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
}

// SEH-safe form_id read. Returning 0 on fault makes the detour fall
// through to passthrough (safer than skipping — at worst the engine
// ticks an actor we couldn't identify, no crash).
static std::uint32_t safe_read_form_id(const void* actor) noexcept {
    if (!actor) return 0;
    __try {
        return *reinterpret_cast<const std::uint32_t*>(
            reinterpret_cast<const std::uint8_t*>(actor) +
            fw::offsets::FORMID_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0xFFFFFFFFu;   // sentinel — see detour
    }
}

// B6.5w17: read Actor+0x2D0 (flags_720) safely. InCombat = bit 0x4000.
static std::uint32_t safe_read_actor_flags(const void* actor) noexcept {
    if (!actor) return 0;
    __try {
        return *reinterpret_cast<const std::uint32_t*>(
            reinterpret_cast<const std::uint8_t*>(actor) + 0x2D0);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

constexpr std::uint32_t PLAYER_FORM_ID = 0x00000014;
constexpr std::uint32_t ACTOR_FLAG_IN_COMBAT = 0x4000u;

// The detour. Hot path: ~thousands of calls per second across all
// loaded Actors. Keep it tight.
//
// B6.5w12 deprecation (2026-05-11): rounds 1-11 POST-hook
// apply_npc_state_to_actor path is CLOSED.
//
// Previous logic (round 2 strategy): call original FIRST so the engine's
// housekeeping (NIF sync, anim graph evaluation, collision) ran
// normally, then POST-overwrite pos/yaw/anim from our cache. The
// "engine's internal NIF sync" wasn't where the renderer ultimately
// read from in the way we hoped — the race against engine's own
// transforms below Update_PerFrame was unwinnable at this level. The
// MoveTo-based output-override path (scene_render_hook) reached the
// same dead-end via a different route. See NPCs.md.
//
// The hook install + form_id read + tracked-set lookup pattern are
// kept as scaffolding. Ghost AI hooks (B6.5w12+) will reuse THIS entry
// point structure but ALSO install separate detours at the decision-
// point functions upstream — combat target setter, package predicate,
// movement wrapper, aim writer, anim state transitions, etc.
//
// The diagnostic counters keep firing — they're useful for "how many
// tracked NPCs is the engine ticking per frame on this client" stat.
void __fastcall detour_actor_update_perframe(void* actor, float sim_time) {
    const std::uint32_t fid = safe_read_form_id(actor);

    // B6.6w0 hook #3 support: register (aiproc -> fid) lazily. Cheap —
    // shared_lock to check membership, only escalate to unique_lock on
    // insert/update. Skips on SEH-failed fid (don't poison map with
    // sentinel) and on missing actor.
    if (fid != 0 && fid != 0xFFFFFFFFu && actor) {
        const void* aiproc =
            safe_read_ptr_at_local(actor, ACTOR_AIPROCESS_OFFSET);
        if (aiproc) {
            bool need_write = false;
            {
                std::shared_lock<std::shared_mutex> lk(g_aiproc_mtx);
                const auto it = g_aiproc_to_fid.find(aiproc);
                if (it == g_aiproc_to_fid.end() || it->second != fid) {
                    need_write = true;
                }
            }
            if (need_write) {
                std::unique_lock<std::shared_mutex> lk(g_aiproc_mtx);
                auto [it, inserted] =
                    g_aiproc_to_fid.insert_or_assign(aiproc, fid);
                if (inserted) {
                    g_aiproc_map_size.store(g_aiproc_to_fid.size(),
                                            std::memory_order_relaxed);
                }
            }
        }
    }

    // B6.5w12 Ghost AI bridge: write the current actor's form_id to the
    // shared atomic BEFORE calling original. Any sub-call within the AI
    // tick (package selector, quest condition eval, dialog topic check,
    // ...) that fires our inner predicate hook (sub_140768CC0) will read
    // this atomic to identify which actor's AI is currently being ticked.
    // Save the prior value and restore after orig to keep recursion-safe
    // (engine doesn't recurse Update_PerFrame in practice, but defensive).
    //
    // Skip on SEH-failed reads (fid == 0xFFFFFFFFu) — better to leave
    // atomic at its prior state than poison it with sentinel.
    const std::uint32_t prev_bridge_fid =
        fw::hooks::g_current_actor_fid.load(std::memory_order_relaxed);
    const void* const   prev_bridge_ptr =
        fw::hooks::g_current_actor_ptr.load(std::memory_order_relaxed);
    if (fid != 0xFFFFFFFFu) {
        fw::hooks::g_current_actor_fid.store(
            fid, std::memory_order_relaxed);
        fw::hooks::g_current_actor_ptr.store(
            actor, std::memory_order_relaxed);
    }

    // B6.5w16 NUCLEAR OPTION: bail Update_PerFrame ENTIRELY for tracked
    // NPCs with movement_override. Per B6.5w4 round 1 (original Ghost AI
    // discovery): "bail Update_PerFrame → tracked NPCs frozen visually
    // at last AI-tick pose. AI tick stops, anim graph stops, NIF sync
    // stops." Originally rejected because they wanted rendering to keep
    // running normally with server pos override. WE WANT THE FREEZE.
    //
    // Live tests of 18 hooks have shown the engine has multiple parallel
    // pos write paths (NIF.local→NIF.world via UpdateWorldData, Havok
    // body sync, anim root motion, character proxy controller) — bailing
    // any one leaves others to drive motion. The only thing UP-tree of
    // ALL of these is Update_PerFrame itself.
    //
    // Trade-off: tracked NPCs become statues (no anim, no logic). For
    // the MVP "raider freezes for sync demonstration" this is acceptable.
    // The Ghost AI Phase 5 will RESTORE rendering by either reanimating
    // them via server-driven anim graph commands or by accepting visual
    // freeze + handling server-decided pos.
    //
    // B6.5w17 v2: STICKY AUTO-TRACK pattern.
    //   Path 0 (NEW): check the runtime auto-tracked set first. Once an
    //     actor was ever bailed, stay bailed forever. No flag oscillation,
    //     no AI re-evaluation can un-freeze them.
    //   Path 1: server-pushed tracked set with movement_override.
    //   Path 2: actor is in COMBAT — engine flag 0x4000 at Actor+0x2D0.
    //   Path 3: actor has any "active combat substate" — bit 0x80000 also
    //     observed as combat-related in some engine code.
    //   Auto-add: on first bail via any path, insert into dynamic set.
    //
    // Excludes player always.
    //
    // B6.5w17 v3 (2026-05-12): the dynamic set was promoted to FILE-SCOPE
    // (g_dyn_tracked) so the other ghost-AI hooks (havok_step, actor_setpos,
    // pos_belt, movement) can query it via is_actor_bail_tracked() and bail
    // their own paths. Previously only Update_PerFrame was silenced for
    // dynamic-tracked actors → engine still drove their motion via Havok.

    bool bail_this_actor = false;
    if (fid != PLAYER_FORM_ID && fid != 0 && fid != 0xFFFFFFFFu) {
        // Path 0: already auto-tracked (shared read).
        {
            std::shared_lock<std::shared_mutex> lk(g_dyn_mtx);
            if (g_dyn_tracked.find(fid) != g_dyn_tracked.end()) {
                bail_this_actor = true;
            }
        }

        if (!bail_this_actor) {
            // Path 1: server tracked
            fw::dispatch::CachedNPCState st_pre{};
            if (fw::dispatch::get_cached_npc_state(fid, &st_pre)
                && st_pre.movement_override != 0)
            {
                bail_this_actor = true;
            }
            // Path 2: InCombat flag (bit 0x4000)
            if (!bail_this_actor) {
                const std::uint32_t flags = safe_read_actor_flags(actor);
                if (flags & ACTOR_FLAG_IN_COMBAT) {
                    bail_this_actor = true;
                }
                // Path 3: extra combat-related bits we'd want to catch
                if (!bail_this_actor && (flags & 0x80000u)) {
                    bail_this_actor = true;
                }
            }

            // Auto-add to dynamic set on first bail (exclusive write).
            //
            // v5 (2026-05-12, post-2nd-crash): also flip the body to
            // KEYFRAMED motion on first auto-add. Previously this was
            // only done for cache.movement_override actors; the dynamic
            // auto-tracked ones never got it. When the player damaged a
            // frozen-but-not-keyframed raider, Havok still tried to apply
            // hit impulses / ragdoll setup against a body whose anim
            // graph was frozen — ~3 sec later the engine hit an
            // inconsistency and crashed. Keyframed bodies ignore
            // impulses, so the damage path stays sane.
            bool just_inserted = false;
            if (bail_this_actor) {
                std::unique_lock<std::shared_mutex> lk(g_dyn_mtx);
                if (g_dyn_tracked.insert(fid).second) {
                    const auto sz = g_dyn_tracked.size();
                    g_dyn_set_size.store(sz, std::memory_order_relaxed);
                    const auto an = g_dyn_auto_adds.fetch_add(
                        1, std::memory_order_relaxed);
                    if (an < 20) {
                        FW_LOG("[npc-ai-suppress] AUTO-TRACK #%llu fid=0x%08X "
                               "— added to shared dynamic bail set "
                               "(now %zu actors; all 5 hooks will bail)",
                               static_cast<unsigned long long>(an), fid, sz);
                    }
                    just_inserted = true;
                }
            }
            // Outside the lock — Havok engine call may take its own lock.
            if (just_inserted) {
                const bool ok = fw::engine::set_actor_motion_keyframed(actor);
                FW_LOG("[npc-ai-suppress] keyframed motion applied at AUTO-TRACK "
                       "fid=0x%08X actor=%p ok=%d — Havok now ignores impulses "
                       "(prevents ragdoll-on-damage crash)",
                       fid, actor, ok ? 1 : 0);
            }
        }
    }

    if (bail_this_actor) {
        static std::atomic<std::uint64_t> g_full_bails{0};
        const auto bn = g_full_bails.fetch_add(1, std::memory_order_relaxed);
        if (bn < 10) {
            FW_LOG("[npc-ai-suppress] FULL BAIL #%llu actor_fid=0x%08X — "
                   "Update_PerFrame skipped entirely (no AI, no anim, "
                   "no NIF sync). Statue mode.",
                   static_cast<unsigned long long>(bn), fid);
        } else if ((bn % 5000) == 0) {
            FW_DBG("[npc-ai-suppress] FULL BAIL #%llu (heartbeat)",
                   static_cast<unsigned long long>(bn));
        }
        // Restore bridge atomic, then return (skipping original entirely).
        fw::hooks::g_current_actor_fid.store(prev_bridge_fid,
                                             std::memory_order_relaxed);
        fw::hooks::g_current_actor_ptr.store(prev_bridge_ptr,
                                             std::memory_order_relaxed);
        g_suppress_fires.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    // Step 1: untracked / no override → always call original.
    if (g_orig_actor_update_perframe) {
        g_orig_actor_update_perframe(actor, sim_time);
    }

    // Restore the bridge atomic for the caller's frame.
    fw::hooks::g_current_actor_fid.store(prev_bridge_fid,
                                         std::memory_order_relaxed);
    fw::hooks::g_current_actor_ptr.store(prev_bridge_ptr,
                                         std::memory_order_relaxed);

    // Step 2: SEH-failed form_id read → no work possible.
    if (fid == 0xFFFFFFFFu) {
        g_seh_failures.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    // Step 3: cache lookup for tracked-set membership (diagnostic only
    // post-deprecation — we no longer apply state here).
    if (fid == 0) {
        g_passthrough_fires.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    fw::dispatch::CachedNPCState st{};
    if (!fw::dispatch::get_cached_npc_state(fid, &st)) {
        // Not a tracked NPC; vanilla state is fine.
        g_passthrough_fires.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    // Tracked NPC — diagnostic counter only. Ghost AI substitutes
    // decision-point inputs upstream; no post-hoc state apply here.
    g_suppress_fires.fetch_add(1, std::memory_order_relaxed);

    // B6.5w15: round 7 keyframed motion REVIVED. For tracked NPCs with
    // movement_override (i.e. server wants them frozen), set Havok motion
    // type to Keyframed (=2) ONCE per actor. After this, Havok stops
    // integrating the rigid body — it sits at its current pos regardless
    // of velocity, anim root motion, or forces.
    //
    // Why HERE: npc_ai_suppress fires Update_PerFrame for every loaded
    // actor every frame. On the FIRST fire where actor is tracked + has
    // movement_override, we apply Keyframed. Subsequent fires are no-ops
    // (already in the set). Cheap.
    //
    // Why this addresses the bypass: we've confirmed (B6.5w15 RE) the
    // engine has multiple parallel pos writers (Actor+0xD0, NIF+0xA0
    // via UpdateWorldData, Havok body world transform via FinishPhysicsStep).
    // Bailing individual writers leaves others to drive motion. Setting
    // Keyframed at the Havok level upstream-blocks the rigid body itself,
    // which is what the renderer ultimately reads.
    if (st.movement_override != 0) {
        static std::mutex                       s_keyframed_mtx;
        static std::unordered_set<std::uint32_t> s_keyframed_set;
        bool need_keyframe = false;
        {
            std::lock_guard<std::mutex> lk(s_keyframed_mtx);
            if (s_keyframed_set.find(fid) == s_keyframed_set.end()) {
                s_keyframed_set.insert(fid);
                need_keyframe = true;
            }
        }
        if (need_keyframe) {
            const bool ok = fw::engine::set_actor_motion_keyframed(actor);
            FW_LOG("[npc-ai-suppress] set_actor_motion_keyframed actor_fid=0x%08X "
                   "actor=%p ok=%d — Havok body now frozen for this NPC",
                   fid, actor, ok ? 1 : 0);
        }
    }

#if 0
    // ===== ROUND 2 (CLOSED) — kept for reference =======================
    // POST-overwrite of pos/yaw/anim from cache.  Don't re-enable: the
    // race against engine's own NIF sync is unwinnable at this level.
    // Architecturally superseded by Ghost AI decision-point hooks.
    fw::engine::apply_npc_state_to_actor(
        actor,
        st.pos_x, st.pos_y, st.pos_z,
        st.yaw_deg_math, st.anim_state,
        /*skip_anim_graph=*/false);
#endif  // ===== end round 2 reference block ===========================
}

} // namespace

bool install_npc_ai_suppress(std::uintptr_t module_base) {
    if (g_installed.load(std::memory_order_acquire)) {
        FW_LOG("[npc-ai-suppress] already installed; skipping");
        return true;
    }
    const auto target_ea =
        module_base + fw::offsets::ACTOR_UPDATE_PERFRAME_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(target_ea),
        reinterpret_cast<void*>(&detour_actor_update_perframe),
        reinterpret_cast<void**>(&g_orig_actor_update_perframe));
    if (ok) {
        g_installed.store(true, std::memory_order_release);
        FW_LOG("[npc-ai-suppress] Actor::Update_PerFrame hook installed at 0x%llX "
               "(RVA 0x%lX) — tracked NPCs will skip vanilla AI tick",
               static_cast<unsigned long long>(target_ea),
               static_cast<unsigned long>(fw::offsets::ACTOR_UPDATE_PERFRAME_RVA));
    } else {
        FW_ERR("[npc-ai-suppress] hook FAILED at 0x%llX — vanilla AI will "
               "continue fighting our pos writes at 60 Hz",
               static_cast<unsigned long long>(target_ea));
    }
    return ok;
}

std::uint64_t get_npc_ai_suppress_fires() {
    return g_suppress_fires.load(std::memory_order_relaxed);
}
std::uint64_t get_npc_ai_passthrough_fires() {
    return g_passthrough_fires.load(std::memory_order_relaxed);
}
std::uint64_t get_npc_ai_seh_failures() {
    return g_seh_failures.load(std::memory_order_relaxed);
}

// B6.5w17 v3 — shared dynamic bail set query.
// O(1) hash lookup under a SHARED-READ lock. Multiple hooks on multiple
// threads (havok=physics, others=main) can run this concurrently without
// blocking each other; only AUTO-TRACK insert (rare, ~once per actor)
// takes an exclusive lock.
//
// Fast-path bypass: if the set is empty (g_dyn_set_size==0), skip the
// lock entirely. Common in early frames before any actor has entered
// combat.
bool is_actor_bail_tracked(std::uint32_t form_id) {
    if (form_id == 0 || form_id == 0xFFFFFFFFu) return false;
    if (g_dyn_set_size.load(std::memory_order_relaxed) == 0) return false;
    std::shared_lock<std::shared_mutex> lk(g_dyn_mtx);
    return g_dyn_tracked.find(form_id) != g_dyn_tracked.end();
}

std::uint64_t get_dyn_bail_tracked_count() {
    return g_dyn_set_size.load(std::memory_order_relaxed);
}

// B6.6w0 hook #3 helper: AIProcess* → form_id reverse lookup.
// Shared-read lock; multiple ghost-AI hooks can query concurrently.
bool get_fid_for_aiproc(const void* aiproc, std::uint32_t* out_fid) {
    if (!aiproc) return false;
    if (g_aiproc_map_size.load(std::memory_order_relaxed) == 0) return false;
    std::shared_lock<std::shared_mutex> lk(g_aiproc_mtx);
    const auto it = g_aiproc_to_fid.find(aiproc);
    if (it == g_aiproc_to_fid.end()) return false;
    if (out_fid) *out_fid = it->second;
    return true;
}

std::uint64_t get_aiproc_map_size() {
    return g_aiproc_map_size.load(std::memory_order_relaxed);
}

// B6.6w0 unified bail predicate. See header for rationale.
//
// Implementation order: cheap atomic checks first, lock acquisition
// only on actual hits. Both sources OR'd.
bool should_freeze_actor(std::uint32_t form_id) {
    if (form_id == 0 || form_id == 0xFFFFFFFFu) return false;
    // PlayerCharacter — NEVER freeze (would break input + camera).
    if (form_id == 0x00000014u) return false;

    // Source 1: server cache (movement_override flag pushed via
    // NPC_STATE_BCAST). Symmetric across both clients because both
    // receive the same broadcast.
    fw::dispatch::CachedNPCState st{};
    if (fw::dispatch::get_cached_npc_state(form_id, &st)
        && st.movement_override != 0)
    {
        return true;
    }

    // Source 2: local dynamic set (auto-tracked via InCombat flag in
    // npc_ai_suppress). Asymmetric across clients — only catches
    // raiders the LOCAL engine has ticked into combat. Used as belt-
    // and-braces when server cache misses an actor.
    return is_actor_bail_tracked(form_id);
}

} // namespace fw::hooks
