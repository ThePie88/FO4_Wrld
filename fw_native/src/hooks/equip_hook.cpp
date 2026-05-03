// M9 wedge 1 — equipment-event sender hook (OBSERVE-only). See equip_hook.h
// for rationale + offsets.h "B8 force-equip-cycle" block for the RE history
// of these RVAs and signatures.
//
// ============================================================================
// ⚠️  POTENTIAL FUTURE CRASH SOURCE  — read this if a SEGV trace lands here ⚠️
// ============================================================================
// This hook is OBSERVE-only TODAY (2026-04-28, M9 wedge 1). It detours
// ActorEquipManager::EquipObject + UnequipObject, reads the args, broadcasts
// an EQUIP_OP, and chains to g_orig WITHOUT touching the ghost body or any
// scene-graph state. In this form it is safe — the 3-day crash hunt
// (re/M9_y_post_bmod_crash_dossier.txt) was caused by hooks that ALSO
// nullified skin bindings / set cull flags / detached the ghost during the
// detour. None of that happens here.
//
// Wedge 2 (visual apply on ghost) re-introduces risk vectors:
//   1. Ghost mutation during an equip event — if wedge 2 attempts to attach
//      armor NIFs to the ghost from inside a detour or from a thread that
//      races with the engine's biped rebuild walk, it lands back in the
//      same crash class. Wedge 2 MUST go through main-thread dispatch
//      (FW_MSG_EQUIP_APPLY pattern, mirror of FW_MSG_DOOR_APPLY) and MUST
//      NOT touch the ghost during the engine's UnequipObject / EquipObject
//      execution — only AFTER the engine call returns and the rebuild has
//      settled.
//
//   2. tls_applying_remote re-entry — when wedge 2 calls engine equip
//      functions on the LOCAL ghost actor to apply a remote peer's event,
//      this detour fires AGAIN with tls_applying_remote=true. We currently
//      passthrough silently in that case. If wedge 2 ever forgets to set
//      the TLS guard before re-entering, infinite ping-pong + crash.
//
//   3. NPC equip events (AI behaviors swap weapons) — currently filtered
//      out via actor_is_local_player(). If a future change loosens that
//      filter (e.g. to also broadcast our companion's weapon swaps), the
//      TX volume jumps 10x and the receiver-apply path on the ghost
//      becomes a hot-loop crash candidate.
//
//   4. Engine assumes Actor* args — the M8P3 ghost is a BSFadeNode, NOT
//      an Actor. Calling ActorEquipManager::EquipObject(ghost) directly
//      will SEH the moment the engine accesses Actor-specific fields
//      (inventory list at +0xF8, biped state at +0xB78, etc). Wedge 2
//      cannot use this code path naively — must do CUSTOM NIF attachment
//      on the ghost's skeleton, NOT go through ActorEquipManager.
//
// Mitigation status:
//   Item 1: design wedge 2 around main-thread dispatch from the start.
//   Item 2: tls_applying_remote guard ALREADY in place (lines 124, 184).
//   Item 3: filter is documented; do not loosen without architectural review.
//   Item 4: not yet addressed — wedge 2 will need a different mechanism.
// ============================================================================

#include "equip_hook.h"

#include <windows.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <vector>          // M9.w4 — extract_equipped_mods returns std::vector

#include "container_hook.h"   // tls_applying_remote (forward-compat for w2)
#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"
#include "../net/client.h"
#include "../net/protocol.h"
#include "../native/weapon_witness.h"  // M9 w4 step 2: post-equip NIF walker
#include "../native/scene_inject.h"    // M9 w4 v9: is_weapon_form form-type gate
#include "../main_thread_dispatch.h"   // M9 w4 v9: deferred mesh-tx via WndProc

namespace fw::hooks {

// === M9 w4 v9 — deferred mesh-tx (2026-05-01 22:10) =======================
//
// Problem: walker runs post-`g_orig_equip` but the engine's runtime weapon
// assembly is asynchronous. Walker often returns 0 meshes → no mesh-tx →
// receiver falls back to TESModel resolve which returns "RecieverDummy.nif"
// (placeholder) → invisible weapon on ghost.
//
// Fix: arm a deferred re-walk 300ms after the equip. By then the engine
// has finished assembling the weapon tree on the player's bipedAnim. The
// deferred walker captures real data → mesh-tx fires → receiver gets the
// proper bgsm path → ghost shows weapon.
//
// Pattern: equip detour stores form_id into a queue, spawns a detached
// worker that sleeps 300ms and PostMessages a custom WM_APP. WndProc
// handler drains the queue and runs the walker + mesh-tx for each entry.
// FW_MSG_DEFERRED_MESH_TX defined in equip_hook.h (inline constexpr).

namespace {

// Run the snapshot walker for the local player's bipedAnim weapon subtree
// and, if any BSGeometry leaves are captured, ship them as a chunked mesh
// blob. Cap on chunks: 50 (~70 KB) — heavier-modded weapons get dropped
// (logged as warning).
//
// Called from:
//   - equip detour POST-CHAIN (immediate, often empty due to async assembly)
//   - deferred WM_APP handler 300ms later (typically wins the assembly race)
//
// MAIN THREAD ONLY. Walker reads scene graph; not safe from worker thread.
void try_mesh_tx_for_form(std::uint32_t form_id) {
    // Cap raised 2026-05-01 22:40 from 50 → 150 (≈200 KB blob).
    // Original 50-chunk cap was paranoid post-VaultSuit-saturation
    // (100 KB clothing blob jammed the channel). Now is_weapon_form
    // filter excludes Vault Suit entirely, so the cap can be relaxed
    // to fit heavily-modded firearm assemblies (observed 13 meshes,
    // 90 KB → 66 chunks). Channel handles 150 chunks fine.
    constexpr std::size_t MAX_CHUNKS_PER_EQUIP = 150;
    auto mesh_snap = fw::native::weapon_witness::snapshot_player_weapon_meshes();
    fw::native::weapon_witness::log_mesh_snapshot(mesh_snap, "[mesh-witness]");

    if (mesh_snap.meshes.empty()) {
        FW_DBG("[mesh-tx] form=0x%X walker returned 0 meshes "
               "(weapon node empty / not assembled yet)", form_id);
        return;
    }

    std::vector<fw::net::MeshBlobMesh> wire_meshes;
    wire_meshes.reserve(mesh_snap.meshes.size());
    for (const auto& m : mesh_snap.meshes) {
        fw::net::MeshBlobMesh w{};
        w.m_name             = m.m_name.c_str();
        w.parent_placeholder = m.parent_placeholder.c_str();
        w.bgsm_path          = m.bgsm_path.c_str();
        w.vert_count         = m.vert_count;
        w.tri_count          = m.tri_count;
        w.local_transform    = m.local_transform;
        w.positions          = m.positions.empty() ? nullptr : m.positions.data();
        w.indices            = m.indices.empty()   ? nullptr : m.indices.data();
        wire_meshes.push_back(w);
    }

    // Chunks pre-flight estimate.
    std::size_t blob_estimate = 10;  // MeshBlobHeader
    for (const auto& m : mesh_snap.meshes) {
        blob_estimate += 76;  // MeshRecordHeader
        blob_estimate += m.m_name.size();
        blob_estimate += m.parent_placeholder.size();
        blob_estimate += m.bgsm_path.size();
        blob_estimate += static_cast<std::size_t>(m.vert_count) * 3 * sizeof(float);
        blob_estimate += static_cast<std::size_t>(m.tri_count) * 3 * sizeof(std::uint16_t);
    }
    constexpr std::size_t CHUNK_DATA_MAX = 1372;  // BCAST-safe sender stride
    const std::size_t est_chunks =
        (blob_estimate + CHUNK_DATA_MAX - 1) / CHUNK_DATA_MAX;
    if (est_chunks > MAX_CHUNKS_PER_EQUIP) {
        FW_WRN("[mesh-tx] form=0x%X est_chunks=%zu > MAX=%zu — "
               "skipping (blob=%zu B, %zu meshes)",
               form_id, est_chunks, MAX_CHUNKS_PER_EQUIP,
               blob_estimate, wire_meshes.size());
        return;
    }

    const std::size_t n_chunks =
        fw::net::client().enqueue_mesh_blob_for_equip(
            form_id, wire_meshes.data(), wire_meshes.size());
    FW_LOG("[mesh-tx] form=0x%X meshes=%zu queued_chunks=%zu (est=%zu)",
           form_id, wire_meshes.size(), n_chunks, est_chunks);
}

std::mutex g_deferred_mesh_mtx;
std::deque<std::uint32_t> g_deferred_mesh_queue;
std::atomic<unsigned> g_deferred_workers_in_flight{0};

void deferred_mesh_worker(std::uint32_t form_id, unsigned int delay_ms) {
    Sleep(delay_ms);
    {
        std::lock_guard lk(g_deferred_mesh_mtx);
        g_deferred_mesh_queue.push_back(form_id);
    }
    HWND hwnd = fw::dispatch::get_target_hwnd();
    if (hwnd) {
        PostMessageW(hwnd, FW_MSG_DEFERRED_MESH_TX, 0, 0);
    }
    g_deferred_workers_in_flight.fetch_sub(1, std::memory_order_relaxed);
}

void arm_deferred_mesh_tx(std::uint32_t form_id, unsigned int delay_ms = 300) {
    // Cap concurrent workers: spam-equipping should not spawn 50 threads.
    // If too many in flight, drop the new arm (the existing ones will
    // eventually fire and the LATEST is what matters anyway).
    constexpr unsigned MAX_INFLIGHT = 4;
    unsigned cur = g_deferred_workers_in_flight.fetch_add(1,
        std::memory_order_relaxed);
    if (cur >= MAX_INFLIGHT) {
        g_deferred_workers_in_flight.fetch_sub(1, std::memory_order_relaxed);
        FW_DBG("[mesh-tx] deferred: too many in-flight workers (%u), drop "
               "arm for form=0x%X",
               cur, form_id);
        return;
    }
    std::thread(&deferred_mesh_worker, form_id, delay_ms).detach();
}

} // namespace

// Public — main_menu_hook WndProc calls this on FW_MSG_DEFERRED_MESH_TX.
void on_deferred_mesh_tx_message() {
    std::deque<std::uint32_t> local;
    {
        std::lock_guard lk(g_deferred_mesh_mtx);
        local.swap(g_deferred_mesh_queue);
    }
    if (local.empty()) return;
    for (std::uint32_t form_id : local) {
        FW_DBG("[mesh-tx] deferred fire for form=0x%X", form_id);
        try_mesh_tx_for_form(form_id);
    }
}

namespace {

// ----------------------------------------------------------------------------
// Engine signatures (from re/M9_equipment_AGENT_A_dossier.txt — RE'd 2026-04-27)
// ----------------------------------------------------------------------------
//
// bool ActorEquipManager::EquipObject(
//     ActorEquipManager*  this,           // a1 = qword_1431E3328 singleton
//     Actor*              actor,          // a2 = target actor
//     BGSObjectInstance*  object,         // a3 = sp<{TESForm*, void*}>
//     std::uint32_t       stackID,        // a4
//     std::int32_t        count,          // a5
//     const BGSEquipSlot* slot,           // a6 (null = use form's default)
//     bool                queueEquip,     // a7
//     bool                forceEquip,     // a8
//     bool                playSounds,     // a9
//     bool                applyNow,       // a10
//     bool                locked);        // a11
//
// bool ActorEquipManager::UnequipObject(
//     ActorEquipManager*  this,           // a1
//     Actor*              actor,          // a2
//     BGSObjectInstance*  object,         // a3
//     std::int32_t        count,          // a4   ← ARG ORDER DIFFERS
//     const BGSEquipSlot* slot,           // a5   ← from EquipObject!
//     std::int32_t        stackID,        // a6   ← (a5/a6 swapped)
//     bool                queueEquip,     // a7
//     bool                forceEquip,     // a8
//     bool                playSounds,     // a9
//     bool                applyNow,       // a10
//     const BGSEquipSlot* slotBeingReplaced); // a11
//
// **CRITICAL**: yesterday's M9 hook attempt mistakenly assumed identical
// arg order — caused argument tearing when reading slot_form_id from the
// wrong register. This impl has them right (verified via decomp).

using EquipObjectFn = char (__fastcall*)(
    void* mgr, void* actor, void** object,
    std::uint32_t stackID,
    std::int32_t  count,
    void* slot,
    char queueEquip, char forceEquip, char playSounds, char applyNow,
    char locked);

using UnequipObjectFn = char (__fastcall*)(
    void* mgr, void* actor, void** object,
    std::int32_t  count,
    void* slot,
    std::int32_t  stackID,
    char queueEquip, char forceEquip, char playSounds, char applyNow,
    void* slotBeingReplaced);

EquipObjectFn   g_orig_equip   = nullptr;
UnequipObjectFn g_orig_unequip = nullptr;

// Fire counters for log correlation (not state).
std::atomic<std::uint64_t> g_equip_fires{0};
std::atomic<std::uint64_t> g_unequip_fires{0};

// Module base captured at install time — needed by the M9.w4 mod extractor
// to compute absolute address of the BGSObjectInstanceExtra vtable for
// vtable-pointer disambiguation against type-byte collisions.
std::uintptr_t g_module_base = 0;

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

inline std::uint64_t now_ms() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

// SEH-protected read of TESForm.formID. Returns 0 on null / fault.
std::uint32_t safe_read_form_id(void* form) {
    if (!form) return 0;
    __try {
        return *reinterpret_cast<std::uint32_t*>(
            reinterpret_cast<char*>(form) + offsets::FORMID_OFF);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

// Extract item TESForm* from BGSObjectInstance. The `object` arg to
// {Equip,Unequip}Object is `_QWORD *obj` where obj[0] is the TESForm*
// (this is what the engine reads at `*a3` per decomp). obj[1] is some
// extra-data slot (stack-id-cache or NiPointer; if 0, engine recomputes).
void* safe_read_item_form(void** object) {
    if (!object) return nullptr;
    __try {
        return *object;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
}

// Extract item BGSObjectInstanceExtra* (= the OMOD-applied InstanceData
// holder) from BGSObjectInstance.extra slot at obj[1]. CONFIRMED via
// TTD trace 2026-05-03: this matches EXACTLY the OIE pointer the engine
// passes as 3rd arg of sub_140436820 (BUILD-HOLDER) for the same equip
// event. Extracting OIE via inventory walk (extract_equipped_mods)
// returns a DIFFERENT, "default" InstanceData that has priority=0
// regardless of OMOD upgrades. object[1] is the engine's authoritative
// pointer with the OMOD-applied priority field at +0x56 ready to read.
//
// May be null when engine wants the helper to recompute defaults from
// the form (rare for equip events where the inventory-resolved instance
// is always present). Caller should fall back to ARMO+0x2A6 default
// priority in that case (already handled inside seh_compute_effective_priority).
void* safe_read_item_extra(void** object) {
    if (!object) return nullptr;
    __try {
        return object[1];
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
}

// Is `actor` the local PlayerCharacter? Filter: actor's TESForm.formID
// must be PLAYER_FORMID (0x14). We only want to broadcast events the
// LOCAL player triggered — not NPC equip changes (combat AI swaps,
// dressing actions, etc) which would flood the network.
bool actor_is_local_player(void* actor) {
    return safe_read_form_id(actor) == offsets::PLAYER_FORMID;
}

// ============================================================================
// === M9 wedge 4 — production mod extraction ================================
// ============================================================================
//
// Replaces the iter 1-4 diagnostic dumps (which targeted the WRONG struct —
// TESObjectWEAP::Data — because formType 0x84 in BGSObjectInstance is for
// BGSSoundOutput, not BGSMod). Iter 5 (IDA tiebreaker) revealed the correct
// path: peer's actual mods live in the inventory's BSExtraDataList as
// BGSObjectInstanceExtra (type byte 0x35) → 16-byte inner struct → packed
// bitstream header → N×8B ObjectModifier records. See
// re/M9_w4_TIEBREAKER_analysis.md for full RE.
//
// All helpers below are POD-only with __try/__except wrappers — they MUST
// NOT use std::string / std::vector / FW_LOG inside the SEH-protected blocks
// (C2712 MSVC restriction). The OUTER caller (extract_equipped_mods) uses
// std::vector and FW_LOG only AFTER the helpers return.

// SEH-protected qword read.
bool seh_read_qword_w4(void* addr, std::uint64_t* out) {
    __try {
        *out = *reinterpret_cast<std::uint64_t*>(addr);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *out = 0;
        return false;
    }
}

// M9.w2 PROPER (May 3 2026) — POD-only helper that calls the engine's
// sub_140436820(holder, ARMO*, OIE*) to build the [ARMO*, InstanceData*]
// pair, reads InstanceData+0x56 (OMOD-effective priority) if non-null
// or ARMO+0x2A6 (form default) if null, then refcount-releases the
// holder's InstanceData ptr per the engine's own pattern (see decomp of
// sub_140658DF0 line 28-39 in re/M9_arma_select_AGENT_A_r8_dec_140658DF0.txt).
//
// Lives in the SEH POD-only zone (no std::vector / no FW_LOG inside __try)
// so the OUTER caller (which uses std::vector mods) doesn't trip C2712.
//
// Returns 0 on any SEH or null inputs — caller treats 0 as "use default
// priority" downstream (the receiver's resolve_armor_nif_path falls back
// to reading ARMO+0x2A6 itself when wire priority is 0).
std::uint16_t seh_compute_effective_priority(void* item_form,
                                              void* oie,
                                              std::uintptr_t module_base) {
    if (!item_form || module_base == 0) return 0;

    using BuildHolderFn = void (__fastcall*)(void**, void*, void*);
    auto build_holder = reinterpret_cast<BuildHolderFn>(
        module_base + fw::offsets::OBJINSTANCE_BUILD_HOLDER_RVA);

    void* holder[2] = {nullptr, nullptr};
    __try {
        build_holder(holder, item_form, oie);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        holder[0] = nullptr;
        holder[1] = nullptr;
    }

    std::uint16_t prio = 0;
    __try {
        if (holder[1]) {
            prio = *reinterpret_cast<std::uint16_t*>(
                reinterpret_cast<char*>(holder[1]) +
                fw::offsets::TESOBJECTARMO_INSTANCEDATA_PRIORITY_OFF);
        } else {
            prio = *reinterpret_cast<std::uint16_t*>(
                reinterpret_cast<char*>(item_form) +
                fw::offsets::TESOBJECTARMO_DEFAULT_PRIORITY_OFF);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        prio = 0;
    }

    // Release holder[1] refcount (NiPointer-style; same pattern as the
    // engine's call site in sub_140658DF0).
    if (holder[1]) {
        __try {
            long* rc = reinterpret_cast<long*>(
                reinterpret_cast<char*>(holder[1]) + 8);
            if (_InterlockedDecrement(rc) == 0) {
                auto vt = *reinterpret_cast<void (__fastcall***)
                    (void*, char)>(holder[1]);
                vt[0](holder[1], 1);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // Refcount release SEH'd — leak rather than crash.
        }
    }
    return prio;
}

// SEH-protected dword read.
bool seh_read_dword_w4(void* addr, std::uint32_t* out) {
    __try {
        *out = *reinterpret_cast<std::uint32_t*>(addr);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *out = 0;
        return false;
    }
}

// SEH-protected byte read.
bool seh_read_byte_w4(void* addr, std::uint8_t* out) {
    __try {
        *out = *reinterpret_cast<std::uint8_t*>(addr);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *out = 0;
        return false;
    }
}

// OIE.inner.data layout (CORRECTED 2026-04-30 from runtime probe).
//
// Tiebreaker analysis hypothesised a packed-bitstream header before the
// records. That description applies to the SAVEGAME serialisation path
// (BGSObjectInstanceExtra::Init which deserialises a bitstream into the
// runtime form). The RUNTIME, in-memory representation we read here is
// FLAT — `byte_len` bytes is exactly `byte_len / 8` records of 8 bytes
// each, starting at `data + 0`. No header walker needed.
//
// Empirical confirmation across 4 weapons in iter 7 test:
//   Vault Suit (1 OMOD):     byte_len=8,  1 record at data+0..+7
//   10mm Pistol modded #1:   byte_len=48, 6 records at data+0..+47
//   10mm Pistol modded #2:   byte_len=96, 12 records at data+0..+95
//
// Each record (8 B):
//   +0..+3  u32 mod_form_id   (OMOD form, formType 0x90)
//   +4      u8  attach_index  (slot/order index — always 0 in observed data)
//   +5      u8  rank/index2   (always 1 in observed data — likely "rank=1")
//   +6      u8  flag          (always 0)
//   +7      u8  pad/garbage   (uninitialised — DO NOT trust)
//
// POD-only.
struct OieHeaderWalkResult {
    const std::uint8_t* records_ptr;   // start of 8B records, nullptr on fail
    std::uint32_t       record_count;  // number of records (0 on fail)
};

OieHeaderWalkResult oie_walk_header(const std::uint8_t* data,
                                     std::uint32_t       byte_len) {
    OieHeaderWalkResult r{nullptr, 0};
    if (!data || byte_len < offsets::OBJMOD_RECORD_STRIDE) return r;
    // Flat: byte_len = N * 8 (record stride)
    if ((byte_len % offsets::OBJMOD_RECORD_STRIDE) != 0) {
        // Not aligned — could indicate the buffer DOES have a header in
        // some edge case. Try aligned floor and proceed; if interpretation
        // is wrong, the form_ids will be garbage and we'll log them.
        // (Better than refusing to extract — the wire layer will sanity-
        // check form_ids on the receiver via lookup_by_form_id.)
    }
    r.records_ptr  = data;
    r.record_count = byte_len / offsets::OBJMOD_RECORD_STRIDE;
    return r;
}

// Read one ObjectModifier record (8 bytes) at records_base + index*8.
// Returns true on success.
struct ObjectModifierRec {
    std::uint32_t mod_form_id;
    std::uint8_t  attach_index;
    std::uint8_t  index2_or_rank;
    std::uint8_t  flag;
};

bool oie_read_record(const std::uint8_t* records_base,
                     std::uint32_t       index,
                     ObjectModifierRec* out)
{
    if (!records_base || !out) return false;
    const std::uint8_t* rec = records_base + index * offsets::OBJMOD_RECORD_STRIDE;
    std::uint32_t form_id = 0;
    std::uint8_t  attach_index = 0;
    std::uint8_t  index2 = 0;
    std::uint8_t  flag = 0;
    bool ok = true;
    ok &= seh_read_dword_w4(const_cast<std::uint8_t*>(
            rec + offsets::OBJMOD_FORM_ID_OFF), &form_id);
    ok &= seh_read_byte_w4(const_cast<std::uint8_t*>(
            rec + offsets::OBJMOD_ATTACH_INDEX_OFF), &attach_index);
    ok &= seh_read_byte_w4(const_cast<std::uint8_t*>(
            rec + offsets::OBJMOD_INDEX2_RANK_OFF), &index2);
    ok &= seh_read_byte_w4(const_cast<std::uint8_t*>(
            rec + offsets::OBJMOD_FLAG_OFF), &flag);
    if (!ok) return false;
    out->mod_form_id    = form_id;
    out->attach_index   = attach_index;
    out->index2_or_rank = index2;
    out->flag           = flag;
    return true;
}

// SEH-protected walk of the BSExtraDataList linked list to find a
// BGSObjectInstanceExtra (type byte == 0x35). Returns the BSExtraData
// pointer to the OIE, or nullptr if absent / SEH.
//
// Identification strategy: (1) check type byte at +0x12 == 0x35, AND
// (2) cross-verify vtable at +0x00 == OIE vtable @ RVA 0x2462298 (some
// BSExtraData subtypes share type bytes by accident; vtable check is the
// definitive disambiguator).
void* find_oie_in_extras(void* extra_list_head, std::uintptr_t module_base) {
    if (!extra_list_head) return nullptr;
    const std::uintptr_t expected_vtable =
        module_base + offsets::BGSOBJECTINSTANCEEXTRA_VTABLE_RVA;

    // Walk up to 64 nodes (sanity cap — real lists rarely exceed 30).
    void* node = extra_list_head;
    for (int i = 0; i < 64 && node != nullptr; ++i) {
        // Read type byte at +0x12
        std::uint8_t type = 0;
        if (!seh_read_byte_w4(reinterpret_cast<char*>(node) +
                offsets::BSEXTRADATA_TYPE_BYTE_OFF, &type)) return nullptr;

        if (type == offsets::BGSOBJECTINSTANCEEXTRA_TYPE_BYTE) {
            // Type matches — verify vtable for safety.
            std::uint64_t vtable_v = 0;
            if (seh_read_qword_w4(node, &vtable_v) &&
                vtable_v == expected_vtable) {
                return node;
            }
            // Type matched but vtable didn't — log and keep scanning. This
            // is a soft fail (not a hard error) since other extras might
            // collide on type byte 0x35 with different vtables.
        }

        // Advance to next node via +0x08 link
        std::uint64_t next_v = 0;
        if (!seh_read_qword_w4(reinterpret_cast<char*>(node) +
                offsets::BSEXTRADATA_NEXT_OFF, &next_v)) return nullptr;
        node = reinterpret_cast<void*>(next_v);
    }
    return nullptr;
}

// Public: extract the mod list for a specific weapon form from an actor's
// inventory. Walks: actor → +0xF8 inventory list → entries → match form_id
// → stack chain → BSExtraDataList → BGSObjectInstanceExtra → inner header
// walk → records.
//
// Returns true if at least one record was extracted (out vector populated).
// Returns false if the form was not found in inventory, or has no OIE
// (= no mods, weapon is in default config), or SEH along the way.
//
// NOTE: this function uses std::vector etc. — the SEH __try blocks are
// CONTAINED inside the helpers above. This function itself is regular C++.
struct ExtractedMod {
    std::uint32_t mod_form_id;
    std::uint8_t  attach_index;
    std::uint8_t  index2_or_rank;
};

bool extract_equipped_mods(void* actor,
                           std::uint32_t weap_form_id,
                           std::uintptr_t module_base,
                           std::vector<ExtractedMod>& out,
                           void** out_oie = nullptr)
{
    out.clear();
    if (out_oie) *out_oie = nullptr;
    if (!actor || weap_form_id == 0) return false;

    // 1) Get inventory list ptr at actor + 0xF8 (REFR_INV_LIST_OFF)
    std::uint64_t inv_list_ptr = 0;
    if (!seh_read_qword_w4(reinterpret_cast<char*>(actor) +
            offsets::REFR_INV_LIST_OFF, &inv_list_ptr)) return false;
    if (inv_list_ptr == 0) {
        // Inventory not yet materialized (lazy init). Could call
        // sub_140511F10 to materialize, but for w4 we assume the actor's
        // inventory is already live (engine populates it on equip event).
        FW_DBG("[w4-extract] actor=%p has null inventory list — skip", actor);
        return false;
    }
    auto* inv_list = reinterpret_cast<void*>(inv_list_ptr);

    // 2) Read inventory header: entries ptr + count + mutex
    //    NOTE: we DON'T lock the mutex from inside the equip detour because
    //    we're already inside an engine-held inventory operation (equip
    //    locks the inventory itself). Locking again would deadlock.
    std::uint64_t entries_ptr = 0;
    std::uint32_t entry_count = 0;
    if (!seh_read_qword_w4(reinterpret_cast<char*>(inv_list) +
            offsets::INVLIST_ENTRIES_OFF, &entries_ptr)) return false;
    if (!seh_read_dword_w4(reinterpret_cast<char*>(inv_list) +
            offsets::INVLIST_COUNT_OFF, &entry_count)) return false;
    if (entries_ptr == 0 || entry_count == 0 || entry_count > 4096) {
        FW_DBG("[w4-extract] inventory empty/bogus (entries=%llX count=%u)",
               static_cast<unsigned long long>(entries_ptr), entry_count);
        return false;
    }
    auto* entries = reinterpret_cast<std::uint8_t*>(entries_ptr);

    // 3) Find the entry matching weap_form_id
    void* matched_data = nullptr;  // BGSInventoryItem.data (Stack chain head)
    for (std::uint32_t i = 0; i < entry_count; ++i) {
        auto* item = entries + i * offsets::INVENTORY_ITEM_STRIDE;
        std::uint64_t obj_ptr = 0;
        if (!seh_read_qword_w4(item, &obj_ptr)) continue;
        if (obj_ptr == 0) continue;

        std::uint32_t form_id = 0;
        if (!seh_read_dword_w4(reinterpret_cast<char*>(
                reinterpret_cast<void*>(obj_ptr)) + offsets::FORMID_OFF,
                &form_id)) continue;
        if (form_id != weap_form_id) continue;

        // Found — read item.data (+0x08) which is Stack chain head
        std::uint64_t data_ptr = 0;
        if (!seh_read_qword_w4(item + 0x08, &data_ptr)) break;
        matched_data = reinterpret_cast<void*>(data_ptr);
        break;
    }
    if (!matched_data) {
        // Form not in inventory — silently return (common: PipBoy "fake"
        // equips for misc items that never enter inventory). No log to
        // avoid spam.
        return false;
    }

    // 4) Walk Stack chain (vtable @+0x00, refcount @+0x08, NEXT @+0x10,
    //    EXTRAS @+0x18). For each stack, find BGSObjectInstanceExtra
    //    (type byte 0x35 + vtable check) in its BSExtraDataList.
    void* stack = matched_data;
    void* oie = nullptr;
    for (int s = 0; s < 16 && stack != nullptr && oie == nullptr; ++s) {
        std::uint64_t extras_ptr = 0;
        if (!seh_read_qword_w4(reinterpret_cast<char*>(stack) +
                offsets::INV_STACK_EXTRAS_OFF, &extras_ptr)) break;
        if (extras_ptr != 0) {
            auto* xlist = reinterpret_cast<void*>(extras_ptr);
            std::uint64_t list_head = 0;
            if (seh_read_qword_w4(reinterpret_cast<char*>(xlist) +
                    offsets::BSEXTRADATALIST_HEAD_OFF, &list_head)) {
                oie = find_oie_in_extras(reinterpret_cast<void*>(list_head),
                                          module_base);
            }
        }
        // Advance to next stack via +0x10
        std::uint64_t next_ptr = 0;
        if (!seh_read_qword_w4(reinterpret_cast<char*>(stack) +
                offsets::INV_STACK_NEXT_OFF, &next_ptr)) break;
        stack = reinterpret_cast<void*>(next_ptr);
    }

    // M9.w2 PROPER (May 3 2026): expose the OIE pointer to the caller so
    // it can compute the OMOD-effective ARMA priority via sub_140436820.
    // We populate this even when the records walk fails — the caller may
    // still want to call the engine helper to confirm "no priority override".
    if (out_oie) *out_oie = oie;

    if (!oie) {
        // No OIE → weapon is in default config (no mods to ship). Silent.
        return false;
    }

    // 5) Read OIE.inner ptr at +0x18, then walk records.
    std::uint64_t inner_ptr = 0;
    if (!seh_read_qword_w4(reinterpret_cast<char*>(oie) +
            offsets::BGSOBJECTINSTANCEEXTRA_INNER_OFF, &inner_ptr)) return false;
    if (inner_ptr == 0) return false;  // OIE found but no inner data

    auto* inner = reinterpret_cast<std::uint8_t*>(inner_ptr);
    std::uint64_t data_buf_ptr = 0;
    std::uint32_t data_byte_len = 0;
    if (!seh_read_qword_w4(inner + offsets::OIE_INNER_DATA_OFF,
            &data_buf_ptr)) return false;
    if (!seh_read_dword_w4(inner + offsets::OIE_INNER_DATA_BYTELEN_OFF,
            &data_byte_len)) return false;
    if (data_buf_ptr == 0 || data_byte_len < offsets::OBJMOD_RECORD_STRIDE ||
            data_byte_len > 65536) {
        return false;
    }
    auto* data_buf = reinterpret_cast<std::uint8_t*>(data_buf_ptr);

    // 6) Walk records. byte_len is exact: byte_len/8 = N records (no header).
    OieHeaderWalkResult walk = oie_walk_header(data_buf, data_byte_len);
    if (!walk.records_ptr || walk.record_count == 0) return false;
    if (walk.record_count > 32) {
        // Sanity: 32 mods max per weapon. Higher = corruption.
        FW_WRN("[w4-extract] suspicious record_count=%u — clamping to 32",
               walk.record_count);
        walk.record_count = 32;
    }

    // 7) Iterate records, populate out vector
    out.reserve(walk.record_count);
    for (std::uint32_t i = 0; i < walk.record_count; ++i) {
        ObjectModifierRec rec{};
        if (!oie_read_record(walk.records_ptr, i, &rec)) continue;
        if (rec.mod_form_id == 0) continue;  // sentinel/empty slot
        ExtractedMod em;
        em.mod_form_id    = rec.mod_form_id;
        em.attach_index   = rec.attach_index;
        em.index2_or_rank = rec.index2_or_rank;
        out.push_back(em);
    }
    return !out.empty();
}

// ----------------------------------------------------------------------------
// Detours
// ----------------------------------------------------------------------------

char __fastcall detour_equip_object(
    void* mgr, void* actor, void** object,
    std::uint32_t stackID, std::int32_t count, void* slot,
    char queueEquip, char forceEquip, char playSounds, char applyNow,
    char locked)
{
    const auto fire = g_equip_fires.fetch_add(1, std::memory_order_relaxed) + 1;

    // Re-entry guard: if we're inside an apply-from-remote path (wedge 2
    // future), tls_applying_remote is true — pass through silently. In
    // wedge 1 this never fires (we don't apply), but the guard is here
    // so it's already correct when wedge 2 lands.
    if (tls_applying_remote) {
        FW_DBG("[equip-tx] EQUIP fire #%llu — applying_remote, passthrough",
               static_cast<unsigned long long>(fire));
        return g_orig_equip ? g_orig_equip(mgr, actor, object, stackID, count,
                                            slot, queueEquip, forceEquip,
                                            playSounds, applyNow, locked) : 0;
    }

    // Filter to local-player-only events. NPC equip changes would flood
    // the network (Sanctuary settlers swap between baseball bat and
    // pistol via AI behaviors several times per minute each).
    if (!actor_is_local_player(actor)) {
        return g_orig_equip ? g_orig_equip(mgr, actor, object, stackID, count,
                                            slot, queueEquip, forceEquip,
                                            playSounds, applyNow, locked) : 0;
    }

    // Extract item + slot form IDs.
    void* item_form = safe_read_item_form(object);
    const std::uint32_t item_form_id = safe_read_form_id(item_form);
    const std::uint32_t slot_form_id = safe_read_form_id(slot);

    if (item_form_id == 0) {
        // Defensive: if we can't read the item form_id, log + skip
        // broadcast (don't poison the network with garbage events).
        FW_WRN("[equip-tx] EQUIP fire #%llu — item_form null/unreadable, skip",
               static_cast<unsigned long long>(fire));
        return g_orig_equip ? g_orig_equip(mgr, actor, object, stackID, count,
                                            slot, queueEquip, forceEquip,
                                            playSounds, applyNow, locked) : 0;
    }

    FW_LOG("[equip-tx] EQUIP fire #%llu item=0x%X slot=0x%X stack=%u count=%d "
           "(applyNow=%d queue=%d force=%d)",
           static_cast<unsigned long long>(fire),
           item_form_id, slot_form_id, stackID, count,
           int(applyNow), int(queueEquip), int(forceEquip));

    // === M9.w4: extract OMOD list for the equipped weapon ===
    // Walks Actor.inventory → matches form_id → BSExtraDataList → OIE →
    // 8-byte ObjectModifier records. Resulting mods get serialised into
    // the EQUIP_OP payload's variable-length tail (protocol v7).
    std::vector<ExtractedMod> mods;
    extract_equipped_mods(actor, item_form_id, g_module_base, mods);

    // === M9.w2 PROPER priority extraction (corrected May 3 2026) ===
    //
    // Read OIE directly from `object[1]` (= BGSObjectInstance.extra) — this
    // is the engine's OWN authoritative OMOD-applied InstanceData pointer
    // for THIS specific equip event. CONFIRMED via TTD trace:
    //
    //   ENGINE: sub_140436820 entry r8(OIE) = 0000013b8d76f0d8
    //   OURS  : object[1]              = 0000013b8d76f0d8  ← MATCH!
    //
    // First-attempt v10 used the OIE returned by extract_equipped_mods'
    // inventory walk, which gave a DIFFERENT pointer (0000013b8b538a78)
    // pointing to a "default unmodded" InstanceData — priority field at
    // +0x56 was 0 regardless of attached OMOD upgrades. The engine has
    // multiple InstanceData allocations per inventory item; only the one
    // BGSObjectInstance carries (object[1]) holds the post-OMOD priority.
    //
    // seh_compute_effective_priority handles null-OIE gracefully by
    // falling back to ARMO+0x2A6 default priority.
    void* oie_from_object = safe_read_item_extra(object);

    std::uint16_t effective_prio = 0;
    if (item_form && g_module_base) {
        effective_prio = seh_compute_effective_priority(
            item_form, oie_from_object, g_module_base);
        FW_DBG("[w2-prio] form=0x%X effective_prio=%u "
               "(object[1]=%p, source=BGSObjectInstance.extra)",
               item_form_id, static_cast<unsigned>(effective_prio),
               oie_from_object);
    }

    // Convert to wire-format records (8 B each, pad zeroed in client::
    // enqueue_equip_op).
    std::vector<fw::net::EquipModRecord> wire_mods;
    wire_mods.reserve(mods.size());
    for (const auto& m : mods) {
        fw::net::EquipModRecord r{};
        r.form_id      = m.mod_form_id;
        r.attach_index = m.attach_index;
        r.rank         = m.index2_or_rank;
        r.flag         = 0;
        r.pad          = 0;
        wire_mods.push_back(r);
    }

    if (!wire_mods.empty()) {
        FW_LOG("[w4-tx] EQUIP form=0x%X has %zu mods:",
               item_form_id, wire_mods.size());
        for (std::size_t i = 0; i < wire_mods.size(); ++i) {
            FW_LOG("[w4-tx]   mod[%zu] form=0x%X attach=%u rank=%u",
                   i, wire_mods[i].form_id,
                   static_cast<unsigned>(wire_mods[i].attach_index),
                   static_cast<unsigned>(wire_mods[i].rank));
        }
    }

    const std::uint8_t mod_count = static_cast<std::uint8_t>(
        std::min<std::size_t>(wire_mods.size(),
                              static_cast<std::size_t>(fw::net::MAX_EQUIP_MODS)));

    // === M9.w4 v8 — TWO-STAGE BROADCAST (witness pattern, 2026-04-30 22:00) ===
    //
    // STAGE 1 (pre-chain, crash-safe):
    //   enqueue_equip_op fires NOW with mods only (no nif_descs). If the
    //   engine EquipObject SEH-AVs in g_orig_equip below, the broadcast
    //   has already left — peers do at least the BASE attach.
    //
    // STAGE 2 (post-chain, best-effort):
    //   After g_orig_equip returns the engine has assembled the modded
    //   weapon onto the local player's BipedAnim. Walk that subtree,
    //   query nif_path_cache for each NiAVObject, build a list of
    //   NifDescriptor, and send a SECOND enqueue with the delta. The
    //   receiver-side ghost_attach_weapon's idempotent path will see
    //   "already attached + nif_descs present" and apply just the mods
    //   on the existing weapon node — no double base attach.
    //
    // If g_orig_equip SEH AVs, stage 2 is silently skipped. Peers see the
    // base weapon with no mods (degraded mode) but the game survives and
    // the next equip-cycle has another shot. SEH-wrap of the chain itself
    // is tracked separately in the todo list.
    fw::net::client().enqueue_equip_op(
        item_form_id,
        static_cast<std::uint8_t>(fw::net::EquipOpKind::EQUIP),
        slot_form_id,
        count,
        now_ms(),
        effective_prio,  // v10 — M9.w2 PROPER OMOD priority
        wire_mods.empty() ? nullptr : wire_mods.data(),
        mod_count,
        /*nif_descs=*/nullptr,
        /*nif_count=*/0);

    // STAGE 1.5 — chain through to engine (mod assembly happens here).
    const char rc = g_orig_equip
        ? g_orig_equip(mgr, actor, object, stackID, count, slot,
                       queueEquip, forceEquip, playSounds, applyNow, locked)
        : 0;

    // === M9.w4 v9 — RAW MESH EXTRACTION + WIRE BROADCAST ===
    //
    // RE-ENABLED 2026-05-01 06:50 with proper gating after the prior
    // regression (Vault Suit + OMOD passed the old `!wire_mods.empty()`
    // gate, walker walked the body bipedAnim, 106 KB blob saturated the
    // reliable channel, ghost stuck on stale weapon).
    //
    // GATES:
    //   1. is_weapon_form(form_id) — resolve via lookup_by_form_id +
    //      TESModel walk + "Weapons\\..." path heuristic. Returns true
    //      ONLY for TESObjectWEAP forms; armor/ammo/food return false.
    //      This is the precise filter we needed — armor with legendary
    //      OMODs (Vault Suit) returns false here.
    //   2. Walker bail (mesh_snap.meshes.empty()) — second line of defense:
    //      if the weapon attach node has no children for some reason,
    //      walker returns empty and we don't ship anything.
    //   3. Chunks cap MAX_CHUNKS_PER_EQUIP — drop the blob if it would
    //      generate more than N chunks. Stops a freak large weapon from
    //      saturating the channel. Cap chosen 50 (≈70 KB) covers all
    //      vanilla + observed modded weapons (10mm pistol modded peaks
    //      ~46 chunks). Beyond cap → log warning, ghost gets no mesh.
    //
    // Future hardening (separate todos):
    //   - Defer mesh-tx off the equip-detour hot path (main-thread idle
    //     worker) so a slow snapshot doesn't block the engine equip call.
    //   - Ship MESH_BLOB chunks unreliable instead of reliable, so they
    //     never compete for ACK budget with EQUIP_BCAST itself.
    // Mesh-tx gate (2026-05-01 21:25):
    //   - is_weapon_form: form is TESObjectWEAP (Weapons\* path resolves)
    //   - !wire_mods.empty(): form has OMODs attached
    //
    // The OMOD gate excludes melee weapons (manganello, sword, etc.) and
    // STOCK firearms (no mods). User insight: melee/static weapons have
    // valid base NIFs and work via legacy ghost_attach_weapon. Only
    // RUNTIME-ASSEMBLED MODDED FIREARMS need mesh-blob (their composed
    // BSGeometry tree can't be replicated by loading a static NIF).
    if (fw::native::is_weapon_form(item_form_id) && !wire_mods.empty()) {
        // Immediate post-chain attempt — usually fails (walker race with
        // engine assembly), but we try anyway in case the engine had time.
        try_mesh_tx_for_form(item_form_id);
        // Schedule a deferred re-walk 300ms later — by then assembly is
        // typically complete and walker will find the assembled tree.
        arm_deferred_mesh_tx(item_form_id, 300);
    } else {
        FW_DBG("[mesh-tx] form=0x%X not a weapon (is_weapon_form=false) — skip",
               item_form_id);
    }

    // STAGE 2 — witness walk + delta broadcast (legacy path-based snapshot,
    // kept compiled for now; produces empty descriptors because nif_path_cache
    // misses weapon NIFs entirely. Will be removed when v9 wire ships.)
    if (!wire_mods.empty()) {
        auto snap = fw::native::weapon_witness::snapshot_local_player_weapon();
        fw::native::weapon_witness::log_snapshot(snap, "[w4-witness]");

        if (!snap.mods.empty()) {
            // Convert weapon_witness::ModDescriptor → fw::net::NifDescriptor
            fw::net::NifDescriptor wire_nif_descs[fw::net::MAX_NIF_DESCRIPTORS]{};
            std::uint8_t wire_nif_count = 0;
            const std::size_t cap = static_cast<std::size_t>(
                fw::net::MAX_NIF_DESCRIPTORS);
            const std::size_t take =
                (snap.mods.size() < cap) ? snap.mods.size() : cap;
            for (std::size_t i = 0; i < take; ++i) {
                const auto& m = snap.mods[i];
                const std::size_t pl =
                    (m.nif_path.size() < fw::net::MAX_NIF_PATH_LEN)
                    ? m.nif_path.size() : fw::net::MAX_NIF_PATH_LEN;
                std::memcpy(wire_nif_descs[i].nif_path,
                            m.nif_path.data(), pl);
                wire_nif_descs[i].nif_path[pl] = 0;
                const std::size_t nl =
                    (m.parent_node_name.size() < fw::net::MAX_NIF_NAME_LEN)
                    ? m.parent_node_name.size() : fw::net::MAX_NIF_NAME_LEN;
                std::memcpy(wire_nif_descs[i].parent_name,
                            m.parent_node_name.data(), nl);
                wire_nif_descs[i].parent_name[nl] = 0;
                std::memcpy(wire_nif_descs[i].local_transform,
                            m.local_transform,
                            sizeof(wire_nif_descs[i].local_transform));
                ++wire_nif_count;
            }

            // Stage 2 broadcast — same form_id, same kind, but with
            // nif_descs filled in. The receiver's ghost_attach_weapon
            // detects "already attached" and applies just the mod loop
            // on top of the existing base weapon node.
            fw::net::client().enqueue_equip_op(
                item_form_id,
                static_cast<std::uint8_t>(fw::net::EquipOpKind::EQUIP),
                slot_form_id,
                count,
                now_ms(),
                effective_prio,  // v10 — same priority as stage 1
                wire_mods.empty() ? nullptr : wire_mods.data(),
                mod_count,
                wire_nif_descs,
                wire_nif_count);
            FW_LOG("[w4-witness] sent stage-2 delta: form=0x%X with %u "
                   "NIF descriptors", item_form_id,
                   static_cast<unsigned>(wire_nif_count));
        }
    }

    return rc;
}

char __fastcall detour_unequip_object(
    void* mgr, void* actor, void** object,
    std::int32_t count, void* slot, std::int32_t stackID,
    char queueEquip, char forceEquip, char playSounds, char applyNow,
    void* slotBeingReplaced)
{
    const auto fire = g_unequip_fires.fetch_add(1, std::memory_order_relaxed) + 1;

    if (tls_applying_remote) {
        FW_DBG("[equip-tx] UNEQUIP fire #%llu — applying_remote, passthrough",
               static_cast<unsigned long long>(fire));
        return g_orig_unequip ? g_orig_unequip(mgr, actor, object, count, slot,
                                                stackID, queueEquip, forceEquip,
                                                playSounds, applyNow,
                                                slotBeingReplaced) : 0;
    }

    if (!actor_is_local_player(actor)) {
        return g_orig_unequip ? g_orig_unequip(mgr, actor, object, count, slot,
                                                stackID, queueEquip, forceEquip,
                                                playSounds, applyNow,
                                                slotBeingReplaced) : 0;
    }

    void* item_form = safe_read_item_form(object);
    const std::uint32_t item_form_id = safe_read_form_id(item_form);
    const std::uint32_t slot_form_id = safe_read_form_id(slot);

    if (item_form_id == 0) {
        FW_WRN("[equip-tx] UNEQUIP fire #%llu — item_form null/unreadable, skip",
               static_cast<unsigned long long>(fire));
        return g_orig_unequip ? g_orig_unequip(mgr, actor, object, count, slot,
                                                stackID, queueEquip, forceEquip,
                                                playSounds, applyNow,
                                                slotBeingReplaced) : 0;
    }

    FW_LOG("[equip-tx] UNEQUIP fire #%llu item=0x%X slot=0x%X stack=%d count=%d "
           "(applyNow=%d queue=%d force=%d)",
           static_cast<unsigned long long>(fire),
           item_form_id, slot_form_id, stackID, count,
           int(applyNow), int(queueEquip), int(forceEquip));

    // === M9.w4: also extract on UNEQUIP for cross-check (the engine often
    //   fires UNEQUIP→EQUIP cycles when modifying gear; logging on both
    //   sides confirms the extraction is stable across the cycle). For
    //   wire transmission, UNEQUIP doesn't strictly need the mod list
    //   (receiver detaches whatever it had attached) — but we log for
    //   visibility during sender testing.
    std::vector<ExtractedMod> mods;
    const bool extracted = extract_equipped_mods(
        actor, item_form_id, g_module_base, mods);
    if (extracted) {
        FW_LOG("[w4-tx] UNEQUIP form=0x%X had %zu mods (pre-unequip snapshot):",
               item_form_id, mods.size());
        for (std::size_t i = 0; i < mods.size(); ++i) {
            FW_LOG("[w4-tx]   mod[%zu] form=0x%X attach=%u rank=%u",
                   i,
                   mods[i].mod_form_id,
                   static_cast<unsigned>(mods[i].attach_index),
                   static_cast<unsigned>(mods[i].index2_or_rank));
        }
    }

    fw::net::client().enqueue_equip_op(
        item_form_id,
        static_cast<std::uint8_t>(fw::net::EquipOpKind::UNEQUIP),
        slot_form_id,
        count,
        now_ms());

    return g_orig_unequip ? g_orig_unequip(mgr, actor, object, count, slot,
                                            stackID, queueEquip, forceEquip,
                                            playSounds, applyNow,
                                            slotBeingReplaced) : 0;
}

} // anon namespace

// ----------------------------------------------------------------------------
// Install
// ----------------------------------------------------------------------------
bool install_equip_hook(std::uintptr_t module_base) {
    if (module_base == 0) {
        FW_ERR("[equip-hook] install: module_base = 0");
        return false;
    }
    // Stash for the M9.w4 mod extractor (needs absolute address of the
    // BGSObjectInstanceExtra vtable for type disambiguation).
    g_module_base = module_base;

    const auto equip_target = reinterpret_cast<void*>(
        module_base + offsets::ENGINE_EQUIP_OBJECT_RVA);
    const auto unequip_target = reinterpret_cast<void*>(
        module_base + offsets::ENGINE_UNEQUIP_OBJECT_RVA);

    bool ok_equip = false, ok_unequip = false;

    {
        void* trampoline = nullptr;
        const bool ok = fw::hooks::install(
            equip_target,
            reinterpret_cast<void*>(&detour_equip_object),
            &trampoline);
        if (ok && trampoline) {
            g_orig_equip = reinterpret_cast<EquipObjectFn>(trampoline);
            FW_LOG("[equip-hook] EquipObject installed at 0x%llX "
                   "(sub_140CE5900) — OBSERVE-only, M9 wedge 1",
                   reinterpret_cast<unsigned long long>(equip_target));
            ok_equip = true;
        } else {
            FW_ERR("[equip-hook] EquipObject install FAILED at 0x%llX",
                   reinterpret_cast<unsigned long long>(equip_target));
        }
    }

    {
        void* trampoline = nullptr;
        const bool ok = fw::hooks::install(
            unequip_target,
            reinterpret_cast<void*>(&detour_unequip_object),
            &trampoline);
        if (ok && trampoline) {
            g_orig_unequip = reinterpret_cast<UnequipObjectFn>(trampoline);
            FW_LOG("[equip-hook] UnequipObject installed at 0x%llX "
                   "(sub_140CE5DA0) — OBSERVE-only, M9 wedge 1",
                   reinterpret_cast<unsigned long long>(unequip_target));
            ok_unequip = true;
        } else {
            FW_ERR("[equip-hook] UnequipObject install FAILED at 0x%llX",
                   reinterpret_cast<unsigned long long>(unequip_target));
        }
    }

    return ok_equip && ok_unequip;
}

} // namespace fw::hooks
