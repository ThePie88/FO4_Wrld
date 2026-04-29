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

#include "container_hook.h"   // tls_applying_remote (forward-compat for w2)
#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"
#include "../net/client.h"
#include "../net/protocol.h"

namespace fw::hooks {

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

// Is `actor` the local PlayerCharacter? Filter: actor's TESForm.formID
// must be PLAYER_FORMID (0x14). We only want to broadcast events the
// LOCAL player triggered — not NPC equip changes (combat AI swaps,
// dressing actions, etc) which would flood the network.
bool actor_is_local_player(void* actor) {
    return safe_read_form_id(actor) == offsets::PLAYER_FORMID;
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

    fw::net::client().enqueue_equip_op(
        item_form_id,
        static_cast<std::uint8_t>(fw::net::EquipOpKind::EQUIP),
        slot_form_id,
        count,
        now_ms());

    return g_orig_equip ? g_orig_equip(mgr, actor, object, stackID, count,
                                        slot, queueEquip, forceEquip,
                                        playSounds, applyNow, locked) : 0;
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
