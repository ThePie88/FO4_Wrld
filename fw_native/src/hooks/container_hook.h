// Hook on TESObjectREFR::AddObjectToContainer (vt[0x7A] of the REFR vtable
// at RVA 0x2564838). This is the convergent entry point for BOTH directions
// of a player-container transfer:
//   - Player takes from container: dest=player, source=container
//   - Player deposits to container: dest=container, source=player
//
// Signature (from CommonLibF4 + our decompile):
//   void __fastcall(
//       TESObjectREFR*          this_dest,
//       TESBoundObject*         item,
//       sp<ExtraDataList>*      extra,   // ignored in B0.3
//       int                     count,
//       TESObjectREFR*          old_container,   // source
//       uint32_t                reason)          // ITEM_REMOVE_REASON enum, ignored in B0.3
//
// The detour MUST call through so the transfer actually happens. In B0.3
// we only log direction + identity triple of the non-player ref. Network
// CONTAINER_OP send lands in B0.4.

#pragma once

#include <cstdint>

namespace fw::hooks {

bool install_container_hook(std::uintptr_t module_base);

// B1.g / B1.k.2 feedback-loop guard. Called by net/client.cpp's
// CONTAINER_BCAST handler around engine::apply_container_op_to_engine
// to mark the current thread's vt[0x7A] / ContainerMenu::TransferItem
// invocations as "do not re-emit to the network". RAII-style: construct
// before the engine call, destruct after. Thread-local.
//
// NOTE: the backing flag `tls_applying_remote` is defined in
// container_hook.cpp at namespace scope (NOT in an anonymous namespace
// anymore, since put_hook.cpp also reads it). Declared here as extern
// so both translation units see the same TLS variable.
extern thread_local bool tls_applying_remote;

// Nestable since loot rework L3 (2026-09-24): the flag is restored to what
// it was, not cleared, so a guard inside the dispatch drain's guard does not
// switch the drain's remaining ops back to "emit to the network".
struct ApplyingRemoteGuard {
    ApplyingRemoteGuard();
    ~ApplyingRemoteGuard();
    ApplyingRemoteGuard(const ApplyingRemoteGuard&) = delete;
    ApplyingRemoteGuard& operator=(const ApplyingRemoteGuard&) = delete;
private:
    bool prev_;
};

// Loot rework L3 (2026-09-24): a container is being activated by the local
// player (the Activate worker, before the ContainerMenu builds its list).
// If the server's view of it is known, the local inventory is aligned to it
// first, so the menu opens on what the server has and not on what the save
// says. The seed of a container the server does not know stays on the
// first op (vt[0x7A] take, TransferItem deposit): by then the menu has made
// the engine resolve the leveled lists, which an activation-time scan might
// see unresolved. A container whose runtime list does not exist yet is
// aligned once more when the activation has built it (L3.4, see
// container_activation_tick). MAIN THREAD (the Activate worker runs there).
void on_container_activation(void* refr, std::uint32_t form_id,
                             std::uint32_t base_id, std::uint32_t cell_id);

// Loot rework L3.4 (2026-09-24): polls the containers activated without a
// runtime list and aligns each one as soon as the engine has built it, or
// drops it with a warning 2 s later. Called from the main-thread tick next
// to Client::container_sweep_tick; cheap when nothing is watched.
void container_activation_tick();

// Loot rework L3.4 (2026-09-24): seed a container the server does not know
// from the caller's REFR, BEFORE the engine moves anything: the scan is the
// pre-op ground truth and the server applies the op that follows on top of
// it. Called by the take detour (vt[0x7A]) and by the deposit detour
// (ContainerMenu::TransferItem); until 2026-09-24 only the take seeded, so
// a deposit into an unknown container left a partial record on the server,
// never bootstrapped and replaced whole by the first scan of any client.
// A list present and empty is sent as the sentinel entry (item 0, count 0);
// a list the engine has not built scans as nothing and is not sent (the
// next touch retries). Idempotent per session via Client::seed_in_flight.
// MAIN THREAD (both detours run there).
void seed_container_if_unknown(void* container_ref, std::uint32_t form_id,
                               std::uint32_t base_id, std::uint32_t cell_id);

} // namespace fw::hooks
