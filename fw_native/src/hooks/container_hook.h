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

struct ApplyingRemoteGuard {
    ApplyingRemoteGuard();
    ~ApplyingRemoteGuard();
    ApplyingRemoteGuard(const ApplyingRemoteGuard&) = delete;
    ApplyingRemoteGuard& operator=(const ApplyingRemoteGuard&) = delete;
};

} // namespace fw::hooks
