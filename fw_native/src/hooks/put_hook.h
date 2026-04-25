// B1.k.2: hook on ContainerMenu::TransferItem (sub_14103E950 @ RVA 0x103E950).
//
// Problem this solves: vt[0x7A] AddObjectToContainer fires on TAKE
// (dest=player, source=container) but NOT on PUT. Live test 2026-04-21
// on B1.g confirmed: A takes → B sees item disappear via engine-apply,
// but A puts-back and nothing reaches B.
//
// First attempt (B1.k.1) hooked sub_14031C310 as the "generic move item"
// function — zero fires in live log. That function is called only from
// two non-UI trampolines, not from the two-column TRASFERISCI menu UI.
//
// Second RE pass identified the real UI path: the Scaleform
// "transferItem" AS3 callback → id=1 registrar → ContainerMenuBase vt[1]
// switch case 1 → virtual call `(*(*this+168))(this, idx, count, side)`
// → ContainerMenu vtable slot[21] = sub_14103E950. We hook that.
//
// Signature (see offsets.h for struct layout notes):
//   void sub_14103E950(
//       ContainerMenu* this,       // a1
//       int            inv_idx,    // a2 — index into this's item array
//       unsigned int   count,      // a3 — transfer count (explicit)
//       unsigned __int8 side);     // a4 — 1 = DEPOSIT, 0 = WITHDRAW
//
// Filter in detour:
//   side == 0 → WITHDRAW, skip (already captured by vt[0x7A])
//   side == 1 → DEPOSIT, extract (container REFR from this+1064, item
//               form from (this+640)[idx*32]+0, count=a3) and submit.
//
// MUST run after install_container_hook (shares the existing
// submit_container_op_blocking pipeline + the tls_applying_remote
// feedback-loop guard).

#pragma once

#include <cstdint>

namespace fw::hooks {

bool install_put_hook(std::uintptr_t module_base);

} // namespace fw::hooks
