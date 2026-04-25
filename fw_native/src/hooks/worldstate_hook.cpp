#include "worldstate_hook.h"

#include <windows.h>
#include <atomic>
#include <cstdint>

#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"
#include "../net/client.h"
#include "../net/protocol.h"

namespace fw::hooks {

namespace {

// Papyrus GlobalVariable.SetValue signature from decomp (sub_1411459E0):
//   __fastcall(VM* a1, uint32_t a2, TESGlobal* a3, float a4) → uint8_t
//   Body writes *(float*)(a3 + 0x30) = a4 unless const flag set.
using GlobalVarSetValueFn = std::uint8_t (*)(
    void* vm, std::uint32_t vm_id, void* global_obj, float new_value);

GlobalVarSetValueFn g_orig_global_set_value = nullptr;

// Thread-local flag: set to true while we're APPLYING a received BCAST so
// the hook doesn't re-broadcast the same value back to the server. FO4
// only calls these natives from the main thread, so one TLS slot is
// enough (applied-from-net path runs on net thread; when it triggers the
// engine fn via WndProc in the future, main thread will be in "applying"
// mode — we'll need to set this then).
//
// For MVP (direct memory write via apply_global_var) the bypass isn't
// triggered at all — no re-entrancy risk because the direct write doesn't
// go through the Papyrus native. Keeping the flag for when we add the
// indirect (native-call) apply path later.
thread_local bool g_applying_remote = false;

std::uint8_t __fastcall detour_global_set_value(
    void* vm, std::uint32_t vm_id, void* global_obj, float new_value)
{
    __try {
        if (global_obj && !g_applying_remote) {
            const auto* bytes = reinterpret_cast<const std::uint8_t*>(global_obj);
            std::uint32_t form_id = 0;
            std::uint32_t flags   = 0;
            __try {
                form_id = *reinterpret_cast<const std::uint32_t*>(
                    bytes + offsets::FORMID_OFF);
                flags = *reinterpret_cast<const std::uint32_t*>(
                    bytes + offsets::FLAGS_OFF);
            } __except (EXCEPTION_EXECUTE_HANDLER) {}

            const bool is_const =
                (flags & offsets::TESGLOBAL_FLAG_CONST) != 0;

            if (form_id != 0 && !is_const) {
                FW_LOG("[worldstate] GlobalVar.SetValue form=0x%X value=%g",
                       form_id, new_value);
                fw::net::client().enqueue_global_var_set(
                    form_id, static_cast<double>(new_value));
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        FW_ERR("[worldstate] SEH in detour_global_set_value");
    }

    // Always run the original so game behavior is preserved.
    if (g_orig_global_set_value) {
        return g_orig_global_set_value(vm, vm_id, global_obj, new_value);
    }
    return 0;
}

} // namespace

bool install_worldstate_hooks(std::uintptr_t module_base) {
    const auto target_ea =
        module_base + offsets::PAPYRUS_GLOBALVAR_SETVALUE_RVA;
    void* target = reinterpret_cast<void*>(target_ea);

    const bool ok = install(
        target,
        reinterpret_cast<void*>(&detour_global_set_value),
        reinterpret_cast<void**>(&g_orig_global_set_value));
    if (!ok) {
        FW_ERR("[worldstate] GlobalVar.SetValue hook install FAILED at 0x%llX",
               static_cast<unsigned long long>(target_ea));
        return false;
    }
    FW_LOG("[worldstate] GlobalVar.SetValue hook installed at 0x%llX "
           "(RVA 0x%lX)",
           static_cast<unsigned long long>(target_ea),
           static_cast<unsigned long>(offsets::PAPYRUS_GLOBALVAR_SETVALUE_RVA));
    return true;
}

} // namespace fw::hooks
