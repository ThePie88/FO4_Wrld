#include "hook_manager.h"

#include <atomic>

#include <MinHook.h>

#include "log.h"

namespace fw::hooks {

namespace {

std::atomic<bool> g_initialized{false};

const char* status_name(MH_STATUS s) {
    switch (s) {
    case MH_OK:                        return "OK";
    case MH_ERROR_ALREADY_INITIALIZED: return "ALREADY_INITIALIZED";
    case MH_ERROR_NOT_INITIALIZED:     return "NOT_INITIALIZED";
    case MH_ERROR_ALREADY_CREATED:     return "ALREADY_CREATED";
    case MH_ERROR_NOT_CREATED:         return "NOT_CREATED";
    case MH_ERROR_ENABLED:             return "ENABLED";
    case MH_ERROR_DISABLED:            return "DISABLED";
    case MH_ERROR_NOT_EXECUTABLE:      return "NOT_EXECUTABLE";
    case MH_ERROR_UNSUPPORTED_FUNCTION:return "UNSUPPORTED_FUNCTION";
    case MH_ERROR_MEMORY_ALLOC:        return "MEMORY_ALLOC";
    case MH_ERROR_MEMORY_PROTECT:      return "MEMORY_PROTECT";
    case MH_ERROR_MODULE_NOT_FOUND:    return "MODULE_NOT_FOUND";
    case MH_ERROR_FUNCTION_NOT_FOUND:  return "FUNCTION_NOT_FOUND";
    default:                           return "?";
    }
}

} // namespace

bool init() {
    if (g_initialized.load()) {
        FW_WRN("hooks: init() called twice — returning existing state");
        return true;
    }
    const MH_STATUS s = MH_Initialize();
    if (s != MH_OK) {
        FW_ERR("hooks: MH_Initialize failed (%s)", status_name(s));
        return false;
    }
    g_initialized.store(true);
    FW_LOG("hooks: MinHook initialized");
    return true;
}

void shutdown() {
    if (!g_initialized.load()) return;
    const MH_STATUS s1 = MH_DisableHook(MH_ALL_HOOKS);
    if (s1 != MH_OK) {
        FW_WRN("hooks: MH_DisableHook(ALL) returned %s", status_name(s1));
    }
    const MH_STATUS s2 = MH_Uninitialize();
    if (s2 != MH_OK) {
        FW_WRN("hooks: MH_Uninitialize returned %s", status_name(s2));
    }
    g_initialized.store(false);
    FW_LOG("hooks: MinHook shut down");
}

bool install(void* target, void* detour, void** original) {
    if (!g_initialized.load()) {
        FW_ERR("hooks: install called before init()");
        return false;
    }
    if (!target || !detour) {
        FW_ERR("hooks: install with null target=%p detour=%p", target, detour);
        return false;
    }

    const MH_STATUS s = MH_CreateHook(target, detour, original);
    if (s != MH_OK) {
        FW_ERR("hooks: MH_CreateHook(target=%p) failed (%s)",
               target, status_name(s));
        return false;
    }
    const MH_STATUS s2 = MH_EnableHook(target);
    if (s2 != MH_OK) {
        FW_ERR("hooks: MH_EnableHook(target=%p) failed (%s)",
               target, status_name(s2));
        // Best-effort cleanup of the created hook.
        MH_RemoveHook(target);
        return false;
    }
    FW_LOG("hooks: installed target=%p detour=%p", target, detour);
    return true;
}

} // namespace fw::hooks
