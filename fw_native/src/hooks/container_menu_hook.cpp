#include "container_menu_hook.h"

#include <windows.h>
#include <atomic>
#include <cstdint>

#include "../hook_manager.h"
#include "../log.h"
#include "../main_thread_dispatch.h"
#include "../offsets.h"

namespace fw::hooks {

namespace {

using FactoryFn    = void* (*)();
using MenuIsOpenFn = bool (*)(void* ui, const void* name);
using MenuNameFn   = const void* (*)();
using UpdateListFn = void (*)(void* menu, std::uint8_t container_side);
using GetHandleFn  = std::uint32_t* (*)(void* refr, std::uint32_t* out);   // sub_140519190
// sub_141ACFCC0(ObjectInterface* this, void* pdata, GFx::Value* result,
// const char* name, const GFx::Value* args, uint64 nargs). Every parameter
// is 64 bits wide on the callee's side: `nargs` lands in a stack slot, and
// an `int` there leaves the high dword undefined, so the callee saw a
// non-zero count and dereferenced a null `args` (live 2026-09-24, AV at
// sub_141AC16B0+9 on every InvalidateLists).
using GfxInvokeFn  = void* (*)(void* obj, void* pdata, std::uint64_t result,
                               const char* fn, const void* args, std::uint64_t nargs);

FactoryFn g_orig_factory = nullptr;
std::atomic<void*> g_menu{nullptr};
std::uintptr_t g_base = 0;

void* detour_factory() {
    void* menu = g_orig_factory ? g_orig_factory() : nullptr;
    g_menu.store(menu, std::memory_order_release);
    FW_DBG("[cmenu] ContainerMenu built at %p", menu);
    return menu;
}

// POD-only, SEH-caged: the UI says a ContainerMenu is open, and `menu` still
// carries ContainerMenu's vtable.
bool menu_live(void* menu) {
    __try {
        void* ui = *reinterpret_cast<void**>(g_base + offsets::UI_SINGLETON_RVA);
        if (!ui) return false;
        const void* name =
            reinterpret_cast<MenuNameFn>(g_base + offsets::CONTAINER_MENU_NAME_RVA)();
        if (!name) return false;
        if (!reinterpret_cast<MenuIsOpenFn>(g_base + offsets::UI_MENU_IS_OPEN_RVA)(ui, name)) {
            return false;
        }
        const auto vt = *reinterpret_cast<const std::uintptr_t*>(menu);
        return vt == g_base + offsets::CONTAINER_MENU_VTABLE_RVA;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// The handle the menu shows against the handle of `refr`. 0 = could not read.
int menu_shows(void* menu, void* refr) {
    __try {
        const std::uint32_t shown = *reinterpret_cast<const std::uint32_t*>(
            static_cast<const std::uint8_t*>(menu) + offsets::CMENU_CONTAINER_HANDLE_OFF);
        std::uint32_t mine = 0;
        reinterpret_cast<GetHandleFn>(g_base + offsets::REFR_GET_HANDLE_RVA)(refr, &mine);
        return (mine != 0 && shown == mine) ? 1 : -1;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

bool call_update_list(void* menu, std::uint8_t side) {
    __try {
        auto** vt = *reinterpret_cast<void***>(menu);
        reinterpret_cast<UpdateListFn>(vt[offsets::CMENU_VT_UPDATE_LIST_SLOT])(menu, side);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// What the engine does after its own UpdateList pair: tells the Scaleform
// side to redraw. Without it the arrays change and the rows do not.
bool call_invalidate_lists(void* menu) {
    __try {
        const auto* bytes = static_cast<const std::uint8_t*>(menu);
        void* obj   = *reinterpret_cast<void* const*>(bytes + offsets::CMENU_GFX_OBJECT_OFF);
        void* movie = *reinterpret_cast<void* const*>(bytes + offsets::CMENU_GFX_MOVIE_OFF);
        if (!obj) return false;
        reinterpret_cast<GfxInvokeFn>(g_base + offsets::GFX_INVOKE_RVA)(
            obj, movie, std::uint64_t{0}, "InvalidateLists", nullptr, std::uint64_t{0});
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

} // namespace

bool refresh_container_menu(void* container_refr, bool container_side,
                            bool player_side)
{
    if (!container_refr || (!container_side && !player_side)) return false;
    void* menu = g_menu.load(std::memory_order_acquire);
    if (!menu || g_base == 0) return false;
    const auto mt = fw::dispatch::main_thread_id();
    if (mt != 0 && GetCurrentThreadId() != mt) {
        FW_WRN("[cmenu] rebuild asked from thread %lu, not the main thread: skipped",
               static_cast<unsigned long>(GetCurrentThreadId()));
        return false;
    }
    if (!menu_live(menu)) return false;
    const int shows = menu_shows(menu, container_refr);
    if (shows != 1) {
        FW_DBG("[cmenu] a ContainerMenu is open but not on %p (%s)", container_refr,
               shows == 0 ? "handle unreadable" : "another container");
        return false;
    }
    bool ok = true;
    if (container_side) ok = call_update_list(menu, 1) && ok;
    if (player_side)    ok = call_update_list(menu, 0) && ok;
    const bool drawn = ok && call_invalidate_lists(menu);
    if (ok && drawn) {
        FW_LOG("[cmenu] lists rebuilt and redrawn for the open container %p "
               "(container=%d player=%d)",
               container_refr, int(container_side), int(player_side));
    } else if (ok) {
        FW_WRN("[cmenu] lists rebuilt for %p but InvalidateLists failed: rows may "
               "stay stale until the menu is reopened", container_refr);
    } else {
        FW_ERR("[cmenu] SEH inside ContainerMenu::UpdateList for %p", container_refr);
    }
    return ok;
}

bool install_container_menu_hook(std::uintptr_t module_base) {
    g_base = module_base;
    const auto target_ea = module_base + offsets::CONTAINER_MENU_FACTORY_RVA;
    const bool ok = install(
        reinterpret_cast<void*>(target_ea),
        reinterpret_cast<void*>(&detour_factory),
        reinterpret_cast<void**>(&g_orig_factory));
    if (ok) {
        FW_LOG("[cmenu] hook installed at 0x%llX (ContainerMenu factory = "
               "sub_1410412B0 @ RVA 0x%lX)",
               static_cast<unsigned long long>(target_ea),
               static_cast<unsigned long>(offsets::CONTAINER_MENU_FACTORY_RVA));
    } else {
        FW_ERR("[cmenu] hook install FAILED at 0x%llX",
               static_cast<unsigned long long>(target_ea));
    }
    return ok;
}

} // namespace fw::hooks
