#include "workbench_hook.h"

#include <windows.h>
#include <atomic>
#include <cstdint>

#include "../hook_manager.h"
#include "../log.h"
#include "../offsets.h"
#include "../ref_identity.h"
#include "../native/world_spawn.h"

namespace fw::hooks {

namespace {

constexpr std::uint32_t kPaFrameBase = 0x0002079Eu;   // FURN PowerArmorFrameFurnitureNoCore

// --- PowerArmorModMenu lifetime (the signal world_spawn's poll runs on) ----
// sub_140AF2400: the creator registered for "PowerArmorModMenu"; returns
// the menu object (2128 bytes, PowerArmorModMenu vtable at +0 and +16).
using PaMenuCreateFn  = void* (__fastcall*)();
// sub_140AF2310: PowerArmorModMenu::~PowerArmorModMenu (this, flags).
using PaMenuDestroyFn = void* (__fastcall*)(void* self, char flags);

PaMenuCreateFn  g_orig_pa_menu_create  = nullptr;
PaMenuDestroyFn g_orig_pa_menu_destroy = nullptr;

std::atomic<bool>          g_pa_menu_open{false};
std::atomic<std::uint64_t> g_pa_menu_closed_ms{0};

void* __fastcall detour_pa_menu_create() {
    void* menu = g_orig_pa_menu_create();
    g_pa_menu_open.store(true, std::memory_order_release);
    FW_LOG("[workbench] PowerArmorModMenu opened (menu=%p) -> station poll armed",
           menu);
    return menu;
}

void* __fastcall detour_pa_menu_destroy(void* self, char flags) {
    g_pa_menu_open.store(false, std::memory_order_release);
    g_pa_menu_closed_ms.store(static_cast<std::uint64_t>(GetTickCount64()),
                              std::memory_order_release);
    FW_LOG("[workbench] PowerArmorModMenu closed (menu=%p) -> station poll "
           "runs 3 s more", self);
    return g_orig_pa_menu_destroy(self, flags);
}

// --- ExamineMenu workers (diagnostic: they never fired for the station) --
using ApplyModFn  = double (__fastcall*)(void* owner, std::int64_t a2);
using SetHealthFn = void (__fastcall*)(void* owner, float health);

ApplyModFn  g_orig_apply_mod  = nullptr;
SetHealthFn g_orig_set_health = nullptr;

void report_owner(void* owner, const char* what) {
    if (!owner) {
        FW_LOG("[workbench] %s: owner=null", what);
        return;
    }
    const auto rid = fw::read_ref_identity(owner);
    const bool frame = (rid.base_id == kPaFrameBase && rid.form_id != 0);
    FW_LOG("[workbench] %s: owner fid=0x%08X base=0x%08X%s", what,
           rid.form_id, rid.base_id, frame ? " (PA frame -> report)" : "");
    if (frame) {
        fw::native::world_spawn::report_frame_pieces(owner, rid.form_id);
    }
}

double __fastcall detour_apply_mod(void* owner, std::int64_t a2) {
    const double rc = g_orig_apply_mod(owner, a2);
    report_owner(owner, "ExamineMenu mod applied");
    return rc;
}

void __fastcall detour_set_health(void* owner, float health) {
    g_orig_set_health(owner, health);
    report_owner(owner, "ExamineMenu repair");
}

} // namespace

bool pa_mod_menu_open() noexcept {
    return g_pa_menu_open.load(std::memory_order_acquire);
}

std::uint64_t pa_mod_menu_closed_ms() noexcept {
    return g_pa_menu_closed_ms.load(std::memory_order_acquire);
}

bool install_workbench_hook(std::uintptr_t module_base) {
    const auto create_ea  = module_base + offsets::PA_MOD_MENU_CREATE_RVA;
    const auto destroy_ea = module_base + offsets::PA_MOD_MENU_DESTROY_RVA;
    const auto apply_ea   = module_base + offsets::EXAMINE_MENU_APPLY_MOD_RVA;
    const auto health_ea  = module_base + offsets::EXAMINE_MENU_SET_ITEM_HEALTH_RVA;

    const bool create_ok = install(
        reinterpret_cast<void*>(create_ea),
        reinterpret_cast<void*>(&detour_pa_menu_create),
        reinterpret_cast<void**>(&g_orig_pa_menu_create));
    const bool destroy_ok = install(
        reinterpret_cast<void*>(destroy_ea),
        reinterpret_cast<void*>(&detour_pa_menu_destroy),
        reinterpret_cast<void**>(&g_orig_pa_menu_destroy));
    const bool apply_ok = install(
        reinterpret_cast<void*>(apply_ea),
        reinterpret_cast<void*>(&detour_apply_mod),
        reinterpret_cast<void**>(&g_orig_apply_mod));
    const bool health_ok = install(
        reinterpret_cast<void*>(health_ea),
        reinterpret_cast<void*>(&detour_set_health),
        reinterpret_cast<void**>(&g_orig_set_health));

    const bool ok = create_ok && destroy_ok && apply_ok && health_ok;
    if (ok) {
        FW_LOG("[workbench] hooks installed: pa_menu_create=0x%llX (sub_140AF2400) "
               "pa_menu_destroy=0x%llX (sub_140AF2310) apply_mod=0x%llX "
               "(sub_14098AE30) set_health=0x%llX (sub_14098E400)",
               static_cast<unsigned long long>(create_ea),
               static_cast<unsigned long long>(destroy_ea),
               static_cast<unsigned long long>(apply_ea),
               static_cast<unsigned long long>(health_ea));
    } else {
        FW_ERR("[workbench] hook install FAILED: pa_menu_create=%d "
               "pa_menu_destroy=%d apply_mod=%d set_health=%d",
               int(create_ok), int(destroy_ok), int(apply_ok), int(health_ok));
    }
    return ok;
}

} // namespace fw::hooks
