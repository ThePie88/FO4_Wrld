// B3.b: auto-Continue on the main menu.
//
// Hooks the MainMenu Scaleform registrar (sub_140B01290 @ RVA 0xB01290) as
// our "main menu is being constructed" signal, then a background worker
// thread delays N seconds and fires VK_RETURN via SendInput. The game's
// own Scaleform input pipeline processes it as a Continue click — we don't
// call the handler (sub_141073DC0) directly because it TLS-reads from the
// main thread's TEB.
//
// Enabled/disabled + delay come from fw::config::Settings (auto_continue,
// auto_continue_delay_ms). If disabled, install_main_menu_hook is still
// called but returns true without doing anything, so the caller can treat
// it uniformly with other hooks.

#pragma once

#include <cstdint>

namespace fw::config { struct Settings; }

namespace fw::hooks {

// Reads cfg.auto_continue and cfg.auto_continue_delay_ms. Returns true on
// success (or when auto_continue is disabled — no-op).
bool install_main_menu_hook(std::uintptr_t module_base,
                            const fw::config::Settings& cfg);

} // namespace fw::hooks
