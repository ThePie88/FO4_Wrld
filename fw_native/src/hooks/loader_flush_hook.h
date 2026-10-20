// L5 detour (2026-10-18): the loader flush that waits for the precombined
// geometry of exterior cells. See loader_flush_hook.cpp for the whole story
// (RESEARCH_interior_loads.md sections 8-11).
#pragma once

#include <cstdint>

namespace fw::config { struct Settings; }

namespace fw::hooks {

// Detours sub_1417AF2F0 (the loader flush) and counts sub_140483760 (the
// precombined task's run step). With cfg.loader_flush_owner_spoof the
// loader's owner thread id is the flushing thread's for the duration of a
// flush run off the main thread, so the owner-only steps run there instead
// of waiting for the main thread to win a lock by luck.
bool install_loader_flush_hook(std::uintptr_t module_base, const fw::config::Settings& cfg);

// True while any thread is inside the loader flush (a cell load, a save
// load): the render hook presents without vsync meanwhile, see
// render/present_hook.cpp (2026-10-18, the precombined geometry waits on the
// renderer's resource thread, which waits on every Present).
bool loader_flush_active() noexcept;

} // namespace fw::hooks
