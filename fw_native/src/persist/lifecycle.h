// Stage 1 of L5 (2026-09-27) — the save/load lifecycle, owned in ONE place.
//
// The persistence design (RESEARCH_L5.md §5) puts the character in an
// engine checkpoint the server commands and holds, and the world in the
// server. Everything the engine does on its own with the save files works
// against that: the timed autosave, the quicksave key, the pause-menu save,
// the exit saves, the quickload key, and the reload of "the last save this
// process wrote or loaded" five seconds after a death. Every one of those
// funnels through seven engine functions, and MinHook accepts one detour
// per function, so this module is the only owner of all seven. Later stages
// (checkpoint, custody, death policy) add behaviour here; they do not add
// hooks elsewhere.
//
// What stage 1 does with them:
//   - queue (sub_140BFE4C0): the autosave, manual save, quicksave and
//     quickload requests are dropped before they are queued; the death
//     reload (flag 4) and the exit saves pass and are logged.
//   - named save (sub_140BF8E10) and save core (sub_140BF9010): refused
//     without a SaveGrant on the calling thread, with the engine's own
//     "You cannot save right now." event, so no file is ever written and
//     the reload target at mgr+0x60 stays the save loaded at boot.
//   - load request (sub_140BF93B0), load job (sub_140C01E80) and death
//     reload (sub_140BFD3C0): bracketed into the load-in-flight signal the
//     rest of the DLL lacked, and JUDGED. Our boot load and the death
//     reload run; any other load while a world is loaded (the pause-menu
//     Load, the console, a quickload) is refused inside the load job,
//     which is the loader's own "file unreadable" answer: the world and
//     the death-reload target stay as they were. In the main menu a load
//     is let through, since there is no world to protect and the menu
//     expects its loading screen. Found on the first live test: a menu
//     load moved the player and became the next death's reload target.
//   - task processor (sub_140BFE820, once per frame): forces the save
//     settings in memory after the INI files have had their say, and reads
//     the pending flags so anything reaching the processor by a path this
//     module does not know shows up in the log.
//
// Every write is preceded by a check that the memory is what the decomp
// says it is (a Setting object names itself), every read is SEH-caged, and
// the whole module can be switched off from fw_config.ini
// (persist_lifecycle = false), which leaves the engine exactly as vanilla.

#pragma once

#include <cstdint>

namespace fw::config { struct Settings; }

namespace fw::persist {

// Installs the detours. Returns how many of the eight went in (the seven
// save/load functions and the pause menu's message handler, whose Load
// message is ignored while a world is loaded so the menu never hides itself
// for a load that will not run); 0 when the feature is off or nothing could
// be hooked. A partial install is logged per target and left in place: each
// detour is independent and a missing one only widens what stage 1 does
// not cover.
int install_lifecycle(std::uintptr_t module_base, const fw::config::Settings& cfg);
constexpr int LIFECYCLE_DETOURS = 8;

// True while the engine is loading a save: a load request is being pumped
// on the main thread or the load job is running on the loader thread.
// Reads two counters, safe from any thread.
bool load_in_flight() noexcept;

// True from the moment the engine queued an exit save (to the main menu or
// to the desktop) until the next load request: the world is being torn
// down, and the first thing the shutdown nulls is the handle table. Every
// module that resolves handles or walks engine state on its tick stops
// while this is true (measured 2026-09-28: the sweep resolved a handle
// through a nulled table at exit, a first-chance AV inside the engine).
bool exiting() noexcept;

// L5 stage 3c — the death module's fallback: the death reload queued again
// through the engine's own function, past this module's policy. Main
// thread, from the task processor's detour.
void requeue_death_reload(void* save_load_mgr) noexcept;

// How many load requests the engine has made since the DLL started. The
// world-spawn module tells a death stand-down that ended in a reload from
// one that ended in a respawn (stage 3c) by this number.
std::uint64_t loads_requested() noexcept;

// The window close (WM_CLOSE, ALT+F4) is an exit the engine never queues a
// save for: main_menu_hook says so here, after the exit checkpoint, so the
// same modules stand still through that teardown too.
void note_exit() noexcept;

// Marks the load requests made on this thread inside the scope as
// commanded by us (the boot load of engine::load_game_by_name): they run
// whatever the world state. Nestable.
struct CommandedLoadScope {
    CommandedLoadScope();
    ~CommandedLoadScope();
    CommandedLoadScope(const CommandedLoadScope&) = delete;
    CommandedLoadScope& operator=(const CommandedLoadScope&) = delete;
};

// Lets a save through on this thread while it lives. Nothing holds one in
// stage 1: the checkpoint of stage 3 will, from inside the task processor's
// detour. Nestable.
struct SaveGrant {
    SaveGrant();
    ~SaveGrant();
    SaveGrant(const SaveGrant&) = delete;
    SaveGrant& operator=(const SaveGrant&) = delete;
};

struct Stats {
    std::uint64_t queue_calls;
    std::uint64_t queue_dropped;
    std::uint64_t saves_vetoed;
    std::uint64_t saves_granted;
    std::uint64_t loads_requested;
    std::uint64_t loads_refused;
    std::uint64_t menu_loads_ignored;
    std::uint64_t load_jobs;
    std::uint64_t death_reloads;
    std::uint64_t settings_forced;
};
Stats stats() noexcept;

} // namespace fw::persist
