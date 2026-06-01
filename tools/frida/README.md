# Frida combat-brain trace

Dynamic instrumentation of Fallout 4's combat AI pipeline. Use this when
the static DLL hooks (fw_native/src/hooks/*) aren't telling us enough —
or when we need to capture a crash with full register/stack context
without WinDbg.

The script attaches to a running `Fallout4.exe` and hooks ~20 of the
combat-AI functions documented in `re/AI_pipeline/MASTER.md`:

- Per-frame entry: `Actor::Update_PerFrame`
- Orchestrator: `Actor::vt[255]` (`sub_140CCFDF0`)
- CombatController: `Update`, `AddTarget`, `RankTargets`, `StateMachine::Tick`
- Validators: `HostilityCore`, `IsHostile`, `CellLoaded`, `EnterCombat`,
  `AIProcess valid`, alive-counter, post-pick gate
- Fire pipeline: `GunFire::DecideAndFire`, `DispatchAttackAction`,
  `WeaponFireHandler`, `Projectile::Launch`
- Crash sites: `sub_140DEF780` (Build 43b event dispatch),
  `sub_1402F9860` (Build 44 form reader)
- Hit applier: `sub_140CD2780`

On every hook, the script logs the args (with form_id resolved), checks
if the ghost is involved, and dumps relevant struct fields
(CombatController +0x110 alive count, AIProcess +0x6C target handle,
etc.).

On AV / EXEC fault / other exception: dumps RIP/RSP/RBP/all GPRs +
16 qwords from the stack + Frida backtrace. The game then crashes
normally (we don't swallow exceptions).

## Prerequisites

```
pip install frida-tools
```

Frida 16.x or later. No need for frida-server — desktop Windows
attaches directly.

## Usage

1. Start Fallout 4 normally via `launcher\start_A.bat` or `start_B.bat`.
2. Wait until you're in-game (save loaded, character in cell).
3. Open a separate cmd and run:
   ```
   tools\frida\run_trace.bat
   ```
   This auto-attaches to `Fallout4.exe` by name and writes to
   `tools\frida\trace_YYYYMMDD_HHMMSS.log`.
4. Do your test scenario (teleport, combat, the thing that crashes).
5. When done or after crash, Ctrl-C in the Frida console.
6. Send the log file content for analysis.

## Verbosity controls

Edit `combat_brain_trace.js` top section `LEVELS = { ... }`:

- `ORCHESTRATOR`, `COMBAT_CTRL_UPDATE`, etc.: per-function on/off
- `GHOST_FILTER_ONLY`: if true, only logs events where ghost is involved
- `STATE_DUMP_INTERVAL_MS`: how often to print controller state

For a noisy initial pass, keep defaults. If output is overwhelming,
flip `GHOST_FILTER_ONLY = true` to filter to ghost-related calls only.

## Two-client trace

Run separate Frida sessions on each Fallout4.exe (Side A + Side B).
The script uses `Module.findBaseAddress("Fallout4.exe")` so it works
on any instance. Each session writes to its own timestamped log.

To attach by PID (when name is ambiguous):
```
frida -p <pid> -l combat_brain_trace.js -o trace.log
```

Get PIDs:
```
frida-ps | findstr Fallout4
```

## What to look at in the trace

After running a session where raiders go idle:

1. Search for `[EnterCombat]` lines — when does the raider's brain
   actually enter combat with the ghost? How many times?
2. Search for `[ctrl-upd-leave alive>0]` — when is alive count > 0
   for a controller? How does it transition?
3. Search for `[host-ret]` with `← GHOST` flag — what rank does
   HostilityCore return for raider↔ghost pairs?
4. Search for `[WFH-ret]` non-1 — when does WeaponFireHandler return
   anything other than success?
5. Search for `[!!]` — exception traces.

The periodic state dump (`[periodic]` lines) every 1 second shows
the current state of all controllers we've ever seen — useful to
spot when alive count drops back to 0 (raider transitions to lost-
target).
