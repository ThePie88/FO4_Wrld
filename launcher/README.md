# FalloutWorld Launcher

One-click startup for Player A and Player B.

## Quick start (both players same PC)

**Preferred (B2 native launcher):**

1. **Double-click `FoM.exe` in the repo root** — prompts for side (A or B) at the console, then runs the same orchestration as the Python launcher.
2. Or invoke directly: `FoM.exe --side A` / `FoM.exe --side B`.

**Legacy (still works):**

1. **Double-click `start_A.bat`** — opens Steam FO4 via f4se_loader, starts the server, attaches client.
2. Wait for `READY` in the A terminal.
3. **Double-click `start_B.bat`** — opens FO4_b via ColdClient steamless, attaches client. Server already running (A started it).
4. Both terminals show merged logs with `[A]` / `[B]` / `[srv]` prefixes.

`FoM.exe` is a thin native wrapper (built via `fw_launcher/build.bat`) that
locates `python.exe` on PATH and runs `python -m launcher.main --side X`.
All orchestration logic (server mgmt, INI mgmt, fw_config write, PID detect)
stays in the Python launcher — the native exe just gives us a clean
distributable entry point and replaces the .bat files. Full C++ port of
the launcher internals is deferred (B2.full, out of scope for MVP).

## What each launcher does

```
[A / B]
  1. Check if server is up on 127.0.0.1:31337
     - A: if not, auto-start server subprocess (with snapshot persistence)
     - B: assumes A already started server (pass --no-server)
  2. Record existing Fallout4.exe PIDs (baseline)
  3. Spawn the game:
     - A: C:\...\Steam\...\Fallout 4\f4se_loader.exe
     - B: <repo>\FO4_b\steamclient_loader.exe
  4. Poll for NEW Fallout4.exe PID (up to 45s)
  5. Wait 5s grace (engine load)
  6. Spawn network client attached to that PID
  7. Pipe all logs to this terminal
  8. Ctrl+C cleanly stops client (and server on A)
```

## Side-A vs Side-B

| | A | B |
|---|---|---|
| Launcher | Steam `f4se_loader.exe` | FO4_b `steamclient_loader.exe` |
| Start order | First | Second (after A) |
| Auto-starts server | Yes | No (`--no-server`) |
| Peer id | `player_A` | `player_B` |
| Ghost target | `0x1CA7D` (Codsworth) | `0x1CA7D` (Codsworth) |

## Paths

Adjust `launcher/config.py` if your install layout differs:

- `STEAM_FO4_DIR` — canonical Steam FO4 folder
- `FO4B_DIR` — patched/hardlinked FO4 for player B
- `SERVER_HOST` / `SERVER_PORT`
- `DEFAULT_GHOST_MAP` — map remote peer -> local formid to drive as their avatar

## Troubleshooting

- **"launcher exe not found"**: check paths in `config.py`.
- **"Fallout4.exe did not spawn in time"**: game took >45s to boot (first run after update?), increase `FO4_PROCESS_WAIT_S`. For side B: verify Steamless patch + Goldberg config in FO4_b.
- **"server not running"**: start it manually with `python -m net.server.main` or drop `--no-server` flag.
- **Ghost not appearing**: check Codsworth exists in both saves. Run `prid 1CA7D; tcl; setav aggression 0` in both consoles.
