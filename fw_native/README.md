# fw_native — FoM-lite native DLL

Proxy `dinput8.dll` that the Windows loader injects into Fallout 4 at boot.
This directory is **FoM-lite block B0** in the repo's roadmap
(see `memory/project_falloutworld.md`). B0.1 is the skeleton — skeleton
means the DLL loads, logs proof-of-life, and forwards all dinput8 calls
to the real system DLL. No hooks, no network yet. Those arrive in B0.2+.

## Requirements

- **Visual Studio Build Tools 2022** (MSVC v14.3x) at `E:\BuildTools`
- **CMake 3.25+** on PATH
- **Ninja 1.10+** on PATH
- Windows 10/11 x64

## Build

```
build.bat
```

Runs `vcvars64` then CMake + Ninja release build. Output: `build/dinput8.dll`.

For a debug build: `cmake --preset=msvc-debug && cmake --build --preset=msvc-debug`
(you still need vcvars64 sourced).

## Deploy

```
deploy.bat
```

Copies `build/dinput8.dll` to both game directories:

- `C:\Program Files (x86)\Steam\steamapps\common\Fallout 4\` (Side A)
- `..\FO4_b\` (Side B, ColdClient/Steamless install)

If FO4 is running, the copy will fail with "file in use" — close it first.

## Verify B0.1 is working

1. Launch FO4 via the existing `launcher\start_A.bat` (or B)
2. Let the game reach the main menu
3. Open `fw_native.log` in the game directory, expect:
   ```
   --- session start ---
   [HH:MM:SS.mmm] === FoM-lite B0.1 hello ===
   [HH:MM:SS.mmm] pid=XXXX fallout4_base=0x7FFxxxxxxxxxxx
   [HH:MM:SS.mmm] self_dir=C:\Program Files (x86)\Steam\steamapps\common\Fallout 4
   [HH:MM:SS.mmm] B0.1 inert — no hooks, no network. ...
   ```
4. Game behavior must be **identical to vanilla** (no crash, no FPS drop,
   no missing input). We're just loading + forwarding; if that regresses
   anything, the proxy export forwarding has a bug.

## File layout

| File | Role |
|---|---|
| `CMakeLists.txt` + `CMakePresets.json` | Build configuration |
| `build.bat` / `deploy.bat` | Wrapper scripts |
| `dinput8.def` | DLL export table (5 forwarded symbols) |
| `src/dll_main.cpp` | `DllMain` + init thread that logs hello |
| `src/proxy_exports.cpp` | Forwards each dinput8 export to System32 |
| `src/log.{h,cpp}` | Thread-safe append log to `fw_native.log` |

## Next blocks

- **B0.2** — vendor MinHook, add version check against known RVA fingerprint,
  abort hook install if binary is not FO4 1.11.191.
- **B0.3** — port the three Frida hooks (kill, container vt[0x7A], player pos
  tick) to native C++ via MinHook. Parity with Python/Frida client.
- **B0.4** — port `net/protocol.py` (via generator) and `net/channel.py` to
  C++ so the DLL can speak to the existing Python server directly.
- **B0.5** — handle `WORLD_STATE` + `CONTAINER_STATE` bootstrap; apply
  validated disable/enable using the already-RE'd engine calls.
- **B0.6** — live parity test: pull Python+Frida client, run DLL alone,
  verify kill/container/ghost all still work.

## Troubleshooting

**DLL didn't load** (no `fw_native.log`):
- Check the DLL is really at `<game_dir>\dinput8.dll` and is named exactly
  that (case-insensitive but extension must be `.dll`).
- Ensure no other `dinput8.dll` override exists elsewhere (some ENB/mod
  managers drop one).
- A digitally-mismatched DLL won't load if the game is signed-enforced;
  Fallout 4 isn't, so this is unlikely.

**Game crashes on launch**:
- Check `fw_native.log` — if the "real dinput8 missing export" warning
  appears for `DirectInput8Create`, our forwarding is broken.
- Verify `C:\Windows\System32\dinput8.dll` exists (standard Windows file;
  should always be there).

**Build fails with "cl.exe not found"**:
- Make sure `build.bat` successfully sourced `vcvars64.bat`. If your MSVC
  is not at `E:\BuildTools`, edit the `VCVARS=` path at the top.
