# FO4_Wrld

Fallout 4 1.11.191 next-gen — multiplayer mod (FoM-lite framework).
Solo-dev, evening project. Target: 10-player persistent-world survival MMO.

> **Status (2026-04-25):** ghost player body visible + textured + position/yaw
> tracked. T-pose static. Animation pending M8 RE. Full design vision in
> `fallout_multiplayer_project_brainstorm.md`.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                     Python Server (asyncio UDP)                   │
│  authoritative state · identity-keyed (base, cell) · validator    │
│  reliable channel (SACK + retransmit) · JSON snapshot persistence │
└─────────────────────────┬────────────────────────────────────────┘
                          │ binary protocol v4 (44B POS_BCAST)
            ┌─────────────┼─────────────┐
            │             │             │
       ┌────▼─────┐  ┌────▼─────┐  ┌────▼─────┐
       │ Client A │  │ Client B │  │   ...    │
       │  FO4 +   │  │  FO4 +   │  │  Up to   │
       │ dxgi.dll │  │ dxgi.dll │  │  10      │
       │  proxy   │  │  proxy   │  │  peers   │
       └──────────┘  └──────────┘  └──────────┘
       Each client:
       - 1 LOCAL player (vanilla FO4 controls, full anim)
       - N GHOST bodies (1 per remote peer, native scene graph)
```

## Repository layout

| Path | Purpose |
|------|---------|
| `fw_native/` | C++ native client (dxgi.dll proxy + MinHook + scene graph injection) |
| `fw_native/src/native/` | Strada B native injection (NIF loader, scene graph, ghost body) |
| `fw_native/src/hooks/` | MinHook detours (kill, container, pos poll, main_menu, worldstate) |
| `fw_native/src/net/` | C++ port of Python protocol (byte-identical via static_assert) |
| `fw_native/docs/` | Internal docs + tools list |
| `launcher/` | Python orchestrator (FO4 INI mgmt, side A/B startup, fw_config.ini) |
| `fw_launcher/` | C++ launcher wrapper (`FoM.exe`) |
| `net/` | Python server (asyncio UDP, validator, persistence, snapshot v3) |
| `frida/` | Frida JS scripts + Python attach helpers (RE / live tracing) |
| `re/` | Reverse-engineering dossiers + IDA Python scripts |

## Major milestones

| Milestone | Status |
|-----------|--------|
| **B0** Networking + native client port | ✅ done — 196+ pytest, byte-identical protocol |
| **B1** Container pre-mutation block | ✅ done — concurrent TAKE dup race closed |
| **B2** Launcher (`FoM.exe`) | ✅ done — drop-in for `start_A.bat`/`start_B.bat` |
| **B3** Auto-load save (delayed LoadGame via WndProc subclass) | ✅ done |
| **B4** Worldstate sync (GlobalVar + QuestStage) | 🟡 GlobalVar shipped; QuestStage RE done, apply pending wire |
| **M5–M6** Strada B ghost body (NIF native injection + textures) | ✅ done — body + head + hands textured, scene graph attached |
| **M7** Ghost animations | 🟫 blocked — needs M8 |
| **M8** Full player creation pipeline RE + replicate | 🚧 IN PROGRESS — 3-4 weeks RE estimated |
| **B5** D3D11 custom render | 🗿 not needed — Strada B native injection replaced |
| **B6** Sync expansion (cell cleared, workshop, faction rep) | ⏳ |
| **B7** Rust server port | ⏳ |

## Major RE achievements

- **Single-instance bypass** (1-byte binary patch @ RVA `0xC2FB62`) — runs 2 FO4
  instances simultaneously on same machine. Killer of Fallout Together + F4MP.
- **`apply_materials` walker discovery** (`sub_140255BA0`) — the missing step
  for `.bgsm` material resolution after standalone NIF load. Documented in
  `re/stradaB_pink_body_solution.txt`.
- **NIF loader public API** (`sub_1417B3E90`) — bypasses the broken cache
  wrapper that hangs with naive args.
- **Scene graph integration** — depth occlusion, lighting, shadows free via
  `BSFadeNode` attachment to `ShadowSceneNode`.

## How to build (developer notes)

Required:
- Visual Studio Build Tools 2022 (`E:\BuildTools\` assumed by `build.bat`)
- CMake ≥ 3.25
- Ninja (bundled with VS Build Tools)
- Python 3.12 (for launcher + server)
- Frida 17+ (for live RE traces)

Build native DLL:
```
cd fw_native
build.bat       # produces build/dxgi.dll
deploy.bat      # copies to Side A + Side B game dirs
```

Run multiplayer (after deploy):
```
launcher/start_A.bat
launcher/start_B.bat
```

## Reverse-engineering target

Fallout4.exe **1.11.191 next-gen** (December 2025).
ImageBase 0x140000000 (no ASLR in practice).
IDA Pro 9.3 used for static decomp; cached DB at `re/Fallout4.exe.i64` (NOT
committed — proprietary format + size). Regenerate locally from your own
copy of Fallout4.exe.

## License

Personal mod project. Not distributed. Requires owned copy of Fallout 4.
No Bethesda IP committed to this repo (no game binaries, no BA2 contents,
no decomp dumps — only our own analysis dossiers).

## Notes

- Brainstorm + design doc: `fallout_multiplayer_project_brainstorm.md`
- Solution dossiers: `re/stradaB_*.txt` (production-grade RE writeups)
- Tools list: `fw_native/docs/tools-da-usare.md`
