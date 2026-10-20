# rva_port — carry the RVAs to a new Fallout4.exe build

Every address in `fw_native/src` was reverse-engineered on 1.11.191. When
Bethesda ships a patch, these scripts find the same functions, globals and
vtables in the new executable and rewrite each moved literal as
`FW_RVA(rva_191, rva_new)` (see `fw_native/src/game_build.h`). The DLL picks
the column for the build it is running in.

Needs `pip install pefile capstone`, both executables, and about ten minutes.

```bash
python tools/rva_port/port.py OLD/Fallout4.exe NEW/Fallout4.exe --out tools/rva_port/rva_map_191_to_240.json
python tools/rva_port/apply.py tools/rva_port/rva_map_191_to_240.json --dry-run   # read report.md
python tools/rva_port/apply.py tools/rva_port/rva_map_191_to_240.json
python tools/rva_port/verify.py OLD/Fallout4.exe NEW/Fallout4.exe              # must print failed: 0
```

The old build comes from Steam without touching your install:
`download_depot 377160 377162 5433405173062582852` in the Steam console
(`steam://open/console`) puts the 1.11.191 executable in
`steamapps/content/app_377160/depot_377162/`.

## How the matching works

| Stage | What it pairs | Evidence |
|---|---|---|
| hash | functions from `.pdata` | instruction bytes identical after zeroing relative branch targets and RIP displacements, unique in both builds |
| callgraph | callees of matched functions | the aligned `call` in both builds |
| gap | unmatched function between two matched ones | same size, same delta as both neighbours |
| leaf | functions with no unwind entry | the aligned calls to them from matched callers |
| data | globals, singletons, tables | the aligned RIP-relative operands that reference them (vote) |
| rtti | vtables | the class name in the complete object locator |
| sig | anything left | 24 masked bytes near the local delta, with every branch target agreeing |

For 1.11.191 → 1.11.240: 214,670 of 217,852 functions paired, 211,693 of
them with identical code (strong evidence the structure layouts did not
change), 486 of 490 literals resolved, the rest are not addresses (form ids,
masks). One thunk needed a manual override, recorded with its evidence in
`overrides_191_to_240.json`.

`apply.py` only touches literals whose line names an address (`*_RVA`,
`VT_*`, `sub_14…`, vtable name tables, the inventory caller ranges);
everything it skipped is listed in `report.md` for review. `verify.py`
re-reads every `FW_RVA` pair from the source and checks it against both
binaries independently of the matcher.

## Adding a third build

Add the build to `kBuilds` in `game_build.cpp` (TimeDateStamp and
SizeOfImage from the PE header), widen `FW_RVA` to three columns, and run
the three scripts against the 1.11.191 executable again.
