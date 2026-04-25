"""B3.b v3 — find the engine-level LoadGame function.

Goal: bypass the Main Menu entirely. On game start, the DLL will directly
invoke LoadGame("SaveName") so the engine goes straight to loading a save
without ever showing the menu.

Search strategy:
  1. ".fos" (save file extension) — strings used by the save subsystem,
     almost always near the load path.
  2. "LoadGame" string — labels used for logging / Papyrus native.
  3. Papyrus natives: "Load" on the Game script (we know the registrar
     pattern from earlier passes).
  4. Console commands: "coc"/"load"/"loadgame" — the console-command
     dispatcher path is already RE'd (sub_1405C0F60 parser).

Output: re/load_game_report.txt
"""
import ida_auto, ida_funcs, ida_hexrays, ida_nalt, idc, idautils, ida_pro

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\load_game_report.txt"

# Strings of interest. Some are noisy (esp "Load") but the xref list lets us
# filter.
TARGET_STRINGS = [
    ".fos",
    "LoadGame",
    "Load a saved game",
    "load",            # console command
    "coc",             # center on cell (used by test harness, might be
                       #  dispatched near LoadGame)
    "Game.Load",
    "Save",
    "NewGame",
    "StartNewGame",    # useful if we ever want the opposite direction
    # Flags / ini keys near load logic
    "bLoadGame",
    "sStartingSave",
    # Known: "requestLoadGame" is the Scaleform callback (idx 13 in the
    # MainMenu registrar at sub_140B01290). Find its native handler.
    "requestLoadGame",
]


def log(msg, fh):
    print(msg); fh.write(msg + "\n"); fh.flush()


def decomp(ea, max_len=4000):
    fn = ida_funcs.get_func(ea)
    if fn is None: return f"<no func at 0x{ea:X}>"
    try:
        cf = ida_hexrays.decompile(fn.start_ea)
        if cf is None: return "<decomp failed>"
        s = str(cf)
        return s if len(s) <= max_len else s[:max_len] + "\n...<truncated>"
    except Exception as e:
        return f"<decomp err: {e}>"


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{img:X}\n", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] no hexrays", fh); fh.close(); ida_pro.qexit(2)

    strs = list(idautils.Strings())
    name_to_eas: dict[str, list[int]] = {}
    for s in strs:
        sval = str(s)
        if sval in TARGET_STRINGS:
            name_to_eas.setdefault(sval, []).append(s.ea)

    for target in TARGET_STRINGS:
        eas = name_to_eas.get(target, [])
        log(f"\n==== {target!r}  ({len(eas)} occurrence(s))", fh)
        if not eas:
            continue
        # Limit to first 3 string-locations × first 3 xrefs to keep noise down.
        for str_ea in eas[:3]:
            log(f"  string @ 0x{str_ea:X} (RVA 0x{str_ea - img:X})", fh)
            xrefs = list(idautils.XrefsTo(str_ea, 0))
            for x in xrefs[:3]:
                fn = ida_funcs.get_func(x.frm)
                fn_lbl = f"RVA 0x{fn.start_ea - img:X}" if fn else "<no func>"
                log(f"    xref 0x{x.frm:X} in {fn_lbl}", fh)
                if fn:
                    body = decomp(fn.start_ea)
                    # Print if something load-related is in the body
                    lower = body.lower()
                    if any(w in lower for w in (
                        "load", "save", ".fos", "menu",
                    )):
                        log(body, fh)
                        log("    ---", fh)

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
