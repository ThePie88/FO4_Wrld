"""B3 RE — find the Main Menu "Continue" handler.

Goal: locate the function that runs when the user clicks "Continue" on the
main menu, so we can call it directly from the DLL (or from an event hook
at main-menu-ready) to automate the click.

Strategy:
  1. Search for strings: 'MainMenu', 'Continue', 'MainMenuContinue', 'Load',
     'LoadGame', 'ContinueGame'. These are Scaleform/menu identifier names.
  2. For each xref, capture the surrounding function. Decompile a few to
     identify the button-handler dispatch.
  3. Also scan for the save-name 'LoadGame' console command string —
     related path (user types `load FOO` in console). RE'd function gives
     us an alternative auto-load route.

Outputs: re/main_menu_report.txt
"""
import ida_auto
import ida_funcs
import ida_hexrays
import ida_nalt
import idc
import idautils
import ida_pro

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\main_menu_report.txt"

TARGET_STRINGS = [
    # UI/menu identifiers
    "MainMenu",
    "Continue",
    "MainMenuContinue",
    "ContinueGame",
    "NewGame",
    "LoadGame",
    "MainMenuLoadGame",
    "$Continue",
    "$CONTINUE",
    "ContinueLastSave",
    "LastSave",
    # Console command for load
    "load",
    "Load",
    # File name constants
    "Fallout4_Intro.bk2",
    "CreditsMenu.bk2",
]


def log(msg, fh):
    print(msg); fh.write(msg + "\n"); fh.flush()


def decomp(ea, max_len=3500):
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

    # Index strings by value.
    strs = list(idautils.Strings())
    name_to_eas: dict[str, list[int]] = {}
    for s in strs:
        sval = str(s)
        if sval in TARGET_STRINGS:
            name_to_eas.setdefault(sval, []).append(s.ea)

    for target in TARGET_STRINGS:
        eas = name_to_eas.get(target, [])
        if not eas:
            log(f"==== {target!r}  <not found>", fh)
            continue
        log(f"==== {target!r}  ({len(eas)} occurrence(s))", fh)
        # Only look at first 2 string-locations and first 3 xrefs each — keep
        # report readable.
        for str_ea in eas[:2]:
            log(f"  string @ 0x{str_ea:X} (RVA 0x{str_ea - img:X})", fh)
            xrefs = list(idautils.XrefsTo(str_ea, 0))
            for x in xrefs[:3]:
                fn = ida_funcs.get_func(x.frm)
                fn_lbl = f"RVA 0x{fn.start_ea - img:X}" if fn else "<no func>"
                log(f"    xref 0x{x.frm:X} in {fn_lbl}", fh)
                if fn:
                    body = decomp(fn.start_ea)
                    # Only print if body contains something interesting
                    # (otherwise it's mostly noise).
                    lower = body.lower()
                    if any(w in lower for w in ("menu", "save", "load", "continue", "intro")):
                        log(body, fh)
                        log("    ---", fh)

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
