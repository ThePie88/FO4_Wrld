"""B3.b v3 RE — find the console command table + the `load` command native.

Strategy:
  - Console commands are registered as a static array of structs shaped like
    { const char* name; const char* short; const char* help; ... native_fn; }.
  - A well-known, distinctive console command is "ToggleCollision" (tcl).
    Find the string, look at its xref → data ref → that's the struct
    holding tcl. From there, walk neighbors in the array.
  - Other easy marker strings: "ShowQuestObjectives", "SetPCName",
    "AddItem", "SetGameSetting".
  - Once we find the table, dump it looking for an entry named "Load" or
    "load" — that's our LoadGame dispatch.

Also dump the Papyrus Game-script registrar if we can find it: Papyrus
Game::Load(String) is also a route into the engine loader.

Output: re/console_cmds_report.txt
"""
import ida_auto, ida_funcs, ida_hexrays, ida_nalt, idc, idautils, ida_pro, ida_bytes

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\console_cmds_report.txt"

# Distinctive command names unlikely to collide with unrelated strings.
MARKER_STRINGS = [
    "ToggleCollision",
    "ShowQuestObjectives",
    "SetPCName",
    "SetGameSetting",
    "PlaceAtMe",
    "CenterOnCell",       # long form of coc
    "ShowVars",
    "ShowGlobalValues",
    "ToggleMenus",
    "QuitGame",
    "Save",               # console "save" command (if exists)
    "Load",               # console "load" command
    "LoadGame",
    "Continue",
    # Papyrus Game script hooks
    "GetPlayer",
    "IncrementStat",
    # FO4-specific
    "startquest",
    "completequest",
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


def read_ptr(ea):
    return ida_bytes.get_qword(ea)


def get_string_at(ea, max_len=128):
    """Read a null-terminated ASCII string at ea."""
    out = []
    for i in range(max_len):
        b = ida_bytes.get_byte(ea + i)
        if b == 0: break
        if 32 <= b < 127:
            out.append(chr(b))
        else:
            return None
    return "".join(out) if out else None


def scan_data_xref_neighborhood(str_ea, radius_slots=256, fh=None, img=None):
    """Given a string at str_ea, find its data xref → that's a struct that
    references this string. Walk the array in both directions, decoding
    each struct as { cmd_name_ptr, cmd_short_ptr, ... }.

    This assumes the command-struct entry starts with a char* pointing at
    the command name. Prints table entries where that assumption holds.
    """
    xrefs = list(idautils.XrefsTo(str_ea, 0))
    if not xrefs:
        log(f"    <no xrefs to 0x{str_ea:X}>", fh); return
    for xr in xrefs[:3]:
        log(f"    data-xref from 0x{xr.frm:X}", fh)
        # Find the start of this struct: assume the xref IS the cmd_name_ptr
        # slot, so struct starts here and extends forward. Walk backward and
        # forward scanning for qword-aligned pointers to valid C strings.

        # Determine the struct stride: walk forward from xref.frm in 8-byte
        # steps, look for the next slot that points to a plausible string.
        # The offset between two consecutive name-slot pointers is the stride.
        stride = None
        for stride_test in (0x20, 0x28, 0x30, 0x38, 0x40):
            next_slot = xr.frm + stride_test
            next_ptr = read_ptr(next_slot)
            if next_ptr and get_string_at(next_ptr, 40):
                stride = stride_test
                break
        if stride is None:
            log(f"      <no stride detected at +0x20..0x40>", fh)
            continue
        log(f"      stride detected = 0x{stride:X}", fh)

        # Walk outward. Find boundaries by watching for a name-slot that
        # doesn't point to a valid string.
        def walk(start_ea, step, max_slots):
            ea = start_ea
            for _ in range(max_slots):
                ptr = read_ptr(ea)
                if not ptr: break
                s = get_string_at(ptr, 60)
                if s is None: break
                yield ea, s
                ea += step

        log(f"      --- forward (up to {radius_slots}) ---", fh)
        for ea, s in walk(xr.frm, stride, radius_slots):
            # Also grab the native handler which is typically at a fixed
            # offset inside the struct. Try a few standard offsets.
            handlers = []
            for h_off in (0x10, 0x18, 0x20, 0x28):
                hp = read_ptr(ea + h_off)
                if hp and ida_funcs.get_func(hp):
                    handlers.append((h_off, hp))
            h_str = ", ".join(
                f"+0x{o:X}→0x{h:X}(RVA 0x{h - img:X})" for o, h in handlers
            ) if handlers else "<no handler candidates>"
            log(f"        0x{ea:X}: {s!r:<35}  {h_str}", fh)

        log(f"      --- backward (up to {radius_slots}) ---", fh)
        for ea, s in walk(xr.frm - stride, -stride, radius_slots):
            handlers = []
            for h_off in (0x10, 0x18, 0x20, 0x28):
                hp = read_ptr(ea + h_off)
                if hp and ida_funcs.get_func(hp):
                    handlers.append((h_off, hp))
            h_str = ", ".join(
                f"+0x{o:X}→0x{h:X}(RVA 0x{h - img:X})" for o, h in handlers
            ) if handlers else "<no handler candidates>"
            log(f"        0x{ea:X}: {s!r:<35}  {h_str}", fh)


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
        if sval in MARKER_STRINGS:
            name_to_eas.setdefault(sval, []).append(s.ea)

    for target in MARKER_STRINGS:
        eas = name_to_eas.get(target, [])
        log(f"\n==== {target!r}  ({len(eas)} occurrence(s))", fh)
        for str_ea in eas[:2]:
            log(f"  string @ 0x{str_ea:X} (RVA 0x{str_ea - img:X})", fh)
            scan_data_xref_neighborhood(str_ea, 128, fh, img)

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
