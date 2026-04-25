"""B3.b v3 RE pass #2 — decode the ObScriptCommand table entry for LoadGame.

From pass #1 we know:
  - "LoadGame" string @ RVA 0x24BB210
  - Data xref holding the pointer: 0x142EF1680 (this is the longName slot
    of the LoadGame struct entry in .rdata)
  - Adjacent commands: CenterOnCell @ 0x142EF06E0, QuitGame @ 0x142EF2300
  - Gaps suggest struct stride of ~0x50 bytes (classic ObScriptCommand
    layout)

This script:
  1. Decodes the LoadGame entry assuming stride 0x50 and the conventional
     Bethesda ObScriptCommand layout (longName +0, shortName +8, opcode
     +0x10, help +0x18, params +0x28, exec_fn +0x30, ...).
  2. Dumps 6 neighbors on each side to verify we're inside the right table.
  3. Decompiles the exec_fn candidate.

Output: re/console_table_report.txt
"""
import ida_auto, ida_funcs, ida_hexrays, ida_nalt, idc, idautils, ida_pro, ida_bytes

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\console_table_report.txt"

LOAD_GAME_SLOT = 0x142EF1680   # start of the LoadGame entry (longName slot)
STRIDE = 0x50                   # typical ObScriptCommand size

# Conventional field offsets within one entry
OFF_LONG_NAME  = 0x00
OFF_SHORT_NAME = 0x08
OFF_OPCODE     = 0x10
OFF_HELP       = 0x18
OFF_NEEDS_PARENT = 0x20
OFF_NUM_PARAMS = 0x22
OFF_PARAMS     = 0x28
OFF_EXEC_FN    = 0x30
OFF_PARSE_FN   = 0x38
OFF_EVAL_FN    = 0x40


def log(msg, fh):
    print(msg); fh.write(msg + "\n"); fh.flush()


def read_q(ea): return ida_bytes.get_qword(ea)
def read_d(ea): return ida_bytes.get_dword(ea)
def read_w(ea): return ida_bytes.get_word(ea)
def read_b(ea): return ida_bytes.get_byte(ea)


def read_cstr(ea, max_len=200):
    if not ea: return None
    out = []
    for i in range(max_len):
        b = ida_bytes.get_byte(ea + i)
        if b == 0: break
        if 0x20 <= b < 0x7F:
            out.append(chr(b))
        else:
            return None
    return "".join(out) if out else None


def decomp(ea, max_len=5000):
    fn = ida_funcs.get_func(ea)
    if fn is None: return f"<no func at 0x{ea:X}>"
    try:
        cf = ida_hexrays.decompile(fn.start_ea)
        if cf is None: return "<decomp failed>"
        s = str(cf)
        return s if len(s) <= max_len else s[:max_len] + "\n...<truncated>"
    except Exception as e:
        return f"<decomp err: {e}>"


def dump_entry(base_ea, fh, img):
    """Dump one ObScriptCommand entry. Returns dict of parsed fields."""
    long_name  = read_q(base_ea + OFF_LONG_NAME)
    short_name = read_q(base_ea + OFF_SHORT_NAME)
    opcode     = read_d(base_ea + OFF_OPCODE)
    help_ptr   = read_q(base_ea + OFF_HELP)
    num_params = read_w(base_ea + OFF_NUM_PARAMS)
    params     = read_q(base_ea + OFF_PARAMS)
    exec_fn    = read_q(base_ea + OFF_EXEC_FN)
    parse_fn   = read_q(base_ea + OFF_PARSE_FN)
    eval_fn    = read_q(base_ea + OFF_EVAL_FN)

    ln = read_cstr(long_name) if long_name else None
    sn = read_cstr(short_name) if short_name else None
    hp = read_cstr(help_ptr)   if help_ptr   else None

    def rva(p):
        return f"0x{p - img:X}" if p else "0"

    help_preview = ((hp[:50] + "…") if (hp and len(hp) > 50) else (hp or ""))
    log(f"  0x{base_ea:X}: long={ln!r:<22} short={sn!r:<10} op=0x{opcode:X} "
        f"exec_fn=RVA {rva(exec_fn)}  parse_fn=RVA {rva(parse_fn)}  eval_fn=RVA {rva(eval_fn)}  "
        f"help={help_preview!r}", fh)
    return {
        "long_name": ln, "short_name": sn, "opcode": opcode, "help": hp,
        "num_params": num_params, "params": params,
        "exec_fn": exec_fn, "parse_fn": parse_fn, "eval_fn": eval_fn,
    }


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{img:X}", fh)
    log(f"[+] Expected LoadGame entry at 0x{LOAD_GAME_SLOT:X}", fh)
    log(f"[+] Using stride 0x{STRIDE:X}\n", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] no hexrays", fh); fh.close(); ida_pro.qexit(2)

    # Dump the LoadGame entry + 8 neighbors each side to verify the layout.
    log("==== table dump around LoadGame (stride 0x50) ====", fh)
    center_entry = None
    for i in range(-8, 9):
        ea = LOAD_GAME_SLOT + i * STRIDE
        entry = dump_entry(ea, fh, img)
        if i == 0:
            center_entry = entry

    if center_entry is None or not center_entry["long_name"]:
        log("\n[-] FAILED to read LoadGame entry at expected offset", fh)
        log("    try a different stride/offset?", fh)
        fh.close(); ida_pro.qexit(3)

    log(f"\n==== center entry (LoadGame) resolved ====", fh)
    log(f"  long_name = {center_entry['long_name']!r}", fh)
    log(f"  short_name = {center_entry['short_name']!r}", fh)
    log(f"  opcode = 0x{center_entry['opcode']:X}", fh)
    log(f"  help = {center_entry['help']!r}", fh)
    log(f"  exec_fn = 0x{center_entry['exec_fn']:X} (RVA 0x{center_entry['exec_fn'] - img:X})", fh)
    log(f"  parse_fn = 0x{center_entry['parse_fn']:X}", fh)
    log(f"  eval_fn = 0x{center_entry['eval_fn']:X}", fh)

    # Decompile the exec_fn for LoadGame
    if center_entry["exec_fn"]:
        log(f"\n==== exec_fn decomp (LoadGame at RVA 0x{center_entry['exec_fn'] - img:X}) ====", fh)
        log(decomp(center_entry["exec_fn"]), fh)

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
