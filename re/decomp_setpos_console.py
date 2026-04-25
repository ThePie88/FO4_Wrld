"""Decompile both candidate functions for the SetPos console command
handler to identify which is the exec path that actually moves the REFR."""
import ida_auto
import ida_funcs
import ida_hexrays
import ida_nalt
import ida_pro

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\setpos_console_decomp.txt"

# Two candidates from setpos_direct_report.txt — data+0x30 and +0x38 of
# the console command entry for "SetPos".
TARGETS = [
    ("SetPos data+0x30", 0x5C0F60),
    ("SetPos data+0x38", 0x5B6150),
]


def log(msg, fh):
    print(msg); fh.write(msg + "\n"); fh.flush()


def decompile(rva, img, fh, seen, depth=0, max_len=4000):
    if depth > 2: return
    ea = img + rva
    fn = ida_funcs.get_func(ea)
    if fn is None:
        log(f"  <no func at 0x{ea:X}>", fh); return
    if fn.start_ea in seen:
        log(f"  <already visited 0x{fn.start_ea:X}>", fh); return
    seen.add(fn.start_ea)
    try:
        cf = ida_hexrays.decompile(fn.start_ea)
        if cf is None:
            log("  <decomp failed>", fh); return
        src = str(cf)
        if len(src) > max_len: src = src[:max_len] + "\n...<truncated>"
        log(src, fh)
        # Follow sub_X calls found in body (up to 3 unique)
        import re
        body = " ".join(src.split())
        subs = re.findall(r"sub_([0-9A-Fa-f]{6,16})", body)
        # Also look for helper/inner functions that take float,float,float
        # These are the most interesting as potential "do the move" functions
        for sub in list(dict.fromkeys(subs))[:4]:
            sub_ea = int(sub, 16)
            if sub_ea - img == rva: continue
            if sub_ea in seen: continue
            log(f"\n    ---- follow sub_{sub} (RVA 0x{sub_ea - img:X}) ----", fh)
            decompile(sub_ea - img, img, fh, seen, depth + 1, max_len=2500)
    except Exception as e:
        log(f"  <decomp err: {e}>", fh)


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{img:X}\n", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] no hexrays", fh); fh.close(); ida_pro.qexit(2)

    for label, rva in TARGETS:
        log(f"\n==== {label} @ RVA 0x{rva:X} ====", fh)
        decompile(rva, img, fh, set())

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
