"""Decompile SetPosition native + follow any forwarder helper."""
import ida_auto
import ida_funcs
import ida_hexrays
import ida_nalt
import ida_pro

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\setposition_decomp.txt"

# From setposition_dump.txt: lea r9, sub_14115D9E0 (the SetPosition native)
TARGETS = [
    ("SetPosition native",    0x115D9E0),
]


def log(msg, fh):
    print(msg); fh.write(msg + "\n"); fh.flush()


def decompile(rva, img, fh, seen, depth=0):
    if depth > 3: return
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
        log(src, fh)
        # Follow simple forwarders
        import re
        body = " ".join(src.split())
        m = re.search(r"return\s+sub_([0-9A-Fa-f]{6,16})\s*\(", body)
        if m:
            fwd = int(m.group(1), 16)
            log(f"\n---- follows forwarder -> 0x{fwd:X} (RVA 0x{fwd - img:X}) ----\n", fh)
            decompile(fwd - img, img, fh, seen, depth + 1)
    except Exception as e:
        log(f"  <decomp err: {e}>", fh)


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{img:X}", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] no hexrays", fh); fh.close(); ida_pro.qexit(2)

    for label, rva in TARGETS:
        log(f"\n==== {label} @ RVA 0x{rva:X} ====", fh)
        decompile(rva, img, fh, set())

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
