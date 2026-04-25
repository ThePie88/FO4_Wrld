"""Identify what dispatches sub_140CA7D20 inside sub_140C4CE00.

- The xref site is 0x140C4FE69 inside sub_140C4CE00.  We need to
  find the preceding switch case / event-ID constant.
- Dump 200 bytes of disassembly context around 0x140C4FE69.
- Find what exported/named function ultimately leads to it
  (Activate handler? PlayerInputHandler?).
- Also dump sub_140C4FE69 (if it's its own function)
- Look at all vftable xrefs to sub_140CA7D20 across the binary.
- Also check if sub_140CA7D20 name is a thunk — dump 50 bytes after
  its first byte.

Output: re/world_pickup_report3.txt
"""
import ida_auto, ida_funcs, ida_hexrays, ida_nalt, ida_pro
import ida_xref, ida_name, ida_bytes, idautils, idc

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\world_pickup_report3.txt"

TARGET_CA7D20 = 0xCA7D20
CALL_SITE     = 0xC4FE69   # inside sub_140C4CE00
PUMP_START    = 0xC4CE00


def log(msg, fh):
    print(msg); fh.write(msg + "\n"); fh.flush()


def section(title, fh):
    log("\n" + "=" * 78, fh)
    log(f"== {title}", fh)
    log("=" * 78, fh)


def get_name(ea):
    n = ida_name.get_ea_name(ea)
    return n if n else f"sub_{ea:X}"


def disasm_context(ea, before=60, after=20, fh=None):
    # Walk backwards N instructions then forwards M instructions
    lines = []
    cur = ea
    for _ in range(before):
        prev = idc.prev_head(cur)
        if prev == idc.BADADDR:
            break
        cur = prev
    start = cur
    cur = start
    cnt = 0
    while cnt < before + after:
        mnem = idc.print_insn_mnem(cur)
        disp = idc.generate_disasm_line(cur, 0)
        lines.append(f"  0x{cur:X}  {disp}")
        nxt = idc.next_head(cur)
        if nxt == idc.BADADDR:
            break
        cur = nxt
        cnt += 1
    return "\n".join(lines)


def scan_cases_in_pump(pump_start_ea, img, fh):
    """In sub_140C4CE00, find all `cmp .., <imm>` preceding any call. Write
    the surrounding 6-line window for each. Focus on the CA7D20 neighborhood."""
    section("Disasm context around 0x140C4FE69 (call to sub_140CA7D20)", fh)
    ctx = disasm_context(0x140000000 + CALL_SITE, before=30, after=4)
    log(ctx, fh)


def decomp(ea, max_len=4000):
    fn = ida_funcs.get_func(ea)
    if fn is None:
        return f"<no func at 0x{ea:X}>"
    try:
        cf = ida_hexrays.decompile(fn.start_ea)
        if cf is None:
            return "<decomp failed>"
        s = str(cf)
        return s if len(s) <= max_len else s[:max_len] + "\n...<truncated>"
    except Exception as e:
        return f"<decomp err: {e}>"


def decomp_partial(ea, start_line_hint, window=120, fh=None):
    """Decompile and pluck the window around the hint."""
    fn = ida_funcs.get_func(ea)
    if fn is None:
        return f"<no func at 0x{ea:X}>"
    try:
        cf = ida_hexrays.decompile(fn.start_ea)
        if cf is None:
            return "<decomp failed>"
        s = str(cf)
    except Exception as e:
        return f"<decomp err: {e}>"
    # Find the hint line
    idx = s.find(start_line_hint)
    if idx < 0:
        return f"<hint '{start_line_hint}' not found>  total {len(s)} chars"
    before = max(0, idx - window * 40)
    after = min(len(s), idx + window * 40)
    return s[before:after]


def hex_dump(ea, count, fh):
    line = []
    for i in range(count):
        b = ida_bytes.get_byte(ea + i)
        line.append(f"{b:02X}")
    return " ".join(line)


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{img:X}", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] no hexrays plugin available", fh)
        fh.close(); ida_pro.qexit(2)

    # Disasm context around call site
    scan_cases_in_pump(img + PUMP_START, img, fh)

    # Hex dump first 32 bytes of sub_140CA7D20 (check for thunk)
    section("Hex dump first 32 bytes of sub_140CA7D20 (to detect thunk)", fh)
    hb = hex_dump(img + TARGET_CA7D20, 32, fh)
    log(hb, fh)
    section("Prologue disasm of sub_140CA7D20 (first 20 insns)", fh)
    cur = img + TARGET_CA7D20
    cnt = 0
    while cnt < 20:
        disp = idc.generate_disasm_line(cur, 0)
        log(f"  0x{cur:X}  {disp}", fh)
        cur = idc.next_head(cur)
        if cur == idc.BADADDR:
            break
        cnt += 1

    # Find partial decomp of sub_140C4CE00 around the CA7D20 call
    section("Partial Hex-Rays of sub_140C4CE00 around sub_CA7D20 call", fh)
    d = decomp_partial(img + PUMP_START, "sub_140CA7D20", window=60, fh=fh)
    log(d, fh)

    # Check if CA7D20 is referenced in any .rdata segment (vtable?)
    section("All xrefs to sub_140CA7D20 across all segments", fh)
    for x in idautils.XrefsTo(img + TARGET_CA7D20, 0):
        seg = idc.get_segm_name(x.frm)
        log(f"  type={x.type}  from=0x{x.frm:X}  seg={seg}  name={get_name(x.frm)}", fh)

    # Probe the second singleton qword_1431E2D50
    section("qword_1431E2D50 — what is it (find string/label references)", fh)
    ea = img + 0x31E2D50
    # Read the name + any xrefs
    log(f"  name at {ea:X} = {get_name(ea)}", fh)
    refs = list(idautils.XrefsTo(ea, 0))
    log(f"  total xrefs to this qword: {len(refs)}", fh)
    seen_fns = set()
    for x in refs:
        fn = ida_funcs.get_func(x.frm)
        if fn is None:
            continue
        seen_fns.add(fn.start_ea)
    log(f"  unique enclosing funcs: {len(seen_fns)}", fh)
    for fea in sorted(list(seen_fns))[:25]:
        log(f"    {get_name(fea)}  RVA=0x{fea - img:X}", fh)

    # Also check sub_140C4CE00 signature and look where event-ID 0x2?? gets
    # routed to CA7D20. Dump more of C4CE00.
    section("Full Hex-Rays of sub_140C4CE00 (up to 16000 chars)", fh)
    d = decomp(img + PUMP_START, 16000)
    log(d, fh)

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
