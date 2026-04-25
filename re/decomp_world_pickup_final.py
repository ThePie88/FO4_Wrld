"""Final analysis — identify the actual slot numbers and entry point.

1. The REFR vtable at RVA 0x2564838 is the "actual" TESObjectREFR vtable
   (I was scanning this).
2. IDA auto-names vtables "??_7TESObjectREFR@@6B@" but the caller report
   said slot[0x16] on this vtable is sub_1404F2F70. However, my scan
   of REFR vtable showed slot[0x16] = sub_140C9A400 (0xC9A400).
   This CAN'T both be right on the same vtable.
3. MOST LIKELY: there are MULTIPLE vtables on different ref-subclasses.
   Skyrim convention: a class may have multiple vtables for each virtual
   base (multiple-inheritance). Find ALL vtables named "??_7TESObjectREFR"
   and list their addresses + first few slots.
4. Clarify which vtable is the runtime 0x2564838 we saw in memory.
"""
import ida_auto, ida_funcs, ida_hexrays, ida_nalt, ida_pro
import ida_xref, ida_name, ida_bytes, idautils, idc, ida_segment

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\world_pickup_report_final.txt"
RUNTIME_REFR_VTABLE = 0x2564838
T_PICKUP = 0x500430
T_4F2F70 = 0x4F2F70


def log(msg, fh):
    print(msg); fh.write(msg + "\n"); fh.flush()


def section(title, fh):
    log("\n" + "=" * 78, fh)
    log(f"== {title}", fh)
    log("=" * 78, fh)


def get_name(ea):
    n = ida_name.get_ea_name(ea)
    return n if n else f"sub_{ea:X}"


def decomp(ea, max_len=6000):
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


def find_all_vtables(img, substring, fh):
    section(f"All named symbols containing '{substring}'", fh)
    matches = []
    for ea, name in idautils.Names():
        if substring in name:
            matches.append((ea, name))
    matches.sort()
    log(f"Total: {len(matches)}", fh)
    for ea, name in matches[:80]:
        log(f"  {name} @ 0x{ea:X}  RVA=0x{ea-img:X}", fh)


def dump_slots_at(name_hint, vt_ea, n, fh, img):
    section(f"Vtable {name_hint} @ 0x{vt_ea:X}  RVA=0x{vt_ea-img:X}", fh)
    for i in range(n):
        slot = vt_ea + i * 8
        t = ida_bytes.get_qword(slot)
        sym = get_name(t) if t else "<null>"
        rva = (t - img) if t else 0
        log(f"  slot[0x{i:X}] -> {sym}  RVA=0x{rva:X}", fh)


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{img:X}", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] no hexrays plugin available", fh)
        fh.close(); ida_pro.qexit(2)

    # Find all named vtables for TESObjectREFR
    find_all_vtables(img, "TESObjectREFR", fh)

    # The runtime vtable at 0x2564838 is mapped; list its name
    rt_ea = img + RUNTIME_REFR_VTABLE
    log(f"\nRuntime vtable @ 0x{rt_ea:X}  name={get_name(rt_ea)}", fh)

    # Find the vtable where slot[0x16] = sub_1404F2F70
    section("Search all .rdata qword entries for sub_1404F2F70", fh)
    target = img + T_4F2F70
    seg = ida_segment.get_segm_by_name(".rdata")
    ea = seg.start_ea
    end = seg.end_ea
    ea = (ea + 7) & ~7
    hits = []
    while ea + 8 <= end:
        if ida_bytes.get_qword(ea) == target:
            hits.append(ea)
        ea += 8
    log(f"Total hits: {len(hits)}", fh)
    for h in hits[:30]:
        # Find enclosing vtable
        cur = h
        for back in range(200):
            cur -= 8
            nm = ida_name.get_ea_name(cur)
            if nm and "??_7" in nm:
                slot_idx = (h - cur) // 8
                log(f"  0x{h:X}  => {nm} slot[0x{slot_idx:X}] (vtable @ 0x{cur:X} RVA=0x{cur-img:X})", fh)
                break
        else:
            log(f"  0x{h:X}  => <unknown enclosing vtable>", fh)

    # Now check: is sub_1404F2F70 also in the runtime REFR vtable (at 0x2564838)?
    section("Runtime REFR vtable @ 0x2564838 slots containing sub_1404F2F70", fh)
    for i in range(0, 0x200):
        slot = rt_ea + i * 8
        if ida_bytes.get_qword(slot) == target:
            log(f"  Found at slot[0x{i:X}]", fh)

    # Full decomp 4F2F70 (8000 chars)
    section("Full decomp sub_1404F2F70 (8000 chars)", fh)
    log(decomp(img + T_4F2F70, 8000), fh)

    # sub_140500430 full (already dumped elsewhere but include here for completeness)
    section("Full decomp sub_140500430 (8000 chars)", fh)
    log(decomp(img + T_PICKUP, 8000), fh)

    # Dump runtime REFR vtable slots 0x14..0x18
    dump_slots_at("runtime REFR vtable slots 0x14..0x18", rt_ea, 0x18 + 1, fh, img)

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
