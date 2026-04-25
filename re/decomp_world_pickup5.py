"""Trace the producer of event-133 in main-thread pump.

sub_140C4CE00 case 133 dispatches sub_140CA7D20. The event is carried in
a 56-byte (or so) blob whose first byte = event_id; v5 (second ptr)
holds item pointer at +16, flags at +24 and +32.

Find whoever writes 133 (0x85) as a byte to this blob and then pushes
to the main-thread queue.

Alternative strategy: since sub_140C4CE00 is the main-thread pump fed by
queue qword_1432F46F8, search for all instances of writing 0x85 into
the queue message header across the entire binary.

Approach:
 - Scan all text segment for 'mov byte ptr ..., 85h' immediate instructions
   and 'mov dword ptr ..., 85' (dword stores to msg header).
 - For each hit, show its enclosing function and 10 lines of disasm.

Output: re/world_pickup_report5.txt
"""
import ida_auto, ida_funcs, ida_hexrays, ida_nalt, ida_pro
import ida_xref, ida_name, ida_bytes, idautils, idc, ida_segment

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\world_pickup_report5.txt"


def log(msg, fh):
    print(msg); fh.write(msg + "\n"); fh.flush()


def section(title, fh):
    log("\n" + "=" * 78, fh)
    log(f"== {title}", fh)
    log("=" * 78, fh)


def get_name(ea):
    n = ida_name.get_ea_name(ea)
    return n if n else f"sub_{ea:X}"


def decomp(ea, max_len=3500):
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


def iter_text_instructions(fh):
    text_seg = ida_segment.get_segm_by_name(".text")
    if not text_seg:
        log("  .text segment not found", fh)
        return
    ea = text_seg.start_ea
    end = text_seg.end_ea
    log(f"  Scanning .text 0x{ea:X}..0x{end:X} ({end-ea:,} bytes)", fh)
    while ea < end:
        yield ea
        nxt = idc.next_head(ea)
        if nxt == idc.BADADDR or nxt <= ea:
            break
        ea = nxt


def search_imm_stores(img, fh, imm_val):
    """Find `mov ..., imm_val` where imm_val can be 1-byte, 4-byte, etc."""
    section(f"Search .text for 'mov <mem>, imm=0x{imm_val:X}' (event-ID writer candidates)", fh)
    hits = []
    count = 0
    for ea in iter_text_instructions(fh):
        count += 1
        if count > 5_000_000:  # sanity cap
            break
        mnem = idc.print_insn_mnem(ea).lower()
        if mnem != "mov":
            continue
        # Check src is immediate with value
        op1_type = idc.get_operand_type(ea, 1)
        if op1_type != idc.o_imm:
            continue
        v = idc.get_operand_value(ea, 1)
        if v != imm_val:
            continue
        # Check dst type — memory or register (we want memory stores)
        op0_type = idc.get_operand_type(ea, 0)
        if op0_type not in (idc.o_mem, idc.o_displ, idc.o_phrase):
            continue
        # capture
        hits.append(ea)
    log(f"  Total hits: {len(hits)} (scanned {count:,} insns)", fh)
    # Group by enclosing func
    per_fn = {}
    for ea in hits:
        fn = ida_funcs.get_func(ea)
        key = fn.start_ea if fn else 0
        per_fn.setdefault(key, []).append(ea)
    log(f"  Unique enclosing functions: {len(per_fn)}", fh)
    # Print up to 30 hits
    for fea, eas in sorted(per_fn.items())[:30]:
        rva = fea - img if fea else 0
        log(f"\n-- in {get_name(fea)}  RVA=0x{rva:X}  ({len(eas)} write-site(s))", fh)
        for ea in eas[:3]:
            # Print 5 lines around the store
            cur = ea
            for _ in range(2):
                p = idc.prev_head(cur)
                if p == idc.BADADDR:
                    break
                cur = p
            for _ in range(6):
                disp = idc.generate_disasm_line(cur, 0)
                marker = " <==" if cur == ea else ""
                log(f"    0x{cur:X}  {disp}{marker}", fh)
                nxt = idc.next_head(cur)
                if nxt == idc.BADADDR:
                    break
                cur = nxt
    return per_fn


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{img:X}", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] no hexrays plugin available", fh)
        fh.close(); ida_pro.qexit(2)

    # Find immediate-0x85 byte/dword stores in .text
    per_fn = search_imm_stores(img, fh, 0x85)

    # For the top 10 most-plausible candidates (named), decompile each
    section("Decompilations of top candidate producer functions", fh)
    candidates = list(per_fn.items())[:12]
    for fea, eas in candidates:
        if fea == 0:
            continue
        rva = fea - img
        log(f"\n=== {get_name(fea)}  RVA=0x{rva:X} ===", fh)
        log(decomp(fea, 4500), fh)

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
