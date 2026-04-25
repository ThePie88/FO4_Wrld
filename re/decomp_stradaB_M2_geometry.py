"""
decomp_stradaB_M2_geometry.py

Strada B — M2.4 geometry dossier analysis.

Goals:
  1. Decode BSVertexDesc packed u64 at BSGeometry+0x150.
     Trace code that reads [BSGeometry+0x150] in render paths.
  2. Disassemble BSDynamicTriShape allocation flow in the two installer
     sites sub_140372CC0 and sub_1406B60C0 — trace how vertex buffers
     are allocated and populated.
  3. Identify the class at BSGeometry+0x140 (BSSkinInstance? BSGeometryData?).
  4. Trace BSGeometry+0x148 (GeometryData) layout.
  5. Find BSGeometry::Upload / render-time mutation points.

Method:
  - idautils.XrefsTo on known RVAs
  - ida_hexrays.decompile for readable code
  - Pattern scans for '+150h' / '+148h' / '+140h' access in BSGeometry
    methods and renderer functions.
"""
import ida_auto
import ida_funcs
import ida_nalt
import ida_hexrays
import ida_pro
import ida_bytes
import ida_segment
import ida_name
import ida_ua
import idautils
import idc

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\stradaB_M2_geometry_raw.txt"


def log(fh, msg):
    print(msg)
    fh.write(msg + "\n")
    fh.flush()


def rva(ea):
    return ea - ida_nalt.get_imagebase()


def decomp_full(ea, fh, label="", max_lines=600):
    log(fh, f"\n-- decomp {label} @ 0x{ea:X} (RVA 0x{rva(ea):X}) --")
    fn = ida_funcs.get_func(ea)
    if not fn:
        log(fh, "  [!] NO FUNC")
        return None
    log(fh, f"  size=0x{fn.end_ea - fn.start_ea:X}")
    try:
        cf = ida_hexrays.decompile(ea)
        if cf:
            t = str(cf)
            lines = t.split("\n")
            if len(lines) > max_lines:
                log(fh, "\n".join(lines[:max_lines]))
                log(fh, f"  ... (truncated, total={len(lines)} lines)")
            else:
                log(fh, t)
            return t
    except Exception as e:
        log(fh, f"  [!] decompile failed: {e}")
    return None


def disasm_dump(ea, fh, label="", insn_count=200):
    log(fh, f"\n-- disasm {label} @ 0x{ea:X} (RVA 0x{rva(ea):X}) --")
    fn = ida_funcs.get_func(ea)
    if not fn:
        log(fh, "  [!] NO FUNC")
        return
    cur = ea
    end = min(fn.end_ea, ea + insn_count * 16)
    i = 0
    while cur < end and i < insn_count:
        dis = idc.generate_disasm_line(cur, 0) or "?"
        log(fh, f"  0x{cur:X}  {dis}")
        cur = idc.next_head(cur, end)
        i += 1
        if cur == idc.BADADDR:
            break


def scan_offset_access(ea, offset_hex, fh, label=""):
    """Scan a function's disasm for '[reg+offset_hex]' access patterns."""
    log(fh, f"\n-- scan for [reg+0x{offset_hex:X}] in {label} @ 0x{ea:X} --")
    fn = ida_funcs.get_func(ea)
    if not fn:
        log(fh, "  [!] NO FUNC")
        return []
    cur = fn.start_ea
    end = fn.end_ea
    hits = []
    off_str_l = f"+{offset_hex:x}h"
    off_str_u = f"+{offset_hex:X}H"
    off_str_alt = f"+0{offset_hex:x}h"
    while cur < end:
        dis = idc.generate_disasm_line(cur, 0) or ""
        dl = dis.lower()
        if off_str_l in dl or f"+{offset_hex:x}]" in dl:
            log(fh, f"  0x{cur:X}  {dis}")
            hits.append(cur)
        cur = idc.next_head(cur, end)
        if cur == idc.BADADDR:
            break
    return hits


def find_offset_in_binary(offset_u32, fh, label="", limit=40):
    """Scan the entire code segment for `[reg+offset]` access. Slow but
    useful. Limits hits. Returns list of (ea, func_ea)."""
    log(fh, f"\n== Scanning code segments for +0x{offset_u32:X} access (limit {limit}) — {label} ==")
    hits = []
    seg = ida_segment.get_first_seg()
    while seg:
        if (seg.perm & ida_segment.SEGPERM_EXEC) == 0:
            seg = ida_segment.get_next_seg(seg.start_ea)
            continue
        cur = seg.start_ea
        end = seg.end_ea
        # Fast path: we use a pattern on displacement. IDA encodes
        # [reg+disp32] as a specific byte pattern, but easier to just
        # search for the disasm text. We'll sample every head.
        while cur < end and len(hits) < limit:
            # IDA disasm text-based scan — slow. Limit to heads with op1 or op2
            # referencing memory with displacement == offset_u32.
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, cur):
                for i in range(2):
                    op = insn.ops[i]
                    if op.type in (ida_ua.o_displ, ida_ua.o_mem):
                        # o_displ: displacement
                        if op.addr == offset_u32 or (hasattr(op, 'value') and op.value == offset_u32):
                            dis = idc.generate_disasm_line(cur, 0) or ""
                            fn = ida_funcs.get_func(cur)
                            fn_ea = fn.start_ea if fn else 0
                            log(fh, f"  0x{cur:X}  in RVA 0x{rva(fn_ea):X}  {dis}")
                            hits.append((cur, fn_ea))
                            break
                cur = cur + insn.size
            else:
                cur = idc.next_head(cur, end)
                if cur == idc.BADADDR:
                    break
        seg = ida_segment.get_next_seg(seg.start_ea)
    log(fh, f"  [total hits] {len(hits)}")
    return hits


def find_fn_containing(ea):
    fn = ida_funcs.get_func(ea)
    return fn.start_ea if fn else 0


def xrefs_to(ea, fh, label, limit=60):
    log(fh, f"\n== xrefs to {label} @ 0x{ea:X} (RVA 0x{rva(ea):X}) ==")
    results = []
    for x in idautils.XrefsTo(ea, 0):
        fn = ida_funcs.get_func(x.frm)
        fn_ea = fn.start_ea if fn else 0
        fname = ida_funcs.get_func_name(x.frm) or "?"
        log(fh, f"  0x{x.frm:X} in {fname} (fn 0x{fn_ea:X} RVA 0x{rva(fn_ea):X}) type={x.type}")
        results.append((x.frm, fn_ea))
        if len(results) >= limit:
            break
    return results


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    log(fh, "==== Strada B M2.4 — GEOMETRY dossier analysis ====")
    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()
    IMG = ida_nalt.get_imagebase()
    log(fh, f"image base = 0x{IMG:X}")

    # Key addresses
    BSGEO_CTOR    = IMG + 0x16D4BD0
    BSTRI_CTOR    = IMG + 0x16D99E0
    BSDYN_CTOR    = IMG + 0x16E4090
    BSGEO_VT      = IMG + 0x267E0B8
    BSTRI_VT      = IMG + 0x267E948
    BSDYN_VT      = IMG + 0x267F758  # corrected per user note
    BSDYN_VT_OLD  = IMG + 0x267F948  # IDA mis-label
    ALLOC_EA      = IMG + 0x16579C0
    INSTALLER_1   = IMG +  0x372CC0  # sub_140372CC0
    INSTALLER_2   = IMG +  0x6B60C0  # sub_1406B60C0
    UNK_VD_GLOBAL = IMG + 0x3437F50  # unk_143437F50 (vertex-desc init default)
    UNK_VD_GLOBAL_1 = IMG + 0x3437F54  # qword_143437F54

    log(fh, f"BSGeometry::ctor              @ 0x{BSGEO_CTOR:X} (RVA 0x{rva(BSGEO_CTOR):X})")
    log(fh, f"BSTriShape::ctor              @ 0x{BSTRI_CTOR:X}")
    log(fh, f"BSDynamicTriShape::ctor       @ 0x{BSDYN_CTOR:X}")
    log(fh, f"BSGeometry  vtable            @ 0x{BSGEO_VT:X}")
    log(fh, f"BSTriShape  vtable            @ 0x{BSTRI_VT:X}")
    log(fh, f"BSDynamicTriShape vtable      @ 0x{BSDYN_VT:X} (corrected)")
    log(fh, f"BSDynamicTriShape vtable alt  @ 0x{BSDYN_VT_OLD:X} (IDA mis-label)")
    log(fh, f"Allocator sub_1416579C0       @ 0x{ALLOC_EA:X}")
    log(fh, f"Installer sub_140372CC0       @ 0x{INSTALLER_1:X}")
    log(fh, f"Installer sub_1406B60C0       @ 0x{INSTALLER_2:X}")
    log(fh, f"unk_143437F50 (VD global)     @ 0x{UNK_VD_GLOBAL:X}")

    # ========================================================
    # STEP 1 — Scan BSGeometry ctor to understand +0x150 init
    # ========================================================
    log(fh, "\n\n========== STEP 1 — BSGeometry ctor re-inspect (+0x150/+0x148/+0x160) ==========")
    decomp_full(BSGEO_CTOR, fh, "BSGeometry::ctor", max_lines=250)
    disasm_dump(BSGEO_CTOR, fh, "BSGeometry::ctor (disasm)", insn_count=120)

    # Check the global unk_143437F50 — what writes it and what does the
    # data at that offset look like?
    log(fh, f"\n== Dump 16 bytes at unk_143437F50 (VD default template) ==")
    for i in range(0, 16, 4):
        b = ida_bytes.get_dword(UNK_VD_GLOBAL + i)
        log(fh, f"  +{i:X}  0x{b:08X}")
    for i in range(0, 16, 8):
        b = ida_bytes.get_qword(UNK_VD_GLOBAL + i)
        log(fh, f"  QW +{i:X}  0x{b:016X}")

    # Who writes unk_143437F50?
    log(fh, "\n== xrefs to unk_143437F50 ==")
    xrefs_to(UNK_VD_GLOBAL, fh, "unk_143437F50")
    xrefs_to(UNK_VD_GLOBAL_1, fh, "qword_143437F54")

    # ========================================================
    # STEP 2 — Scan binary for [reg+150h] displacement access
    # ========================================================
    log(fh, "\n\n========== STEP 2 — hunt [reg+150h] read sites (limited) ==========")
    hits_150 = find_offset_in_binary(0x150, fh, "BSGeometry+0x150 (VertexDesc)", limit=60)

    # Deduplicate by function
    unique_fn_150 = sorted(set([h[1] for h in hits_150 if h[1]]))
    log(fh, f"\n== unique functions accessing +0x150 ({len(unique_fn_150)}) ==")
    for fn_ea in unique_fn_150:
        name = ida_funcs.get_func_name(fn_ea) or "?"
        log(fh, f"  0x{fn_ea:X}  RVA 0x{rva(fn_ea):X}  {name}")

    # ========================================================
    # STEP 3 — Decomp the top handful of +0x150 readers to find
    # the one that unpacks nibbles (input-layout setup)
    # ========================================================
    log(fh, "\n\n========== STEP 3 — decomp top +0x150 readers ==========")
    # Take up to 6 small-ish functions that reference +0x150
    from collections import Counter
    fn_counts_150 = Counter([h[1] for h in hits_150 if h[1]])
    top_fns_150 = sorted(fn_counts_150.items(), key=lambda x: -x[1])[:10]
    for fn_ea, cnt in top_fns_150:
        fn = ida_funcs.get_func(fn_ea)
        if not fn:
            continue
        size = fn.end_ea - fn.start_ea
        log(fh, f"\n[candidate reader] RVA 0x{rva(fn_ea):X} size=0x{size:X} hits={cnt}")
        if size < 0x800:
            decomp_full(fn_ea, fh, f"+0x150 reader RVA 0x{rva(fn_ea):X}", max_lines=250)
        else:
            log(fh, "  (too large — skipped decomp)")

    # ========================================================
    # STEP 4 — Same scan for +0x148 (GeometryData ptr)
    # ========================================================
    log(fh, "\n\n========== STEP 4 — hunt [reg+148h] (GeometryData) ==========")
    hits_148 = find_offset_in_binary(0x148, fh, "BSGeometry+0x148", limit=60)
    unique_fn_148 = sorted(set([h[1] for h in hits_148 if h[1]]))
    log(fh, f"\n== unique functions ({len(unique_fn_148)}) ==")
    for fn_ea in unique_fn_148:
        log(fh, f"  RVA 0x{rva(fn_ea):X}")

    from collections import Counter
    fn_counts_148 = Counter([h[1] for h in hits_148 if h[1]])
    top_fns_148 = sorted(fn_counts_148.items(), key=lambda x: -x[1])[:6]
    for fn_ea, cnt in top_fns_148:
        fn = ida_funcs.get_func(fn_ea)
        if not fn:
            continue
        size = fn.end_ea - fn.start_ea
        log(fh, f"\n[candidate +0x148 reader] RVA 0x{rva(fn_ea):X} size=0x{size:X} hits={cnt}")
        if size < 0x800:
            decomp_full(fn_ea, fh, f"+0x148 reader RVA 0x{rva(fn_ea):X}", max_lines=250)

    # ========================================================
    # STEP 5 — +0x140 (skin instance?)
    # ========================================================
    log(fh, "\n\n========== STEP 5 — hunt [reg+140h] (skin instance?) ==========")
    hits_140 = find_offset_in_binary(0x140, fh, "BSGeometry+0x140", limit=60)
    fn_counts_140 = Counter([h[1] for h in hits_140 if h[1]])
    top_fns_140 = sorted(fn_counts_140.items(), key=lambda x: -x[1])[:6]
    for fn_ea, cnt in top_fns_140:
        fn = ida_funcs.get_func(fn_ea)
        if not fn:
            continue
        size = fn.end_ea - fn.start_ea
        log(fh, f"\n[candidate +0x140 reader] RVA 0x{rva(fn_ea):X} size=0x{size:X} hits={cnt}")
        if size < 0x800:
            decomp_full(fn_ea, fh, f"+0x140 reader RVA 0x{rva(fn_ea):X}", max_lines=250)

    # ========================================================
    # STEP 6 — Decomp installer sub_140372CC0 (FULL)
    # ========================================================
    log(fh, "\n\n========== STEP 6 — INSTALLER sub_140372CC0 full decomp ==========")
    decomp_full(INSTALLER_1, fh, "sub_140372CC0", max_lines=1500)

    # ========================================================
    # STEP 7 — Decomp installer sub_1406B60C0 (FULL)
    # ========================================================
    log(fh, "\n\n========== STEP 7 — INSTALLER sub_1406B60C0 full decomp ==========")
    decomp_full(INSTALLER_2, fh, "sub_1406B60C0", max_lines=1500)

    # ========================================================
    # STEP 8 — BSDynamicTriShape vtable dump (slots)
    # ========================================================
    log(fh, "\n\n========== STEP 8 — BSDynamicTriShape vtable slot dump ==========")
    for slot in range(0, 96):
        ea = ida_bytes.get_qword(BSDYN_VT + slot * 8)
        if ea == 0:
            break
        name = ida_funcs.get_func_name(ea) or "?"
        log(fh, f"  [{slot:2d}] +0x{slot*8:03X}  0x{ea:X}  RVA 0x{rva(ea):X}  {name}")

    # ========================================================
    # STEP 9 — BSTriShape vtable slot dump (to compare)
    # ========================================================
    log(fh, "\n\n========== STEP 9 — BSTriShape vtable slot dump ==========")
    for slot in range(0, 96):
        ea = ida_bytes.get_qword(BSTRI_VT + slot * 8)
        if ea == 0:
            break
        name = ida_funcs.get_func_name(ea) or "?"
        log(fh, f"  [{slot:2d}] +0x{slot*8:03X}  0x{ea:X}  RVA 0x{rva(ea):X}  {name}")

    # ========================================================
    # STEP 10 — BSGeometry vtable (for comparison — same slots
    # override pattern?)
    # ========================================================
    log(fh, "\n\n========== STEP 10 — BSGeometry vtable slot dump ==========")
    for slot in range(0, 96):
        ea = ida_bytes.get_qword(BSGEO_VT + slot * 8)
        if ea == 0:
            break
        name = ida_funcs.get_func_name(ea) or "?"
        log(fh, f"  [{slot:2d}] +0x{slot*8:03X}  0x{ea:X}  RVA 0x{rva(ea):X}  {name}")

    # ========================================================
    # STEP 11 — Scan BSDynamicTriShape::ctor for +0x178/+0x17C writes
    # ========================================================
    log(fh, "\n\n========== STEP 11 — BSDynamicTriShape ctor disasm ==========")
    decomp_full(BSDYN_CTOR, fh, "BSDynamicTriShape::ctor", max_lines=100)
    disasm_dump(BSDYN_CTOR, fh, "BSDynamicTriShape::ctor (disasm)", insn_count=60)

    # sub_1416D95B0 is the BSTriShape sub-ctor wrapper called from BSDynamic.
    # Let's decomp it too.
    BSTRI_SUBCTOR = IMG + 0x16D95B0
    log(fh, "\n== BSTriShape sub-ctor wrapper ==")
    decomp_full(BSTRI_SUBCTOR, fh, "sub_1416D95B0", max_lines=100)

    # ========================================================
    # STEP 12 — trace +0x160 access (packed count) to confirm fields
    # ========================================================
    log(fh, "\n\n========== STEP 12 — +0x160 scan (packed count) ==========")
    hits_160 = find_offset_in_binary(0x160, fh, "BSGeometry+0x160", limit=40)
    fn_counts_160 = Counter([h[1] for h in hits_160 if h[1]])
    top_fns_160 = sorted(fn_counts_160.items(), key=lambda x: -x[1])[:5]
    for fn_ea, cnt in top_fns_160:
        fn = ida_funcs.get_func(fn_ea)
        if not fn:
            continue
        size = fn.end_ea - fn.start_ea
        log(fh, f"\n[candidate +0x160 reader] RVA 0x{rva(fn_ea):X} size=0x{size:X} hits={cnt}")
        if size < 0x800:
            decomp_full(fn_ea, fh, f"+0x160 reader RVA 0x{rva(fn_ea):X}", max_lines=250)

    # ========================================================
    # STEP 13 — trace BSDynamicTriShape +0x17C (dyn vert buffer)
    # ========================================================
    log(fh, "\n\n========== STEP 13 — +0x17C scan (dyn vert buffer) ==========")
    hits_17c = find_offset_in_binary(0x17C, fh, "BSDyn+0x17C", limit=40)
    fn_counts_17c = Counter([h[1] for h in hits_17c if h[1]])
    top_fns_17c = sorted(fn_counts_17c.items(), key=lambda x: -x[1])[:5]
    for fn_ea, cnt in top_fns_17c:
        fn = ida_funcs.get_func(fn_ea)
        if not fn:
            continue
        size = fn.end_ea - fn.start_ea
        log(fh, f"\n[candidate +0x17C reader] RVA 0x{rva(fn_ea):X} size=0x{size:X} hits={cnt}")
        if size < 0xC00:
            decomp_full(fn_ea, fh, f"+0x17C reader RVA 0x{rva(fn_ea):X}", max_lines=250)

    # ========================================================
    # STEP 14 — trace BSDynamicTriShape +0x178 (dyn vert count)
    # ========================================================
    log(fh, "\n\n========== STEP 14 — +0x178 scan (dyn vert count) ==========")
    hits_178 = find_offset_in_binary(0x178, fh, "BSDyn+0x178", limit=40)
    fn_counts_178 = Counter([h[1] for h in hits_178 if h[1]])
    top_fns_178 = sorted(fn_counts_178.items(), key=lambda x: -x[1])[:5]
    for fn_ea, cnt in top_fns_178:
        fn = ida_funcs.get_func(fn_ea)
        if not fn:
            continue
        size = fn.end_ea - fn.start_ea
        log(fh, f"\n[candidate +0x178 reader] RVA 0x{rva(fn_ea):X} size=0x{size:X} hits={cnt}")
        if size < 0xC00:
            decomp_full(fn_ea, fh, f"+0x178 reader RVA 0x{rva(fn_ea):X}", max_lines=250)

    log(fh, "\n==== END M2.4 GEOMETRY DUMP ====")
    fh.close()
    ida_pro.qexit(0)


main()
