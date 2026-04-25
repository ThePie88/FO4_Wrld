"""
decomp_stradaB_M2_geom2.py

Follow-up RE for M2.4 dossier — narrower and deeper.

Focus:
 - sub_14182FFD0 (the geometry builder used by both installers)
 - Scan tri-shape-specific code only (RVA 0x16D*, 0x16E*, 0x21B*, 0x1A8*)
 - Decomp key +0x150/+0x148/+0x178/+0x17C readers in renderer range
 - BSGeometry vtable slot 70 (0x16D5E30) — has name "NiIntegerExtraData"-like
   string pattern in memory, probably GetRTTI-like virtual
 - sub_1416D4D60 (BSTriShape vt[47]) — look for LoadBinary / geometry-level
   initializer
 - sub_141677A80 (index buffer alloc helper)
 - sub_141656E30 — heap-alloc-with-cleanup used by installer 1
 - sub_14165BE20 — seg alloc
 - sub_14165C3F0 — release
 - sub_1416576D0 — another alloc helper
 - sub_141657750 — another release helper
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

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\stradaB_M2_geometry_raw2.txt"


def log(fh, msg):
    print(msg)
    fh.write(msg + "\n")
    fh.flush()


def rva(ea):
    return ea - ida_nalt.get_imagebase()


def decomp_full(ea, fh, label="", max_lines=800):
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


def disasm_dump(ea, fh, label="", insn_count=60):
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


def xrefs_to(ea, fh, label, limit=30):
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
    log(fh, "==== Strada B M2.4 GEOM phase-2 ====")
    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()
    IMG = ida_nalt.get_imagebase()
    log(fh, f"image base = 0x{IMG:X}")

    # Critical targets
    GEO_BUILDER        = IMG + 0x182FFD0   # sub_14182FFD0 — BSTriShape factory
    ALLOC_V2           = IMG + 0x1656E30   # sub_141656E30 (alloc sub-heap)
    SEG_ALLOC          = IMG + 0x165BE20   # sub_14165BE20 (segment alloc)
    SEG_FREE           = IMG + 0x165C3F0   # sub_14165C3F0 (segment free)
    TMP_ALLOC          = IMG + 0x1657750   # sub_141657750 (release helper)
    TMP_ALLOC2         = IMG + 0x16576D0   # sub_1416576D0 (alloc helper)
    BSTRI_VT47         = IMG + 0x16D4D60   # BSTriShape vt[47]
    BSTRI_VT48         = IMG + 0x16D4DC0   # BSTriShape vt[48]
    BSTRI_VT49         = IMG + 0x16D4E30
    BSTRI_VT50         = IMG + 0x16D4EA0
    BSTRI_VT51         = IMG + 0x16D4F80
    BSTRI_VT52         = IMG + 0x16D54E0
    BSTRI_VT58_ATTACH  = IMG + 0x16D4F10   # vt[58] for BSTriShape
    BSDYN_VT89         = IMG + 0x16E45A0
    BSDYN_VT90         = IMG + 0x16E4630
    BSDYN_VT91         = IMG + 0x16E4640
    BSDYN_VT92         = IMG + 0x16E4650
    BSDYN_VT93         = IMG + 0x16E46A0
    BSDYN_VT_TRANSFORM = IMG + 0x16E45A0
    SMALL_ALLOC        = IMG + 0x1677A80   # sub_141677A80 (used for index triples)
    INSTALLER_1        = IMG + 0x372CC0
    INSTALLER_2        = IMG + 0x6B60C0
    SUB_14216F9C0      = IMG + 0x216F9C0   # BSEffectShaderProperty init
    SUB_142161B10      = IMG + 0x2161B10   # BSEffectShaderProperty helper
    SUB_1404C6B30      = IMG +  0x4C6B30   # FogOfWar reader
    SUB_142214640      = IMG + 0x2214640   # BSSkyShaderProperty init

    log(fh, f"GEO BUILDER sub_14182FFD0    @ 0x{GEO_BUILDER:X}")

    # -------------------------------------------------
    # STEP A — Decomp GEO_BUILDER — it accepts buffers and returns a
    # BSTriShape pointer. This is the MAIN geometry factory.
    # -------------------------------------------------
    log(fh, "\n\n========== STEP A — GEO BUILDER sub_14182FFD0 decomp ==========")
    decomp_full(GEO_BUILDER, fh, "sub_14182FFD0 (geo builder)", max_lines=1200)
    disasm_dump(GEO_BUILDER, fh, "sub_14182FFD0 (disasm head)", insn_count=200)

    # xrefs — all callers of this builder
    log(fh, "\n== xrefs to sub_14182FFD0 (all BSTriShape factory callers) ==")
    xrefs_to(GEO_BUILDER, fh, "sub_14182FFD0", limit=80)

    # -------------------------------------------------
    # STEP B — Decomp the small helpers
    # -------------------------------------------------
    log(fh, "\n\n========== STEP B — alloc helpers ==========")
    decomp_full(ALLOC_V2, fh, "sub_141656E30 (alloc v2)", max_lines=200)
    decomp_full(SEG_ALLOC, fh, "sub_14165BE20 (seg alloc)", max_lines=200)
    decomp_full(SEG_FREE, fh, "sub_14165C3F0 (seg free)", max_lines=200)
    decomp_full(TMP_ALLOC2, fh, "sub_1416576D0 (tmp alloc2)", max_lines=200)
    decomp_full(TMP_ALLOC, fh, "sub_141657750 (tmp free)", max_lines=200)
    decomp_full(SMALL_ALLOC, fh, "sub_141677A80 (small alloc)", max_lines=100)

    # -------------------------------------------------
    # STEP C — Decomp BSTriShape vtable slots that likely handle
    # rendering / upload / update
    # -------------------------------------------------
    log(fh, "\n\n========== STEP C — BSTriShape vtable slots ==========")
    decomp_full(BSTRI_VT47, fh, "BSTriShape vt[47] sub_1416D4D60", max_lines=250)
    decomp_full(BSTRI_VT48, fh, "BSTriShape vt[48] sub_1416D4DC0", max_lines=250)
    decomp_full(BSTRI_VT49, fh, "BSTriShape vt[49] sub_1416D4E30", max_lines=250)
    decomp_full(BSTRI_VT50, fh, "BSTriShape vt[50] sub_1416D4EA0", max_lines=250)
    decomp_full(BSTRI_VT51, fh, "BSTriShape vt[51] sub_1416D4F80", max_lines=250)
    decomp_full(BSTRI_VT52, fh, "BSTriShape vt[52] sub_1416D54E0", max_lines=250)
    decomp_full(BSTRI_VT58_ATTACH, fh, "BSTriShape vt[58] sub_1416D4F10", max_lines=250)

    # -------------------------------------------------
    # STEP D — BSDynamicTriShape vt[89..93] — dynamic-specific slots
    # -------------------------------------------------
    log(fh, "\n\n========== STEP D — BSDynamicTriShape vt[89..93] ==========")
    decomp_full(BSDYN_VT89, fh, "BSDyn vt[89] sub_1416E45A0", max_lines=200)
    decomp_full(BSDYN_VT90, fh, "BSDyn vt[90] sub_1416E4630", max_lines=200)
    decomp_full(BSDYN_VT91, fh, "BSDyn vt[91] sub_1416E4640", max_lines=200)
    decomp_full(BSDYN_VT92, fh, "BSDyn vt[92] sub_1416E4650", max_lines=200)
    decomp_full(BSDYN_VT93, fh, "BSDyn vt[93] sub_1416E46A0", max_lines=200)

    # -------------------------------------------------
    # STEP E — decomp BSDyn vt[0] (destructor with flags) and vt[52]
    # -------------------------------------------------
    log(fh, "\n\n========== STEP E — BSDyn vt[0], vt[52] ==========")
    decomp_full(IMG + 0x16E41F0, fh, "BSDyn vt[0] (dtor)", max_lines=200)
    decomp_full(IMG + 0x16E40E0, fh, "BSDyn vt[52] sub_1416E40E0", max_lines=200)
    decomp_full(IMG + 0x16E3E00, fh, "BSDyn vt[26] sub_1416E3E00", max_lines=200)
    decomp_full(IMG + 0x16E3F70, fh, "BSDyn vt[27] sub_1416E3F70", max_lines=200)
    decomp_full(IMG + 0x16E3F80, fh, "BSDyn vt[28] sub_1416E3F80", max_lines=200)

    # -------------------------------------------------
    # STEP F — the rendering path references — 0x2695C0 / 0x269860 / 0x269B00
    # These accessed +0x17C in the earlier scan.
    # -------------------------------------------------
    log(fh, "\n\n========== STEP F — render-path slots +0x17C readers ==========")
    decomp_full(IMG + 0x2695C0, fh, "sub_1402695C0 +0x17C writer", max_lines=250)
    decomp_full(IMG + 0x269860, fh, "sub_140269860 +0x17C writer", max_lines=250)
    decomp_full(IMG + 0x269B00, fh, "sub_140269B00 +0x17C writer", max_lines=150)
    decomp_full(IMG + 0x26A540, fh, "sub_14026A540 +0x17C read", max_lines=150)

    # -------------------------------------------------
    # STEP G — The renderer-ish  0x2B4xxx series that touched +0x150
    # -------------------------------------------------
    log(fh, "\n\n========== STEP G — renderer 0x2B4xxx / 0x264xxx / 0x265xxx sites ==========")
    decomp_full(IMG + 0x264940, fh, "sub_140264940", max_lines=250)
    decomp_full(IMG + 0x264C30, fh, "sub_140264C30", max_lines=250)
    decomp_full(IMG + 0x265490, fh, "sub_140265490", max_lines=250)
    decomp_full(IMG + 0x265C70, fh, "sub_140265C70", max_lines=250)
    decomp_full(IMG + 0x2B43B0, fh, "sub_1402B43B0", max_lines=250)
    decomp_full(IMG + 0x2B4750, fh, "sub_1402B4750", max_lines=250)

    # -------------------------------------------------
    # STEP H — sub_1416E41F0 (BSDyn vt[0] partial dtor) to see what
    # gets freed — confirms +0x17C is a buffer we own
    # -------------------------------------------------
    log(fh, "\n\n========== STEP H — BSDyn vt[0] dtor (free check) ==========")
    decomp_full(IMG + 0x16E41F0, fh, "BSDyn::dtor", max_lines=250)

    # -------------------------------------------------
    # STEP I — BSGeometry vt[26..31] (RTTI/clone-ish slots)
    # -------------------------------------------------
    log(fh, "\n\n========== STEP I — BSGeometry vt[26..31] ==========")
    decomp_full(IMG + 0x16BA6F0, fh, "BSGeo vt[26]", max_lines=120)
    decomp_full(IMG + 0x16D4980, fh, "BSGeo vt[27]", max_lines=120)
    decomp_full(IMG + 0x16D49F0, fh, "BSGeo vt[28]", max_lines=120)
    decomp_full(IMG + 0x16D4AB0, fh, "BSGeo vt[29]", max_lines=120)
    decomp_full(IMG + 0x16D4B30, fh, "BSGeo vt[30]", max_lines=120)
    decomp_full(IMG + 0x16D4BC0, fh, "BSGeo vt[31]", max_lines=120)

    # -------------------------------------------------
    # STEP J — BSGeometry vt[65..70] — clone/save slots
    # -------------------------------------------------
    log(fh, "\n\n========== STEP J — BSGeometry vt[65..70] ==========")
    decomp_full(IMG + 0x16D59B0, fh, "BSGeo vt[64]", max_lines=150)
    decomp_full(IMG + 0x16D5990, fh, "BSGeo vt[65]", max_lines=150)
    decomp_full(IMG + 0x16D5E30, fh, "BSGeo vt[70]", max_lines=150)

    # -------------------------------------------------
    # STEP K — sub_1416D5840 (BSGeometry vt[0] — maybe factory?)
    # -------------------------------------------------
    log(fh, "\n\n========== STEP K — BSGeo vt[0] ==========")
    decomp_full(IMG + 0x16D5840, fh, "BSGeo vt[0]", max_lines=200)
    decomp_full(IMG + 0x16D5980, fh, "BSGeo vt[2]", max_lines=150)

    # -------------------------------------------------
    # STEP L — hunt caller of BSGeometry::ctor sub_1416D4BD0 to see
    # more ctors wrapping it (like BSTriShape::ctor) — confirms
    # we know ALL geometry-derived ctors
    # -------------------------------------------------
    log(fh, "\n\n========== STEP L — callers of BSGeometry::ctor ==========")
    xrefs_to(IMG + 0x16D4BD0, fh, "BSGeometry::ctor", limit=30)

    # -------------------------------------------------
    # STEP M — BSTriShape::ctor sub_1416D99E0 — deeper look
    # -------------------------------------------------
    log(fh, "\n\n========== STEP M — BSTriShape ctor + sub_1416D95B0 ==========")
    decomp_full(IMG + 0x16D99E0, fh, "BSTriShape::ctor sub_1416D99E0", max_lines=200)
    # Also disasm it so we see the vt overwrite
    disasm_dump(IMG + 0x16D99E0, fh, "BSTriShape::ctor disasm", insn_count=40)
    decomp_full(IMG + 0x16D95B0, fh, "sub_1416D95B0 (the inner wrapper)", max_lines=200)

    # -------------------------------------------------
    # STEP N — sub_14182FFD0 xref analysis: identify the FIRST non-zero
    # argument pattern (vertex_count, indices, index_count, verts, uv, ...)
    # by scanning selected callers.
    # -------------------------------------------------
    log(fh, "\n\n========== STEP N — callers of GEO_BUILDER (sample decomp) ==========")
    seen_fns = set()
    for x in idautils.XrefsTo(GEO_BUILDER, 0):
        fn = ida_funcs.get_func(x.frm)
        if not fn:
            continue
        fn_ea = fn.start_ea
        if fn_ea in seen_fns:
            continue
        seen_fns.add(fn_ea)
        if len(seen_fns) > 12:
            break
        size = fn.end_ea - fn.start_ea
        if size > 0x1200:
            log(fh, f"\n  (skip large caller RVA 0x{rva(fn_ea):X} size=0x{size:X})")
            continue
        decomp_full(fn_ea, fh, f"builder caller RVA 0x{rva(fn_ea):X}", max_lines=200)

    # -------------------------------------------------
    # STEP O — target all functions that write to a VertexDesc-looking
    # offset *within* BSGeometry (not rsp). We need the low-level
    # readers, which are in code that calls IASetInputLayout.
    # Strategy: search for the bit/nibble unpacking pattern typical of
    # BSVertexDesc decoding.  That uses `shr X, 4` or `and X, 0xF`
    # right after a `mov rax, [reg+150h]` load. Count those.
    # -------------------------------------------------
    log(fh, "\n\n========== STEP O — find +0x150 load followed by shr/and ==========")
    seg = ida_segment.get_first_seg()
    found_sites = []
    while seg:
        if (seg.perm & ida_segment.SEGPERM_EXEC) == 0:
            seg = ida_segment.get_next_seg(seg.start_ea)
            continue
        cur = seg.start_ea
        end = seg.end_ea
        while cur < end and len(found_sites) < 30:
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, cur):
                # Look for pattern: mov reg, [reg+150h]
                if insn.itype == 123 or True:
                    op0 = insn.ops[0]
                    op1 = insn.ops[1]
                    if op1.type == ida_ua.o_displ and op1.addr == 0x150:
                        # Check the next few insns for shr/and
                        next_ea = cur + insn.size
                        for _ in range(6):
                            insn2 = ida_ua.insn_t()
                            if not ida_ua.decode_insn(insn2, next_ea):
                                break
                            d2 = (idc.generate_disasm_line(next_ea, 0) or "").lower()
                            if "shr " in d2 or "and " in d2 or "bt " in d2:
                                fn = ida_funcs.get_func(cur)
                                fn_ea = fn.start_ea if fn else 0
                                log(fh, f"  0x{cur:X} [mov from +150h] RVA 0x{rva(fn_ea):X}")
                                log(fh, f"    followed by 0x{next_ea:X} {d2}")
                                found_sites.append((cur, fn_ea))
                                break
                            next_ea += insn2.size
                cur = cur + insn.size
            else:
                cur = idc.next_head(cur, end)
                if cur == idc.BADADDR:
                    break
        seg = ida_segment.get_next_seg(seg.start_ea)
    log(fh, f"  [total +150h unpack sites] {len(found_sites)}")

    # Decomp top 3 unique functions
    uniq_fns = sorted(set([f for _, f in found_sites if f]))[:5]
    for fn_ea in uniq_fns:
        fn = ida_funcs.get_func(fn_ea)
        if not fn:
            continue
        size = fn.end_ea - fn.start_ea
        log(fh, f"\n[VD unpacker candidate] RVA 0x{rva(fn_ea):X} size=0x{size:X}")
        if size < 0x1000:
            decomp_full(fn_ea, fh, f"VD unpacker RVA 0x{rva(fn_ea):X}", max_lines=300)

    log(fh, "\n==== END PHASE 2 ====")
    fh.close()
    ida_pro.qexit(0)


main()
