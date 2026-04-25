"""
decomp_stradaB_M2_rdiag.py

Strada B M2 — Render Diagnosis.

5 investigations:
  1. Render dispatch trace from ShadowSceneNode (vt_rva=0x2908F40).
     - Decomp vt slots that iterate .children
     - Trace to BSGeometry::Render slot (dispatcher to D3D11)
     - Identify culling / bounding checks
     - Find shader bind / IASetVertexBuffers site
  2. AttachChild semantics (sub_1416BE170) when reuseFirstEmpty=1
  3. BSVertexDesc packing:  0x0003B00005430206 (src)  vs  0x1300000300204 (our cube)
     - Decode both
     - Packer output test
  4. Factory sub_14182FFD0 post-conditions — does the cube need any other call
  5. NiAVObject flag requirements — do we need to clear 0x1 (APP_CULLED)? Etc.

Output: C:\\Users\\filip\\Desktop\\FalloutWorld\\re\\stradaB_M2_rdiag_raw.txt
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

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\stradaB_M2_rdiag_raw.txt"


def log(fh, msg):
    print(msg)
    fh.write(msg + "\n")
    fh.flush()


def rva(ea):
    return ea - ida_nalt.get_imagebase()


def decomp_full(ea, fh, label="", max_lines=1200):
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


def vtable_dump(vt_ea, fh, label, max_slots=120):
    log(fh, f"\n== {label} vtable @ 0x{vt_ea:X} (RVA 0x{rva(vt_ea):X}) slot dump ==")
    for slot in range(0, max_slots):
        ea = ida_bytes.get_qword(vt_ea + slot * 8)
        if ea == 0 or ea == 0xFFFFFFFFFFFFFFFF:
            break
        # Sanity: is it a code pointer?
        if ea < 0x140000000 or ea > 0x148000000:
            log(fh, f"  [{slot:2d}] +0x{slot*8:03X}  0x{ea:X}  (non-code, stop)")
            break
        name = ida_funcs.get_func_name(ea) or "?"
        log(fh, f"  [{slot:2d}] +0x{slot*8:03X}  0x{ea:X}  RVA 0x{rva(ea):X}  {name}")


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    log(fh, "==== Strada B M2 — RENDER DIAGNOSIS ====")
    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()
    IMG = ida_nalt.get_imagebase()
    log(fh, f"image base = 0x{IMG:X}")

    # ==================================================================
    # Key addresses
    # ==================================================================
    # Scene render entry (Strada A discovery)
    SCENE_RENDER_RVA = 0xC38F80
    SCENE_RENDER_EA  = IMG + SCENE_RENDER_RVA

    # Factory + post-alloc helpers
    GEO_BUILDER      = IMG + 0x182FFD0
    POSTALLOC        = IMG + 0x16DA0A0
    POSTALLOC_EMPTY  = IMG + 0x16DA0F0

    # Scene graph nodes
    SSN_VT           = IMG + 0x2908F40
    BSFADE_VT        = IMG + 0x28FA3E8
    NINODE_VT        = IMG + 0x267C888
    BSTRI_VT         = IMG + 0x267E948
    BSGEO_VT         = IMG + 0x267E0B8
    NIAVOBJECT_VT    = IMG + 0x267D0C0

    # AttachChild
    ATTACHCHILD      = IMG + 0x16BE170

    # Update
    UPDATE_DOWNWARD  = IMG + 0x16C8050

    # BSGeometry ctor & alpha setter
    BSGEO_CTOR       = IMG + 0x16D4BD0
    BSTRI_CTOR       = IMG + 0x16D99E0
    BSGEO_VT_42      = IMG + 0x16D5930  # SetAlphaProperty

    # Packer + helpers
    PACKER           = IMG + 0x182DFC0

    log(fh, f"SCENE_RENDER      @ 0x{SCENE_RENDER_EA:X}")
    log(fh, f"GEO_BUILDER       @ 0x{GEO_BUILDER:X}")
    log(fh, f"POSTALLOC         @ 0x{POSTALLOC:X}")
    log(fh, f"POSTALLOC_EMPTY   @ 0x{POSTALLOC_EMPTY:X}")
    log(fh, f"SSN vtable        @ 0x{SSN_VT:X}")
    log(fh, f"BSFadeNode vtable @ 0x{BSFADE_VT:X}")
    log(fh, f"NiNode vtable     @ 0x{NINODE_VT:X}")
    log(fh, f"BSTriShape vtable @ 0x{BSTRI_VT:X}")
    log(fh, f"BSGeometry vtable @ 0x{BSGEO_VT:X}")
    log(fh, f"NiAVObject vtable @ 0x{NIAVOBJECT_VT:X}")
    log(fh, f"AttachChild       @ 0x{ATTACHCHILD:X}")
    log(fh, f"UpdateDownward    @ 0x{UPDATE_DOWNWARD:X}")
    log(fh, f"PACKER            @ 0x{PACKER:X}")

    # ==================================================================
    # TASK 1 — Render dispatch trace from SSN
    # ==================================================================
    log(fh, "\n\n" + "="*70)
    log(fh, "TASK 1 — SSN render dispatch trace")
    log(fh, "="*70)

    # 1a. Dump SSN full vtable
    vtable_dump(SSN_VT, fh, "ShadowSceneNode", max_slots=140)
    # 1b. Dump BSFadeNode full vtable (scenes go SSN -> NiNode -> BSFadeNode -> BSTriShape)
    vtable_dump(BSFADE_VT, fh, "BSFadeNode", max_slots=140)
    # 1c. NiNode for comparison
    vtable_dump(NINODE_VT, fh, "NiNode", max_slots=140)
    # 1d. BSTriShape vtable
    vtable_dump(BSTRI_VT, fh, "BSTriShape", max_slots=140)
    # 1e. BSGeometry vtable
    vtable_dump(BSGEO_VT, fh, "BSGeometry", max_slots=140)

    # 1f. Decomp scene render entry
    log(fh, "\n-- SCENE RENDER entry decomp --")
    decomp_full(SCENE_RENDER_EA, fh, "sub_140C38F80 SCENE_RENDER", max_lines=800)

    # 1g. Inspect NiNode's UpdateDownwardPass — this is what iterates children
    log(fh, "\n-- UpdateDownwardPass (children walker) decomp --")
    decomp_full(UPDATE_DOWNWARD, fh, "sub_1416C8050 UpdateDownwardPass", max_lines=300)

    # 1h. SSN likely has overrides for "render" in some vtable slot.
    # Decomp the SSN-specific slots (look for ones that differ from NiNode).
    log(fh, "\n-- Decomp a few SSN-specific vtable entries to find the scene-walking one --")
    for slot in [35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 60, 62, 63, 64, 65, 66, 67, 68]:
        ea = ida_bytes.get_qword(SSN_VT + slot * 8)
        if not ea or ea < 0x140000000 or ea > 0x148000000:
            break
        ni_ea = ida_bytes.get_qword(NINODE_VT + slot * 8)
        marker = ""
        if ea == ni_ea:
            marker = "   (same as NiNode)"
        fn = ida_funcs.get_func(ea)
        size = (fn.end_ea - fn.start_ea) if fn else 0
        log(fh, f"  SSN slot[{slot:2d}] = 0x{ea:X} (RVA 0x{rva(ea):X}) size=0x{size:X}{marker}")

    # 1i. Decomp BSGeometry vtable slots that LIKELY are render hooks.
    log(fh, "\n-- Decomp BSGeometry vtable slots that differ from NiAVObject (render-related?) --")
    for slot in range(40, 90):
        ea = ida_bytes.get_qword(BSGEO_VT + slot * 8)
        if not ea or ea < 0x140000000 or ea > 0x148000000:
            break
        av_ea = ida_bytes.get_qword(NIAVOBJECT_VT + slot * 8)
        marker = ""
        if ea == av_ea:
            marker = "   (same as NiAVObject)"
        fn = ida_funcs.get_func(ea)
        size = (fn.end_ea - fn.start_ea) if fn else 0
        log(fh, f"  BSGeometry slot[{slot:2d}] = 0x{ea:X} (RVA 0x{rva(ea):X}) size=0x{size:X}{marker}")

    # ==================================================================
    # TASK 2 — AttachChild semantics
    # ==================================================================
    log(fh, "\n\n" + "="*70)
    log(fh, "TASK 2 — AttachChild semantics with reuseFirstEmpty=1")
    log(fh, "="*70)
    decomp_full(ATTACHCHILD, fh, "sub_1416BE170 NiNode::AttachChild", max_lines=200)
    disasm_dump(ATTACHCHILD, fh, "AttachChild disasm", insn_count=120)

    # Also dump sub_1416BFEB0 (the NiTObjectArray push — if AttachChild
    # increments count or not is encoded here)
    ARRAY_PUSH = IMG + 0x16BFEB0
    decomp_full(ARRAY_PUSH, fh, "sub_1416BFEB0 NiTObjectArray push", max_lines=200)

    # sub_1416C8B60 — the SetParent helper
    SET_PARENT = IMG + 0x16C8B60
    decomp_full(SET_PARENT, fh, "sub_1416C8B60 SetParent", max_lines=100)

    # ==================================================================
    # TASK 3 — BSVertexDesc packing mismatch
    # ==================================================================
    log(fh, "\n\n" + "="*70)
    log(fh, "TASK 3 — BSVertexDesc decode")
    log(fh, "="*70)

    # Decode the observed values.
    def decode_vdesc(label, qw):
        log(fh, f"\n  === {label}: 0x{qw:016X} ===")
        # The low byte is stride/4 (nibble pair). Let's decode.
        stride_lo = (qw >> 0) & 0xFF
        # Bits 0..3 = pos offset/4, bits 6..9 = uv offset/4,
        # bits 10..13 = tangent off, bits 14..17 = normal off,
        # bits 22..25 = colors, bits 26..29 = skin, bits 30..33 = tangent-extra,
        # bits 34..37 = eye. Let's compute these nibbles.
        # (The packer code is: v98 = v23 & 0xFFFFFFFFFFFFFF00 | (v24 >> 2 & 0x3FFFFFFFFFFFFF0F) | (4 * HIDWORD(v90)))
        pos_nib  = (qw >> 0) & 0xF
        uv_nib   = (qw >> 6) & 0xF
        tan_nib  = (qw >> 10) & 0xF
        nrm_nib  = (qw >> 14) & 0xF
        pos_alt  = (qw >> 18) & 0xF
        col_nib  = (qw >> 22) & 0xF
        sk_nib   = (qw >> 26) & 0xF
        tx_nib   = (qw >> 30) & 0xF
        eye_nib  = (qw >> 34) & 0xF
        top_byte = (qw >> 56) & 0xFF   # flags/stride
        top_dword = (qw >> 32) & 0xFFFFFFFF
        log(fh, f"    stride byte    (low 8b) = 0x{stride_lo:02X} = {stride_lo}")
        log(fh, f"    pos   nib (b0)        = 0x{pos_nib:X}  off = {pos_nib*4}")
        log(fh, f"    uv    nib (b6)        = 0x{uv_nib:X}  off = {uv_nib*4}")
        log(fh, f"    tan   nib (b10)       = 0x{tan_nib:X}  off = {tan_nib*4}")
        log(fh, f"    nrm   nib (b14)       = 0x{nrm_nib:X}  off = {nrm_nib*4}")
        log(fh, f"    pos'  nib (b18)       = 0x{pos_alt:X}  off = {pos_alt*4}")
        log(fh, f"    col   nib (b22)       = 0x{col_nib:X}  off = {col_nib*4}")
        log(fh, f"    skin  nib (b26)       = 0x{sk_nib:X}  off = {sk_nib*4}")
        log(fh, f"    tanEx nib (b30)       = 0x{tx_nib:X}  off = {tx_nib*4}")
        log(fh, f"    eye   nib (b34)       = 0x{eye_nib:X}  off = {eye_nib*4}")
        log(fh, f"    top byte (b56..)      = 0x{top_byte:02X}   (flag bits 42..57)")
        log(fh, f"    top dword (b32..)     = 0x{top_dword:08X}")
        # "Stream present" flag bits 42..57 live in the top dword, every 2 bits.
        log(fh, f"    flag bit42 (POS)      = {(qw >> 42) & 0x3}")
        log(fh, f"    flag bit43 (?)        = {(qw >> 43) & 0x1}")
        log(fh, f"    flag bit44 (UV)       = {(qw >> 44) & 0x3}")
        log(fh, f"    flag bit45 (?)        = {(qw >> 45) & 0x1}")
        log(fh, f"    flag bit46 (NORMAL)   = {(qw >> 46) & 0x3}")
        log(fh, f"    flag bit48 (TAN)      = {(qw >> 48) & 0x3}")
        log(fh, f"    flag bit50 (COL)      = {(qw >> 50) & 0x3}")
        log(fh, f"    flag bit52 (SKIN)     = {(qw >> 52) & 0x3}")
        log(fh, f"    flag bit54 (SKIN2?)   = {(qw >> 54) & 0x3}")
        log(fh, f"    flag bit56 (EYE)      = {(qw >> 56) & 0x3}")

    decode_vdesc("SOURCE BSTriShape vdesc", 0x0003B00005430206)
    decode_vdesc("OUR CUBE vdesc (from log)", 0x0001300000300204)  # padded
    decode_vdesc("OUR CUBE vdesc (as-logged)", 0x1300000300204)

    # Find the exact top-of-packer shift structure
    log(fh, "\n-- Packer (sub_14182DFC0) — first 200 lines decomp for desc construction --")
    decomp_full(PACKER, fh, "sub_14182DFC0 PACKER", max_lines=200)

    # ==================================================================
    # TASK 4 — Factory post-conditions
    # ==================================================================
    log(fh, "\n\n" + "="*70)
    log(fh, "TASK 4 — Factory post-conditions")
    log(fh, "="*70)
    # full GEO_BUILDER decomp
    decomp_full(GEO_BUILDER, fh, "sub_14182FFD0 GEO_BUILDER", max_lines=600)

    # POSTALLOC
    decomp_full(POSTALLOC,       fh, "sub_1416DA0A0 POSTALLOC_NORMAL", max_lines=200)
    decomp_full(POSTALLOC_EMPTY, fh, "sub_1416DA0F0 POSTALLOC_EMPTY",  max_lines=200)

    # Decomp the post-factory pattern from a representative vanilla call site
    # (sub_140372CC0 is the FogOfWarOverlay path — examine how it uses
    # the returned BSTriShape).
    FOW_INSTALLER = IMG + 0x372CC0
    log(fh, "\n-- sub_140372CC0 decomp (first 800 lines) — shows full vanilla path --")
    decomp_full(FOW_INSTALLER, fh, "sub_140372CC0 FogOfWar installer", max_lines=800)

    # ==================================================================
    # TASK 5 — NiAVObject flags
    # ==================================================================
    log(fh, "\n\n" + "="*70)
    log(fh, "TASK 5 — NiAVObject flags at +0x108 requirements")
    log(fh, "="*70)
    NIAV_CTOR = IMG + 0x16C8CD0
    decomp_full(NIAV_CTOR, fh, "sub_1416C8CD0 NiAVObject ctor", max_lines=200)
    disasm_dump(NIAV_CTOR, fh, "NiAVObject ctor disasm", insn_count=100)

    # Also dump BSTriShape::ctor (inherits BSGeometry::ctor which calls NiAVObject::ctor)
    decomp_full(BSTRI_CTOR, fh, "sub_1416D99E0 BSTriShape::ctor", max_lines=150)

    # Search for [reg+108h] writes in a known-good installer
    log(fh, "\n-- scan sub_140372CC0 for [reg+108h] reads/writes (NiAVObject flag usage) --")
    fn = ida_funcs.get_func(FOW_INSTALLER)
    if fn:
        cur = fn.start_ea
        end = fn.end_ea
        while cur < end:
            dis = idc.generate_disasm_line(cur, 0) or ""
            dl = dis.lower()
            if "+108h" in dl or "+100h" in dl or "+110h" in dl or "+118h" in dl or "+120h" in dl:
                log(fh, f"    0x{cur:X}  {dis}")
            cur = idc.next_head(cur, end)
            if cur == idc.BADADDR:
                break

    # Are there any CANDIDATE bit values at +0x108 we might be missing?
    # The 1-byte-above test is: decomp a render-walk and see what it checks.
    # Quick: look for code patterns `test [reg+108h], imm` which gate rendering.
    log(fh, "\n-- Find [reg+108h] TEST sites across the binary (culling gates) --")
    # Scan executable text for "test" instructions on +0x108.
    seg = ida_segment.get_first_seg()
    hits_108 = []
    while seg:
        if (seg.perm & ida_segment.SEGPERM_EXEC):
            cur = seg.start_ea
            end = seg.end_ea
            while cur < end and len(hits_108) < 80:
                insn = ida_ua.insn_t()
                if ida_ua.decode_insn(insn, cur):
                    mnem = insn.get_canon_mnem()
                    if mnem in ("test", "bt"):
                        for i in range(2):
                            op = insn.ops[i]
                            if op.type == ida_ua.o_displ and op.addr == 0x108:
                                dis = idc.generate_disasm_line(cur, 0) or "?"
                                fn = ida_funcs.get_func(cur)
                                fn_name = ida_funcs.get_func_name(cur) or "?"
                                fn_ea = fn.start_ea if fn else 0
                                log(fh, f"    0x{cur:X}  RVA 0x{rva(cur):X}  in {fn_name}  {dis}")
                                hits_108.append((cur, fn_ea))
                                break
                    cur += insn.size
                else:
                    cur = idc.next_head(cur, end)
                    if cur == idc.BADADDR:
                        break
        seg = ida_segment.get_next_seg(seg.start_ea)
    log(fh, f"\n  [total [reg+108h] test hits] {len(hits_108)}")

    # ==================================================================
    # BONUS — Find the render-walk site that filters by flag
    # ==================================================================
    log(fh, "\n\n" + "="*70)
    log(fh, "BONUS — Functions that test +0x108 AND +0x120 (bounds cull?)")
    log(fh, "="*70)
    # Multi-signal: functions that read both flag and bound sphere.
    # Limit to small functions to be quick.
    fn_test_108 = set([h[1] for h in hits_108 if h[1]])
    log(fh, f"  functions with +0x108 test: {len(fn_test_108)}")
    count = 0
    for fn_ea in sorted(fn_test_108):
        fn = ida_funcs.get_func(fn_ea)
        if not fn:
            continue
        size = fn.end_ea - fn.start_ea
        if size > 0x600 or size < 0x30:
            continue
        # Does it also reference +0x120 (bound) or the SSN walker pattern?
        cur = fn.start_ea
        end = fn.end_ea
        has_120 = False
        has_c0 = False
        has_attach = False
        while cur < end:
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, cur):
                for i in range(2):
                    op = insn.ops[i]
                    if op.type == ida_ua.o_displ:
                        if op.addr == 0x120:
                            has_120 = True
                        if op.addr == 0xC0:
                            has_c0 = True
                cur += insn.size
            else:
                cur = idc.next_head(cur, end)
                if cur == idc.BADADDR:
                    break
        sig = f"+120={1 if has_120 else 0} +C0={1 if has_c0 else 0}"
        if has_120 or has_c0:
            log(fh, f"  fn RVA 0x{rva(fn_ea):X} size=0x{size:X} {sig}")
            if count < 6 and (has_120 and has_c0):
                decomp_full(fn_ea, fh, f"render-cull candidate RVA 0x{rva(fn_ea):X}", max_lines=200)
                count += 1

    log(fh, "\n==== END RENDER DIAGNOSIS ====")
    fh.close()
    ida_pro.qexit(0)


main()
