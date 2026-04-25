"""
decomp_stradaB_M2_geom3.py — decode the vertex packer

Targets:
  sub_14182DFC0  — the vertex-data walker (19 args, produces stride)
  sub_141818550  — index builder
  sub_1416DA0A0  — BSTriShape post-alloc init (vtable, count, desc)
  sub_1416DA0F0  — empty BSTriShape post-alloc init
  sub_1416CE630  — VD-aware vertex packer
  sub_1416D5E80  — BSGeometry+0x120 writer (vertex-desc template)
  sub_1416BCE00  — sets result on geometry
  sub_14216F9C0  — BSEffectShaderProperty ctor wrapper
  sub_142214640  — BSSkyShaderProperty ctor wrapper
  byte_143A0F400 — vertex layout template constant (the nibble table)
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

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\stradaB_M2_geometry_raw3.txt"


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


def disasm_dump(ea, fh, label="", insn_count=100):
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


def dump_bytes(ea, count, fh, label=""):
    log(fh, f"\n-- bytes at {label} 0x{ea:X} (RVA 0x{rva(ea):X}) (first {count}) --")
    line = "  "
    for i in range(count):
        b = ida_bytes.get_byte(ea + i)
        line += f"{b:02X} "
        if (i + 1) % 16 == 0:
            log(fh, line)
            line = "  "
    if line.strip():
        log(fh, line)


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    log(fh, "==== Strada B M2.4 GEOM phase-3 — vertex packer ====")
    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()
    IMG = ida_nalt.get_imagebase()
    log(fh, f"image base = 0x{IMG:X}")

    PACKER         = IMG + 0x182DFC0
    IDX_BUILDER    = IMG + 0x1818550
    TRI_POSTALLOC  = IMG + 0x16DA0A0
    TRI_POSTALLOC_EMPTY = IMG + 0x16DA0F0
    VD_PACKER      = IMG + 0x1416CE630 - IMG + IMG  # sub_1416CE630
    VD_PACKER      = IMG + 0x16CE630
    VD_TEMPLATE_WR = IMG + 0x16D5E80  # sub_1416D5E80 writes +0x120..
    GEO_SET        = IMG + 0x16BCE00  # sub_1416BCE00
    BYTE_VTX_TMPL  = IMG + 0x3A0F400  # byte_143A0F400 — vertex layout template
    EFFECT_SHADER  = IMG + 0x216F9C0
    SKY_SHADER     = IMG + 0x2214640
    VD_GLOBAL      = IMG + 0x3437F50  # unk_143437F50 default

    log(fh, f"PACKER sub_14182DFC0        @ 0x{PACKER:X}")
    log(fh, f"IDX_BUILDER sub_141818550   @ 0x{IDX_BUILDER:X}")
    log(fh, f"TRI_POSTALLOC sub_1416DA0A0 @ 0x{TRI_POSTALLOC:X}")
    log(fh, f"TRI_POSTALLOC_E sub_1416DA0F0 @ 0x{TRI_POSTALLOC_EMPTY:X}")
    log(fh, f"VD_PACKER sub_1416CE630     @ 0x{VD_PACKER:X}")
    log(fh, f"VD_TEMPLATE_WR sub_1416D5E80@ 0x{VD_TEMPLATE_WR:X}")
    log(fh, f"GEO_SET sub_1416BCE00       @ 0x{GEO_SET:X}")
    log(fh, f"BYTE_VTX_TMPL 143A0F400     @ 0x{BYTE_VTX_TMPL:X}")

    # --- STEP 1: dump the vertex layout template bytes
    log(fh, "\n\n========== STEP 1 — byte_143A0F400 hex dump (256 bytes) ==========")
    dump_bytes(BYTE_VTX_TMPL, 256, fh, "byte_143A0F400")
    # Also dump neighbours (template is usually 16-32 bytes repeated patterns)
    log(fh, "\n-- as dwords (first 64) --")
    for i in range(0, 64, 8):
        d0 = ida_bytes.get_dword(BYTE_VTX_TMPL + 4*i)
        d1 = ida_bytes.get_dword(BYTE_VTX_TMPL + 4*(i+1))
        d2 = ida_bytes.get_dword(BYTE_VTX_TMPL + 4*(i+2))
        d3 = ida_bytes.get_dword(BYTE_VTX_TMPL + 4*(i+3))
        d4 = ida_bytes.get_dword(BYTE_VTX_TMPL + 4*(i+4))
        d5 = ida_bytes.get_dword(BYTE_VTX_TMPL + 4*(i+5))
        d6 = ida_bytes.get_dword(BYTE_VTX_TMPL + 4*(i+6))
        d7 = ida_bytes.get_dword(BYTE_VTX_TMPL + 4*(i+7))
        log(fh, f"  +{4*i:04X}  {d0:08X} {d1:08X} {d2:08X} {d3:08X}  {d4:08X} {d5:08X} {d6:08X} {d7:08X}")

    # --- STEP 2: PACKER decomp
    log(fh, "\n\n========== STEP 2 — PACKER sub_14182DFC0 decomp ==========")
    decomp_full(PACKER, fh, "sub_14182DFC0 (packer)", max_lines=800)
    disasm_dump(PACKER, fh, "sub_14182DFC0 (disasm)", insn_count=400)

    # --- STEP 3: IDX_BUILDER decomp
    log(fh, "\n\n========== STEP 3 — IDX_BUILDER sub_141818550 decomp ==========")
    decomp_full(IDX_BUILDER, fh, "sub_141818550 (idx build)", max_lines=400)

    # --- STEP 4: TRI_POSTALLOC decomp
    log(fh, "\n\n========== STEP 4 — TRI_POSTALLOC sub_1416DA0A0 decomp ==========")
    decomp_full(TRI_POSTALLOC, fh, "sub_1416DA0A0 (post-alloc)", max_lines=400)
    disasm_dump(TRI_POSTALLOC, fh, "sub_1416DA0A0 (disasm)", insn_count=150)

    # --- STEP 4b: TRI_POSTALLOC_EMPTY decomp
    log(fh, "\n\n========== STEP 4b — TRI_POSTALLOC_EMPTY sub_1416DA0F0 decomp ==========")
    decomp_full(TRI_POSTALLOC_EMPTY, fh, "sub_1416DA0F0 (empty post-alloc)", max_lines=200)
    disasm_dump(TRI_POSTALLOC_EMPTY, fh, "sub_1416DA0F0 (disasm)", insn_count=60)

    # --- STEP 5: VD_PACKER decomp
    log(fh, "\n\n========== STEP 5 — VD_PACKER sub_1416CE630 decomp ==========")
    decomp_full(VD_PACKER, fh, "sub_1416CE630 (VD packer)", max_lines=600)

    # --- STEP 6: VD_TEMPLATE_WR
    log(fh, "\n\n========== STEP 6 — VD_TEMPLATE_WR sub_1416D5E80 decomp ==========")
    decomp_full(VD_TEMPLATE_WR, fh, "sub_1416D5E80 (VD template writer)", max_lines=300)
    disasm_dump(VD_TEMPLATE_WR, fh, "sub_1416D5E80 (disasm)", insn_count=100)

    # --- STEP 7: GEO_SET
    log(fh, "\n\n========== STEP 7 — GEO_SET sub_1416BCE00 decomp ==========")
    decomp_full(GEO_SET, fh, "sub_1416BCE00", max_lines=250)

    # --- STEP 8: EFFECT_SHADER / SKY_SHADER wrappers
    log(fh, "\n\n========== STEP 8 — shader wrappers ==========")
    decomp_full(EFFECT_SHADER, fh, "sub_14216F9C0 (BSEffectShader)", max_lines=250)
    decomp_full(SKY_SHADER, fh, "sub_142214640 (BSSkyShader)", max_lines=250)

    # --- STEP 9: dump VD_GLOBAL unk_143437F50 (+64 bytes to see surrounding template)
    log(fh, "\n\n========== STEP 9 — unk_143437F50 template region (+128 bytes) ==========")
    dump_bytes(VD_GLOBAL, 128, fh, "unk_143437F50")
    for i in range(0, 16):
        q = ida_bytes.get_qword(VD_GLOBAL + 8*i)
        log(fh, f"  +{8*i:04X}  QW 0x{q:016X}")

    # --- STEP 10: Find BSShaderRenderTargetManager::Upload-ish code. Look
    # for functions that read +0x148 AND call D3D11 helpers (IDA calls
    # 0x... to DeviceContext ops).  Quick heuristic: functions named
    # BSBatchRenderer* or BSShaderRenderTargetManager* if RTTI labeled.
    log(fh, "\n\n========== STEP 10 — RTTI-named relevant classes ==========")
    import ida_search
    # Search string "BSBatchRenderer"
    for term in ["BSBatchRenderer", "BSShaderRenderer", "BSShaderRenderTargetManager",
                 "BSGeometry", "BSSkinInstance", "BSDynamicTriShape", "BSTriShape",
                 "BSGraphics", "VertexDesc"]:
        log(fh, f"\n--- search '{term}' ---")
        ea = ida_search.find_text(0, 0, 0, term, ida_search.SEARCH_DOWN)
        count = 0
        while ea != idc.BADADDR and count < 3:
            # Show surrounding context
            log(fh, f"  hit @ 0x{ea:X} (RVA 0x{rva(ea):X})")
            # Next
            ea = ida_search.find_text(ea + 1, 0, 0, term, ida_search.SEARCH_DOWN)
            count += 1

    # --- STEP 11: sub_1416DA410 (BSTriShape vt[72]) might be "GetGeometryData"
    log(fh, "\n\n========== STEP 11 — possible getters ==========")
    decomp_full(IMG + 0x16DA410, fh, "BSTriShape vt[72] sub_1416DA410", max_lines=200)
    decomp_full(IMG + 0x16DA340, fh, "BSTriShape vt[0] sub_1416DA340 (dtor)", max_lines=200)

    # --- STEP 12: sub_1416DA2B0 / 2x vt entries
    log(fh, "\n\n========== STEP 12 — near-vt slot peek ==========")
    decomp_full(IMG + 0x16DA2B0, fh, "sub_1416DA2B0", max_lines=200)
    decomp_full(IMG + 0x16DA3F0, fh, "sub_1416DA3F0", max_lines=200)
    decomp_full(IMG + 0x16DA400, fh, "sub_1416DA400", max_lines=200)

    # --- STEP 13: What writes to the +0x178 / +0x17C of BSDyn? grep for
    # sub_1416E... functions that mov [ptr+17Ch], X
    log(fh, "\n\n========== STEP 13 — BSDyn internal offsets writers ==========")
    seg = ida_segment.get_first_seg()
    dyn_wr = []
    while seg:
        if (seg.perm & ida_segment.SEGPERM_EXEC) == 0:
            seg = ida_segment.get_next_seg(seg.start_ea)
            continue
        # Only scan narrow range around BSDyn ctor
        scan_start = max(seg.start_ea, IMG + 0x16E0000)
        scan_end = min(seg.end_ea, IMG + 0x16E6000)
        if scan_start >= scan_end:
            seg = ida_segment.get_next_seg(seg.start_ea)
            continue
        cur = scan_start
        while cur < scan_end:
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, cur):
                op0 = insn.ops[0]
                if op0.type == ida_ua.o_displ and op0.addr in (0x170, 0x178, 0x17C, 0x184):
                    dis = idc.generate_disasm_line(cur, 0) or ""
                    fn = ida_funcs.get_func(cur)
                    fn_ea = fn.start_ea if fn else 0
                    log(fh, f"  0x{cur:X} in RVA 0x{rva(fn_ea):X}  {dis}")
                    dyn_wr.append((cur, fn_ea))
                cur = cur + insn.size
            else:
                cur = idc.next_head(cur, scan_end)
                if cur == idc.BADADDR:
                    break
        seg = ida_segment.get_next_seg(seg.start_ea)

    # Decomp unique fns
    uniq_fns = sorted(set([f for _, f in dyn_wr if f]))
    log(fh, f"\n== Unique BSDyn offset writers ({len(uniq_fns)}) ==")
    for fn_ea in uniq_fns[:20]:
        fn = ida_funcs.get_func(fn_ea)
        if not fn:
            continue
        size = fn.end_ea - fn.start_ea
        log(fh, f"  RVA 0x{rva(fn_ea):X} size=0x{size:X}")
        if size < 0x400:
            decomp_full(fn_ea, fh, f"BSDyn writer RVA 0x{rva(fn_ea):X}", max_lines=150)

    log(fh, "\n==== END PHASE 3 ====")
    fh.close()
    ida_pro.qexit(0)


main()
