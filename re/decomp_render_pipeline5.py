"""
decomp_render_pipeline5.py
CRITICAL: sub_140C38F80 is the actual 3D scene render entry (called from sub_140C38910).
Also dump BSBatchRenderer slot 4 (size 0x38B - likely the big render loop).
Dump BSGeometry vt slot 7 (the one called with (shape, phase_code, ...)).
"""
import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_nalt
import ida_pro
import idc
import idautils
import idaapi

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\render_pipeline_report5.txt"

def log(fh, msg):
    print(msg)
    fh.write(msg + "\n")
    fh.flush()

def decomp(ea):
    try:
        c = ida_hexrays.decompile(ea)
        return str(c) if c else None
    except Exception as e:
        return f"<{e}>"

def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()
    imb = ida_nalt.get_imagebase()

    # sub_140C38F80 = the real 3D scene renderer
    log(fh, "==== sub_140C38F80 = 3D scene render main entry ====")
    ea = 0x140C38F80
    txt = decomp(ea)
    if txt:
        for ln in txt.splitlines()[:400]:
            log(fh, f"  {ln}")

    # BSBatchRenderer slot 4 = size 0x38B — likely the big batch dispatch
    log(fh, "\n==== BSBatchRenderer::vt[4] = 0x14221BC90 (0x38B bytes, likely Dispatch) ====")
    ea = 0x14221BC90
    txt = decomp(ea)
    if txt:
        for ln in txt.splitlines()[:200]:
            log(fh, f"  {ln}")

    log(fh, "\n==== BSBatchRenderer::vt[5] = 0x14221C030 (0x152 bytes) ====")
    ea = 0x14221C030
    txt = decomp(ea)
    if txt:
        for ln in txt.splitlines()[:80]:
            log(fh, f"  {ln}")

    # BSGeometry vtable @ RVA 0x267E0B8 — dump all slots
    log(fh, "\n==== BSGeometry::vtable (RVA 0x267E0B8, 0x14267E0B8) ====")
    vt = 0x14267E0B8
    for i in range(40):
        q = ida_bytes.get_qword(vt + 8 * i)
        if q < 0x140000000 or q > 0x150000000:
            break
        fn = ida_funcs.get_func(q)
        sz = (fn.end_ea - fn.start_ea) if fn else 0
        fname = ida_funcs.get_func_name(q) or "?"
        log(fh, f"  [{i:2d}]  +0x{8*i:03X}  -> 0x{q:X}  RVA=0x{q-imb:X}  size=0x{sz:X}  {fname}")

    # BSGeometry vt[7] is the critical one (+56)
    log(fh, "\n==== BSGeometry::vt[7] decomp (phase-dispatch shape method) ====")
    vt7 = ida_bytes.get_qword(vt + 8 * 7)
    log(fh, f"  vt[7] -> 0x{vt7:X}  RVA=0x{vt7-imb:X}")
    txt = decomp(vt7)
    if txt:
        for ln in txt.splitlines()[:150]:
            log(fh, f"  {ln}")

    # BSDynamicTriShape vtable (RVA 0x267F948) vt[7]
    log(fh, "\n==== BSDynamicTriShape::vt[7] decomp ====")
    vt = 0x14267F948
    vt7 = ida_bytes.get_qword(vt + 8 * 7)
    log(fh, f"  vt[7] -> 0x{vt7:X}  RVA=0x{vt7-imb:X}")
    txt = decomp(vt7)
    if txt:
        for ln in txt.splitlines()[:150]:
            log(fh, f"  {ln}")

    # Scan for BSSkinnedTriShape
    log(fh, "\n==== BSSkinnedTriShape RTTI search ====")
    # pattern .?AVBSSkinnedTriShape@@
    seg_start, seg_end = 0x142000000, 0x144200000
    needle = b".?AVBSSkinnedTriShape@@"
    found = []
    # scan in chunks
    chunk = 0x100000
    base = seg_start
    while base < seg_end:
        data = ida_bytes.get_bytes(base, min(chunk, seg_end - base))
        if data:
            idx = 0
            while True:
                idx = data.find(needle, idx)
                if idx < 0:
                    break
                found.append(base + idx)
                idx += 1
        base += chunk
    log(fh, f"  found RTTI string at: {[hex(x) for x in found[:4]]}")
    if found:
        tdb = found[0] - 0x10
        log(fh, f"  typedesc @ 0x{tdb:X}  RVA=0x{tdb-imb:X}")

    log(fh, "\n==== sub_140C38F80 caller of sub_140C38910 ====")
    # We want to see what sub_140C38910 returns to — confirm its xref chain
    for xr in idautils.XrefsTo(0x140C38910, 0):
        fn = ida_funcs.get_func(xr.frm)
        if fn:
            log(fh, f"  from 0x{xr.frm:X}  func=0x{fn.start_ea:X}  RVA=0x{fn.start_ea-imb:X}")

    # also try to find "Opaque" strings
    log(fh, "\n==== Search for render-phase strings (Opaque / ShadowMap / PostProcess) ====")
    seg_start, seg_end = 0x142000000, 0x144200000
    for needle in [b"Opaque", b"OPAQUE", b"ShadowMap", b"PrePass", b"PreZPass", b"BeginRender",
                   b"EndRender", b"RenderPass", b"SubmitScene", b"RenderMain", b"RenderHook",
                   b"RenderFrame"]:
        base = seg_start
        count = 0
        while base < seg_end:
            data = ida_bytes.get_bytes(base, min(0x100000, seg_end - base))
            if data:
                idx = 0
                while True:
                    idx = data.find(needle, idx)
                    if idx < 0:
                        break
                    ea = base + idx
                    # print the full string at that ea
                    s = idc.get_strlit_contents(ea) or b""
                    try:
                        ss = s.decode('utf-8', errors='ignore')
                    except Exception:
                        ss = "<?>"
                    log(fh, f"  {needle.decode():10s}  @ 0x{ea:X}  full={ss!r}")
                    idx += 1
                    count += 1
                    if count >= 3:
                        break
            if count >= 3:
                break
            base += 0x100000

    log(fh, "\n==== DONE ====")
    fh.close()
    ida_pro.qexit(0)

main()
