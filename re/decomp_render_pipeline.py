"""
decomp_render_pipeline.py
Finish the RE of the render pipeline.
Needed:
  - BSShaderAccumulator vtable contents -> AddShape / per-pass methods
  - BSBatchRenderer string location + vtable
  - The phase dispatcher (sub_141A815B0 family): what are phase codes 1,2,5,6?
  - The callers of sub_140C32D30 (RenderDispatch_1) to find the caller chain
    from the main loop all the way down.
  - What thread executes sub_140C32D30? (trace to CreateThread/job-list init)
  - The callers of sub_140C37D20 (scene submit)
"""
import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_nalt
import ida_pro
import ida_segment
import ida_name
import ida_xref
import idc
import idautils

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\render_pipeline_report.txt"

IMAGE_BASE_PROBE = 0x140000000

# From existing reports
BSShaderAccumulator_VT_RVA = 0x290A6B0
BSLightingShader_VT_RVA = 0x290E458
BSShader_VT_RVA = 0x290DBB8

# RenderDispatch chain
SUB_FRAMETICK = 0x140C334B0        # FrameTick
SUB_RENDERDISPATCH_1 = 0x140C32D30 # RenderDispatch_1
SUB_SCENE_SUBMIT = 0x140C37D20     # scene submit
SUB_PHASE1 = 0x141A815B0           # phase 1 (opaque-ish) - passes 1 to vt[56]
SUB_PHASE2 = 0x141A81BB0           # phase 2 - passes 2 to vt[56]
SUB_PHASE56 = 0x141A81DB0          # phase 5/6 - transparent / post
SUB_MAINRENDER = 0x140BD3F80       # main render job list registrar
SUB_MAINCALLER = 0x140C2FAD0       # framedispatch
SUB_MAINTOP = 0x140C2F3F0          # top trampoline
SUB_MAINRENDERLOOP = 0x140C30FD0   # outermost loop (calls FrameTick)

# CB helpers
CB_MAP_A = 0x21A0680
CB_MAP_B = 0x21A05E0


def log(fh, msg):
    print(msg)
    fh.write(msg + "\n")
    fh.flush()


def rva(ea):
    return ea - ida_nalt.get_imagebase()


def decomp(ea):
    try:
        c = ida_hexrays.decompile(ea)
        if c is None:
            return None
        return str(c)
    except Exception as e:
        return f"<decompile failed: {e}>"


def walk_callers(ea, depth=0, maxdepth=5, seen=None, out=None):
    if seen is None:
        seen = set()
    if out is None:
        out = []
    if ea in seen or depth > maxdepth:
        return out
    seen.add(ea)
    callers = set()
    for x in idautils.XrefsTo(ea, 0):
        caller_fn = ida_funcs.get_func(x.frm)
        if caller_fn:
            callers.add(caller_fn.start_ea)
    for c in callers:
        name = ida_funcs.get_func_name(c) or f"sub_{c:X}"
        out.append((depth, c, name))
        walk_callers(c, depth + 1, maxdepth, seen, out)
    return out


def dump_vtable(fh, vt_rva, name_, max_slots=64):
    vt_ea = vt_rva + ida_nalt.get_imagebase()
    log(fh, f"\n---- VTABLE {name_} @ RVA 0x{vt_rva:X}  ea=0x{vt_ea:X} ----")
    for i in range(max_slots):
        slot = vt_ea + 8 * i
        # stop if this address is no longer in the vtable (xref from below?)
        if i > 0:
            xrefs = list(idautils.XrefsTo(slot, 0))
            if xrefs and any(x.frm < vt_ea for x in xrefs):
                # another vtable begins here
                pass
        q = ida_bytes.get_qword(slot)
        if q == 0:
            break
        name = ida_funcs.get_func_name(q) or ida_name.get_name(q) or "?"
        fn = ida_funcs.get_func(q)
        size = (fn.end_ea - fn.start_ea) if fn else 0
        log(fh, f"  [{i:2d}]  +0x{8*i:03X}  -> 0x{q:X}  RVA=0x{q-ida_nalt.get_imagebase():X}  size=0x{size:X}  {name}")


def find_string(s):
    for ea in idautils.Strings():
        try:
            if str(ea) == s:
                return ea.ea
        except Exception:
            pass
    # Slow fallback
    for ea, sval in [(e.ea, str(e)) for e in idautils.Strings()]:
        if sval == s:
            return ea
    return None


def find_strings_containing(needles):
    hits = {}
    for s in idautils.Strings():
        try:
            sv = str(s)
        except Exception:
            continue
        for n in needles:
            if n in sv:
                hits.setdefault(n, []).append((s.ea, sv))
    return hits


def scan_vtable_range(fh, vt_ea, n=60):
    """Return list of slots (ea,func) until a jump to a negative offset or unknown data."""
    out = []
    for i in range(n):
        slot = vt_ea + 8 * i
        q = ida_bytes.get_qword(slot)
        if q < 0x140000000 or q > 0x150000000:
            break
        out.append((i, slot, q))
    return out


def dump_func_brief(fh, ea, name):
    fn = ida_funcs.get_func(ea)
    if not fn:
        log(fh, f"  [!] {name} @ 0x{ea:X}  NO FUNC")
        return
    log(fh, f"\n  === {name} @ 0x{ea:X}  RVA=0x{rva(ea):X}  size=0x{fn.end_ea-fn.start_ea:X} ===")
    c = decomp(ea)
    if c:
        # first 150 lines
        lines = c.splitlines()
        for ln in lines[:200]:
            log(fh, f"    {ln}")
        if len(lines) > 200:
            log(fh, f"    ... +{len(lines)-200} more lines ...")


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    log(fh, "==== render_pipeline_report ====")
    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()
    imb = ida_nalt.get_imagebase()
    log(fh, f"image base: 0x{imb:X}")

    # =============== 1: BSShaderAccumulator full vtable ===============
    log(fh, "\n====================================================================")
    log(fh, "  1) BSShaderAccumulator VTABLE (slot-by-slot)")
    log(fh, "====================================================================")
    vt_ea = BSShaderAccumulator_VT_RVA + imb
    slots = scan_vtable_range(fh, vt_ea, 80)
    for i, slot_ea, func_ea in slots:
        fn = ida_funcs.get_func(func_ea)
        size = (fn.end_ea - fn.start_ea) if fn else 0
        fname = ida_funcs.get_func_name(func_ea) or "?"
        log(fh, f"  [{i:3d}]  +0x{8*i:03X}  -> 0x{func_ea:X}  RVA=0x{func_ea-imb:X}  size=0x{size:X}  {fname}")

    # =============== 2: Search for BSBatchRenderer / BSShaderManager / ShadowSceneNode ===============
    log(fh, "\n====================================================================")
    log(fh, "  2) BATCH RENDERER / SHADER MANAGER STRING SEARCH")
    log(fh, "====================================================================")
    needles = [
        "BSBatchRenderer", "BSBatch", "BatchRenderer",
        "BSShaderManager", "ShaderManager",
        "BSShadowDirectionalLight", "ShadowSceneNode",
        "Renderer::RenderPass", "Pre Pass",
        "PerFrame", "PerGeometry", "PerMaterial",
        "DFPrePass", "DFLight",
        "OpaqueRender", "Opaque",
        "TransparentRender",
        "DrawPrimitiveNoVB", "DrawPrimitive",
        "BSLight", "BSSDSF",
        "AccumShapes", "AddShape",
        "BSShaderAccumulator", "SetCamera",
        "BSDynamicTriShape",
        "BSSkinnedTriShape",
        "BSGeometry",
    ]
    hits = find_strings_containing(needles)
    for k in needles:
        if k in hits:
            for ea, s in hits[k][:6]:
                log(fh, f"  {k!r:30s} @ 0x{ea:X}  RVA=0x{ea-imb:X}  full={s!r}")
                # callers
                for xr in idautils.XrefsTo(ea, 0):
                    fn = ida_funcs.get_func(xr.frm)
                    if fn:
                        log(fh, f"      xref from 0x{xr.frm:X}  func=0x{fn.start_ea:X} RVA=0x{fn.start_ea-imb:X}")
                    else:
                        log(fh, f"      xref from 0x{xr.frm:X}  NO FUNC")
        else:
            log(fh, f"  [missing] {k!r}")

    # =============== 3: Phase dispatcher deep-dive ===============
    log(fh, "\n====================================================================")
    log(fh, "  3) PHASE DISPATCHER: sub_141A815B0 (phase 1) and siblings")
    log(fh, "====================================================================")
    for ea, label in [
        (SUB_PHASE1, "Phase1 (vt[56] with code 1)"),
        (SUB_PHASE2, "Phase2 (vt[56] with code 2)"),
        (SUB_PHASE56, "Phase5+6 (vt[56] with codes 5 then 6)"),
        (SUB_SCENE_SUBMIT, "Scene Submit trampoline (sub_140C37D20)"),
    ]:
        dump_func_brief(fh, ea, label)

    # =============== 4: Callers of key functions (thread-id trace) ===============
    log(fh, "\n====================================================================")
    log(fh, "  4) CALLER CHAINS (to identify thread ownership)")
    log(fh, "====================================================================")
    for ea, label in [
        (SUB_RENDERDISPATCH_1, "RenderDispatch_1 (sub_140C32D30)"),
        (SUB_FRAMETICK, "FrameTick (sub_140C334B0)"),
        (SUB_SCENE_SUBMIT, "Scene submit (sub_140C37D20)"),
        (SUB_PHASE1, "Phase1 (sub_141A815B0)"),
    ]:
        log(fh, f"\n  -- callers of {label} @ 0x{ea:X} --")
        chain = walk_callers(ea, maxdepth=4)
        for depth, cea, name in chain[:80]:
            indent = "    " * (depth + 1)
            log(fh, f"{indent}{name}  0x{cea:X}  RVA=0x{rva(cea):X}")

    # =============== 5: Scan sub_141A815B0 for known call signatures ===============
    # What is vt[56] on the scene root? sub_141A815B0 calls
    #   (*(... **)(v9 + 56))(v8, 1, v10)  -- vt slot 7 (56/8) on the shape node
    log(fh, "\n====================================================================")
    log(fh, "  5) WHAT IS SCENE-ROOT vtable slot 7 (offset +56)?")
    log(fh, "====================================================================")
    log(fh, "  Phase dispatcher pattern: for each shape S in scene roots { S->vt[7](S, phase_code, arg3) }")
    log(fh, "  That slot is NiObjectNET::Visit(type, arg3) OR a phase switch. ")
    log(fh, "  Caller: sub_141A815B0 line `(*(...**)(v9 + 56))(v8, 1, v10)`")

    # find the vtable of the object passed to vt[56] in sub_141A815B0 — look at ctors that reference qword_1430DD830
    log(fh, "\n  -- xrefs TO qword_1430DD830 (scene root singleton - 'Shader Manager'?) --")
    g = 0x1430DD830
    cnt = 0
    for xr in idautils.XrefsTo(g, 0):
        fn = ida_funcs.get_func(xr.frm)
        if fn:
            log(fh, f"    from 0x{xr.frm:X}  func=0x{fn.start_ea:X}  name={ida_funcs.get_func_name(fn.start_ea)}")
        cnt += 1
        if cnt > 30:
            log(fh, "    (stopped at 30)")
            break

    # =============== 6: CreateThread calls / thread naming ===============
    log(fh, "\n====================================================================")
    log(fh, "  6) RENDER / MAIN THREAD DISCOVERY")
    log(fh, "====================================================================")
    names_to_scan = ["CreateThread", "_beginthreadex", "_beginthread", "SetThreadDescription"]
    for n in names_to_scan:
        ea = ida_name.get_name_ea(ida_nalt.BADADDR, n)
        if ea == ida_nalt.BADADDR:
            continue
        log(fh, f"\n  -- {n} @ 0x{ea:X} --")
        cnt = 0
        for xr in idautils.XrefsTo(ea, 0):
            fn = ida_funcs.get_func(xr.frm)
            if fn:
                log(fh, f"    from 0x{xr.frm:X}  func=0x{fn.start_ea:X}  RVA=0x{rva(fn.start_ea):X}  {ida_funcs.get_func_name(fn.start_ea)}")
            cnt += 1
            if cnt > 40:
                log(fh, "    (stopped at 40)")
                break

    # Thread-name strings
    log(fh, "\n  -- thread name strings (if any) --")
    thread_needles = ["RenderThread", "Render Thread", "Main Thread", "MainThread",
                      "Worker Thread", "JobThread", "Job Thread", "BSThread", "PhysicsThread"]
    thits = find_strings_containing(thread_needles)
    for k, arr in thits.items():
        for ea, s in arr[:3]:
            log(fh, f"    {k!r:20s}  @ 0x{ea:X}  s={s!r}")

    # =============== 7: CB_Map call-site enumeration (confirm DFPrePass hook point) ===============
    log(fh, "\n====================================================================")
    log(fh, "  7) CB-MAP HELPERS (0x21A0680 / 0x21A05E0) CALLER SIGNATURE")
    log(fh, "====================================================================")
    for addr, lab in [(CB_MAP_A + imb, "CB_Map_A"), (CB_MAP_B + imb, "CB_Map_B")]:
        log(fh, f"\n  -- {lab} @ 0x{addr:X} callers (sampling first 12) --")
        cnt = 0
        for xr in idautils.XrefsTo(addr, 0):
            fn = ida_funcs.get_func(xr.frm)
            if fn:
                log(fh, f"    from 0x{xr.frm:X}  func=0x{fn.start_ea:X}  RVA=0x{rva(fn.start_ea):X}")
                cnt += 1
                if cnt >= 12:
                    log(fh, "    (stopped at 12)")
                    break

    log(fh, "\n==== DONE ====")
    fh.close()
    ida_pro.qexit(0)


main()
