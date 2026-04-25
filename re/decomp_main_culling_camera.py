"""
decomp_main_culling_camera.py

Goal: find the MainCullingCamera singleton + trace how it gets populated
with a NiCamera (so we can read its +288 matrix = true scene VP).

Strategy:
 1. Find xrefs to MainCullingCamera vtable @ RVA 0x255DB08 — these are
    instance ctors (or sites that bind the vtable).
 2. For each ctor, decompile: where does it allocate + store a NiCamera*?
 3. Find where the MainCullingCamera instance is stored globally —
    look for 'mov qword [rip+GLOBAL], rax' right after an allocator call
    inside the ctor or its callers.
 4. Try alternative approach: look for string 'MainCullingCamera' xrefs —
    the engine often labels its singletons.

Also dumps:
 - BSShaderAccumulator vtable (Agent 4 report: RVA 0x290A6B0) slot
   names — one of them is SetCamera / SetCameraData.

Output: re/main_culling_camera_report.txt
"""
import ida_auto, ida_bytes, ida_funcs, ida_hexrays, ida_nalt, ida_name
import ida_segment, ida_ua
import idautils, idc

OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\main_culling_camera_report.txt"

MAIN_CULLING_CAMERA_VTBL_RVA  = 0x255DB08
NI_CAMERA_VTBL_RVA            = 0x267DD50
BS_SHADER_ACCUMULATOR_VTBL_RVA = 0x290A6B0

def image_base():
    return ida_nalt.get_imagebase()

def ea2rva(ea):
    return ea - image_base()

def rva2ea(rva):
    return image_base() + rva

def log(msg, fh):
    print(msg)
    fh.write(msg + "\n")
    fh.flush()

def decomp(ea, fh, header, max_chars=6000):
    fn = ida_funcs.get_func(ea)
    if not fn:
        log(f"[!] no func at 0x{ea:X} ({header})", fh)
        return None
    log(f"\n======== {header}  RVA 0x{ea2rva(fn.start_ea):X}  ========", fh)
    try:
        cf = ida_hexrays.decompile(fn.start_ea)
        if cf is None:
            log("   decomp = None", fh)
            return fn.start_ea
        src = str(cf)
        if len(src) > max_chars:
            src = src[:max_chars] + f"\n... (truncated, total {len(src)} chars)"
        log(src, fh)
        return fn.start_ea
    except Exception as e:
        log(f"   exception: {e}", fh)
        return None

def dump_vtable(vt_rva, label, fh, n_slots=35):
    log(f"\n---- VTBL {label} @ RVA 0x{vt_rva:X} ----", fh)
    ea = rva2ea(vt_rva)
    for i in range(n_slots):
        ptr = ida_bytes.get_qword(ea + i*8)
        if ptr == 0 or ptr == idc.BADADDR:
            log(f"  [{i:2}] 0x0 (end)", fh)
            break
        fn = ida_funcs.get_func(ptr)
        name = ida_funcs.get_func_name(fn.start_ea) if fn else \
               ida_name.get_ea_name(ptr, ida_name.GN_VISIBLE)
        log(f"  [{i:2}] -> 0x{ptr:X} (RVA 0x{ea2rva(ptr):X})  {name or '?'}", fh)

def find_xrefs_to_vtable(vt_rva, label, fh, max_show=30):
    log(f"\n-- xrefs TO {label} vtable @ RVA 0x{vt_rva:X} --", fh)
    vt_ea = rva2ea(vt_rva)
    funcs = set()
    for x in idautils.XrefsTo(vt_ea, 0):
        fn = ida_funcs.get_func(x.frm)
        if fn:
            funcs.add(fn.start_ea)
    funcs = sorted(funcs)
    log(f"   unique functions: {len(funcs)}", fh)
    for i, fea in enumerate(funcs[:max_show]):
        fn_name = ida_funcs.get_func_name(fea) or "?"
        log(f"     [{i}] 0x{fea:X} RVA 0x{ea2rva(fea):X}  {fn_name}", fh)
    return funcs

def search_string_xrefs(target_str, fh, max_show=12):
    """Find all strings matching target_str, then find xrefs to them."""
    log(f"\n-- search for string '{target_str}' --", fh)
    # iterate strings in the binary
    matches = []
    for s in idautils.Strings():
        try:
            text = str(s)
        except Exception:
            continue
        if target_str in text:
            matches.append((s.ea, text))
    log(f"   matches: {len(matches)}", fh)
    for (ea, text) in matches[:max_show]:
        log(f"     str @ 0x{ea:X} (RVA 0x{ea2rva(ea):X}): {text[:80]!r}", fh)
        # dump xrefs TO this string
        for x in idautils.XrefsTo(ea, 0):
            fn = ida_funcs.get_func(x.frm)
            fn_name = ida_funcs.get_func_name(fn.start_ea) if fn else "?"
            log(f"       from 0x{x.frm:X}  in {fn_name} (RVA 0x{ea2rva(fn.start_ea) if fn else 0:X})", fh)

def main():
    ida_auto.auto_wait()
    with open(OUT, "w", encoding="utf-8") as fh:
        log(f"image base: 0x{image_base():X}", fh)

        # 1. dump the MainCullingCamera vtable for its method names
        dump_vtable(MAIN_CULLING_CAMERA_VTBL_RVA, "MainCullingCamera", fh, n_slots=35)

        # 2. find ctors / bind-sites via xrefs to its vtable
        ctors = find_xrefs_to_vtable(
            MAIN_CULLING_CAMERA_VTBL_RVA, "MainCullingCamera", fh)

        # 3. decompile each ctor candidate - look for singleton store patterns
        for i, c in enumerate(ctors[:3]):
            decomp(c, fh, f"MainCullingCamera ctor / binder #{i}",
                   max_chars=7000)

        # 4. string search for 'MainCullingCamera' / 'MainCulling'
        search_string_xrefs("MainCullingCamera", fh)
        search_string_xrefs("MainCulling", fh)
        search_string_xrefs("CullingCamera", fh)

        # 5. also look at BSShaderAccumulator vtable (Agent 4's scene-camera setter)
        dump_vtable(BS_SHADER_ACCUMULATOR_VTBL_RVA, "BSShaderAccumulator",
                    fh, n_slots=30)

        log("\n==== Done ====", fh)

main()
