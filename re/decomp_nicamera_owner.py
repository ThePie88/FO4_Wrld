"""
decomp_nicamera_owner.py

Goal: resolve the 3 outstanding offsets blocking FoM-lite matrix capture:
  OFF_NICAM  — offset of NiCamera* inside a TESCameraState subclass
  OFF_VIEW   — offset of 4x4 view (or view-proj) matrix inside NiCamera
  OFF_PROJ   — offset of 4x4 proj matrix inside NiCamera

Strategy:
 1. Find NiCamera's ctor: the function that stores `lea rax,[rip+NI_CAM_VTBL]`
    then `mov [this/rcx], rax` at entry. Xrefs TO NI_CAM_VTBL give us the
    ctor address directly.
 2. Dump NiCamera ctor in full — we see the init pattern for all members,
    which tells us where view/proj/frustum live.
 3. Find xrefs TO the NiCamera ctor — these are the callers (TESCameraState
    subclass ctors or factory functions) that instantiate a NiCamera.
 4. Decompile a few of those callers — look for pattern
       call <NiCamera_ctor> ; mov [r1?+Y], rax
    Y is OFF_NICAM.
 5. Dump vtable[24..35] of NiCamera — typically Update/SetViewport/SetFrustum
    which reveal view/proj access patterns.

Output: re/nicamera_owner_report.txt
Run in IDA 9.3 via  idat -A -S<path> -L<log> <i64>
"""
import ida_auto, ida_bytes, ida_funcs, ida_hexrays, ida_nalt, ida_name
import ida_segment, ida_ua
import idautils, idc

OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\nicamera_owner_report.txt"

NI_CAMERA_VTBL_RVA = 0x267DD50

def log(msg, fh):
    print(msg)
    fh.write(msg + "\n")
    fh.flush()

def image_base():
    return ida_nalt.get_imagebase()

def ea2rva(ea):
    return ea - image_base()

def rva2ea(rva):
    return image_base() + rva

def decomp(ea, fh, header, max_chars=6000):
    fn = ida_funcs.get_func(ea)
    if not fn:
        log(f"[!] no func at 0x{ea:X} ({header})", fh)
        return None
    log(f"\n======== {header}  RVA 0x{ea2rva(fn.start_ea):X}  ========", fh)
    try:
        cf = ida_hexrays.decompile(fn.start_ea)
        if cf is None:
            log("   decompile returned None", fh)
            return fn.start_ea
        src = str(cf)
        if len(src) > max_chars:
            src = src[:max_chars] + f"\n... (truncated, total {len(src)} chars)"
        log(src, fh)
        return fn.start_ea
    except Exception as e:
        log(f"   exception: {e}", fh)
        return None

def find_ctors_via_vtable_write(vtbl_ea, label, fh):
    """Find every function that writes this vtable via lea+mov pattern.
    Returns list of ctor EAs."""
    log(f"\n-- searching xrefs TO VTBL {label} @ 0x{vtbl_ea:X} --", fh)
    ctors = set()
    for x in idautils.XrefsTo(vtbl_ea, 0):
        fn = ida_funcs.get_func(x.frm)
        if fn:
            ctors.add(fn.start_ea)
        log(f"   from 0x{x.frm:X} (func start 0x{fn.start_ea:X})" if fn else
            f"   from 0x{x.frm:X} (NO FUNC)", fh)
    log(f"   unique ctor-candidate funcs: {len(ctors)}", fh)
    return sorted(ctors)

def find_callers_of(callee_ea, label, fh, max_show=20):
    """Find callers of a given function."""
    log(f"\n-- callers of {label} @ 0x{callee_ea:X} --", fh)
    callers = set()
    for x in idautils.XrefsTo(callee_ea, 0):
        if idc.print_insn_mnem(x.frm) == "call":
            fn = ida_funcs.get_func(x.frm)
            if fn:
                callers.add((fn.start_ea, x.frm))
    callers = sorted(callers)
    log(f"   {len(callers)} call sites", fh)
    for fn_ea, call_ea in callers[:max_show]:
        log(f"     call_site 0x{call_ea:X}  in func 0x{fn_ea:X}", fh)
    return callers

def scan_mov_this_offset_after_call(call_ea, fh, max_insn_look=12):
    """After a `call X` instruction, look at the next few instructions
    for `mov [reg+disp], rax` — reg likely being the `this` register of
    the caller. Returns the first such disp found."""
    ea = call_ea
    sz = ida_ua.decode_insn(ida_ua.insn_t(), ea)
    if sz <= 0:
        return None
    ea += sz
    for _ in range(max_insn_look):
        insn = ida_ua.insn_t()
        sz = ida_ua.decode_insn(insn, ea)
        if sz <= 0:
            break
        mnem = idc.print_insn_mnem(ea)
        if mnem == "mov":
            op0 = idc.print_operand(ea, 0)
            op1 = idc.print_operand(ea, 1)
            if op1.strip() == "rax" and "+" in op0 and "[" in op0:
                return (ea, op0, op1)
        ea += sz
    return None

def main():
    ida_auto.auto_wait()
    with open(OUT, "w", encoding="utf-8") as fh:
        log(f"image base: 0x{image_base():X}", fh)

        vtbl_ea = rva2ea(NI_CAMERA_VTBL_RVA)
        ctors = find_ctors_via_vtable_write(vtbl_ea, "NiCamera", fh)

        # Usually the real ctor is the smallest-by-size xref writer.
        # But we'll just dump them all up to 3.
        for i, c in enumerate(ctors[:3]):
            decomp(c, fh, f"NiCamera ctor candidate #{i}", max_chars=8000)

        # Find callers of the first (= biggest likely) ctor. These should
        # be TESCameraState subclass ctors.
        if ctors:
            primary = ctors[0]
            callers = find_callers_of(primary, "NiCamera ctor (primary)", fh, max_show=10)
            # First: summary of mov-after-call for ALL callers (fast, no decomp)
            log(f"\n==== mov-after-call summary for ALL {len(callers)} callers ====", fh)
            for (fn_ea, call_ea) in callers:
                res = scan_mov_this_offset_after_call(call_ea, fh)
                if res:
                    log(f"   caller 0x{fn_ea:X}: mov {res[1]} = rax  @ 0x{res[0]:X}", fh)
                else:
                    log(f"   caller 0x{fn_ea:X}: (no mov-after-call in window)", fh)
            # Then decomp top 5 callers for context
            for (fn_ea, call_ea) in callers[:5]:
                decomp(fn_ea, fh, f"caller of NiCamera ctor (from 0x{call_ea:X})",
                       max_chars=4500)

        # Dump vtable[24..35] of NiCamera for Update / SetViewport /
        # SetFrustum. Names in IDA should be mapped.
        log(f"\n\n==== NiCamera vtable slots 0..35 names ====", fh)
        for i in range(36):
            ptr = ida_bytes.get_qword(vtbl_ea + i*8)
            if ptr == 0 or ptr == idc.BADADDR:
                log(f"  [{i:2}] 0x0 (end)", fh)
                break
            fn = ida_funcs.get_func(ptr)
            name = ida_funcs.get_func_name(fn.start_ea) if fn else \
                   ida_name.get_ea_name(ptr, ida_name.GN_VISIBLE)
            log(f"  [{i:2}] -> 0x{ptr:X} (RVA 0x{ea2rva(ptr):X})  {name or '?'}", fh)

        # Also try to find NiCamera vtable[X] where name contains 'Update' or
        # 'SetViewport' or 'PickPoint' — those touch view/proj matrices.
        log(f"\n==== Searching NiCamera vtable entries that likely touch view/proj ====", fh)
        for i in range(36):
            ptr = ida_bytes.get_qword(vtbl_ea + i*8)
            if ptr == 0:
                break
            fn = ida_funcs.get_func(ptr)
            if not fn:
                continue
            name = ida_funcs.get_func_name(fn.start_ea) or ""
            if any(kw in name.lower() for kw in ("update", "view", "proj",
                                                  "frustum", "pickpoint",
                                                  "setscreen", "setview")):
                decomp(fn.start_ea, fh,
                       f"NiCamera::vtable[{i}] (match: {name})",
                       max_chars=5000)

        # Finally: find the NiCamera world-viewproj method by looking for
        # functions that read [rcx+288] then do something heavy (since
        # our clone dumped shows +288..+352 is a 64-byte matrix).
        log(f"\n==== Done ====", fh)

main()
