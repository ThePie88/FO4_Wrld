"""
decomp_camera.py  —  RE pass: PlayerCamera, TESCamera, NiCamera, state classes.

Goals:
 1) Confirm PlayerCamera singleton RVA (binary analysis said 0x30DBD58 via VA 0x1430DBD58).
 2) Dump decomp of:
    - PlayerCamera ctor at RVA 0x1024A80 (approximate — scanner says ~0x1024A4C prologue)
    - GetPlayerCamera (callers of the singleton read) — pick a small one
    - PlayerCamera::Update / OnFrame / equivalent (vtable[N])
    - TESCamera::Update (TESCamera vtable at RVA 0x2519158)
    - NiCamera::UpdateViewProjection-ish methods (NiCamera vtable at RVA 0x267DD50)
 3) Dump the PlayerCamera primary vtable (RVA 0x25A25D8) and NiCamera vtable (0x267DD50)
    with symbol names next to each slot.
 4) Find the member offset inside PlayerCamera that points to a NiCamera — critical for
    reading view/proj matrices in the DLL hook.
 5) List all globals in .data that the PlayerCamera ctor stores into (near the singleton).

Output:  re/camera_report.txt  (not to be confused with the hand-written summary
                                camera_report.txt the user's agent produces).
Run in IDA:   File > Script file  ->  decomp_camera.py
"""
import ida_auto, ida_bytes, ida_funcs, ida_hexrays, ida_nalt, ida_name, ida_segment, ida_ua
import idautils, idc, ida_pro

OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\camera_decomp_report.txt"

# Known constants from binary-level analysis already done outside IDA.
PLAYER_CAMERA_SINGLETON_RVA = 0x30DBD58           # VA 0x1430DBD58
PLAYER_CAMERA_CTOR_RVA      = 0x1024A80           # approximate; scanner saw prologue @0x1024A4C
PLAYER_CAMERA_VTABLE_RVA    = 0x25A25D8           # primary vtable
PLAYER_CAMERA_SUB_VTABLES   = [0x25A2600, 0x25A2610, 0x25A2628, 0x25A2640]
TES_CAMERA_VTABLE_RVA       = 0x2519158
THIRD_PERSON_STATE_VTABLE   = 0x251AA18
FIRST_PERSON_STATE_VTABLE   = 0x25A2A08
FREE_CAMERA_STATE_VTABLE    = 0x25A26E8
VATS_CAMERA_STATE_VTABLE    = 0x25A32A8
NI_CAMERA_VTABLE_RVA        = 0x267DD50
MAIN_CULLING_CAMERA_VTABLE  = 0x255DB08
BS_FRUSTUM_FOV_CTRL_VTABLE  = 0x268BF38

# A few callers of the PlayerCamera singleton (read via 'mov rcx, [rip+disp]'):
# from binary analysis — first 20 load sites:
SINGLETON_CONSUMERS_RVAS = [
    0x22D371, 0x395D8E, 0x395DBD, 0x395DCF, 0x3A19FF, 0x3A1B6C,
    0x413927, 0x415748, 0x4422F0, 0x44CC31, 0x4796AB, 0x4B08F9,
    0x4FEE77, 0x4FEEA4, 0x4FF0F8, 0x5142BA, 0x5813D7, 0x58143C,
    0x581BB3, 0x5A305A,
]


def log(msg, fh):
    print(msg)
    fh.write(msg + "\n")
    fh.flush()


def image_base():
    return ida_nalt.get_imagebase()


def rva2ea(rva):
    return image_base() + rva


def ea2rva(ea):
    return ea - image_base()


def safe_func_name(ea):
    fn = ida_funcs.get_func(ea)
    if not fn:
        return "?"
    return ida_funcs.get_func_name(fn.start_ea)


def decompile_dump(ea, fh, max_chars=8000, header=""):
    fn = ida_funcs.get_func(ea)
    if not fn:
        log(f"[-] {header}: no function at 0x{ea:X}", fh)
        return None
    log(f"\n======== {header} func_start=0x{fn.start_ea:X} (RVA 0x{ea2rva(fn.start_ea):X}) ========", fh)
    try:
        cf = ida_hexrays.decompile(fn.start_ea)
        if cf is None:
            log("  decompile returned None", fh)
            return fn.start_ea
        src = str(cf)
        if len(src) > max_chars:
            log(src[:max_chars] + f"\n... (truncated, total {len(src)} chars)", fh)
        else:
            log(src, fh)
        return fn.start_ea
    except Exception as e:
        log(f"  decompile exception: {e}", fh)
        return None


def dump_vtable(vt_rva, label, fh, n_slots=40):
    log(f"\n---- VTABLE {label} @ RVA 0x{vt_rva:X} ----", fh)
    ea = rva2ea(vt_rva)
    for i in range(n_slots):
        ptr = ida_bytes.get_qword(ea + i*8)
        if ptr == 0 or ptr == idc.BADADDR:
            log(f"  [{i:2}] 0x0 (end)", fh)
            break
        # is it pointing to code?
        fn = ida_funcs.get_func(ptr)
        name = ida_funcs.get_func_name(fn.start_ea) if fn else ida_name.get_ea_name(ptr, ida_name.GN_VISIBLE)
        if not name:
            name = "?"
        log(f"  [{i:2}] -> 0x{ptr:X} (RVA 0x{ea2rva(ptr):X})  {name}", fh)


def list_xrefs_short(ea, label, fh, max_items=10):
    log(f"\n-- xrefs TO {label} @ 0x{ea:X} (RVA 0x{ea2rva(ea):X}) --", fh)
    xr = list(idautils.XrefsTo(ea, 0))
    log(f"   total: {len(xr)}", fh)
    for i, x in enumerate(xr[:max_items]):
        fn = ida_funcs.get_func(x.frm)
        fname = ida_funcs.get_func_name(fn.start_ea) if fn else "?"
        log(f"     from 0x{x.frm:X}  RVA 0x{ea2rva(x.frm):X}  func={fname}", fh)


def scan_for_nicamera_member_offset(player_camera_ctor_ea, fh):
    """
    Walk the PlayerCamera ctor and list every store into [r14+disp] (this+disp)
    and every call to a sub-ctor. Goal: find which offset gets the NiCamera*
    (discovered by the call target address matching NiCamera ctor, or a
     'mov [r14+X], rax' right after 'call NiCamera_ctor').
    """
    log(f"\n-- walking PlayerCamera ctor near 0x{player_camera_ctor_ea:X} --", fh)
    fn = ida_funcs.get_func(player_camera_ctor_ea)
    if not fn:
        log("   no function", fh)
        return
    ea = fn.start_ea
    end = fn.end_ea
    calls = []
    stores = []
    while ea < end:
        insn = ida_ua.insn_t()
        sz = ida_ua.decode_insn(insn, ea)
        if sz <= 0:
            ea += 1
            continue
        mnem = idc.print_insn_mnem(ea)
        if mnem == "call":
            target = idc.get_operand_value(ea, 0)
            tname = ida_funcs.get_func_name(target) if target else "?"
            calls.append((ea, target, tname))
        if mnem == "mov":
            # Look for  mov [r14+imm], reg  (r14 is 'this' in this ctor based on pattern)
            op0 = idc.print_operand(ea, 0)
            op1 = idc.print_operand(ea, 1)
            if "r14+" in op0 or "r14]" in op0:
                stores.append((ea, op0, op1))
        ea += sz
    log(f"   calls from ctor: {len(calls)}", fh)
    for cea, t, n in calls[:30]:
        log(f"     0x{cea:X}  call  0x{t:X}  ({n})", fh)
    log(f"   stores into [r14+...]: {len(stores)}", fh)
    for sea, o0, o1 in stores[:40]:
        log(f"     0x{sea:X}  mov {o0}, {o1}", fh)


def main():
    fh = open(OUT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] Hex-Rays plugin not available", fh)
        fh.close()
        ida_pro.qexit(2)
        return

    ib = image_base()
    log(f"[+] Image base 0x{ib:X}", fh)

    # --- Confirm singleton
    singleton_ea = rva2ea(PLAYER_CAMERA_SINGLETON_RVA)
    log(f"\n==== PlayerCamera singleton @ 0x{singleton_ea:X} ====", fh)
    try:
        val = ida_bytes.get_qword(singleton_ea)
        log(f"   runtime value (will be 0 offline): 0x{val:X}", fh)
    except Exception:
        pass
    list_xrefs_short(singleton_ea, "PlayerCamera singleton", fh, 40)

    # --- Decomp PlayerCamera ctor
    # Walk back from 0x1024A4C prologue — let IDA resolve function bounds.
    ctor_ea = rva2ea(PLAYER_CAMERA_CTOR_RVA)
    # Actually fn start is a bit earlier. Find the function containing 0x1024A8C (vtable store site).
    anchor_ea = rva2ea(0x1024A8C)
    fn = ida_funcs.get_func(anchor_ea)
    if fn:
        log(f"[+] PlayerCamera ctor resolved: 0x{fn.start_ea:X}", fh)
        decompile_dump(fn.start_ea, fh, header="PlayerCamera::ctor", max_chars=12000)
        scan_for_nicamera_member_offset(fn.start_ea, fh)
    else:
        log("[-] PlayerCamera ctor: IDA has no function at anchor", fh)

    # --- Vtables
    dump_vtable(PLAYER_CAMERA_VTABLE_RVA, "PlayerCamera primary", fh, 30)
    for i, v in enumerate(PLAYER_CAMERA_SUB_VTABLES):
        dump_vtable(v, f"PlayerCamera sub[{i}]", fh, 6)
    dump_vtable(TES_CAMERA_VTABLE_RVA, "TESCamera", fh, 6)
    dump_vtable(THIRD_PERSON_STATE_VTABLE, "ThirdPersonState", fh, 30)
    dump_vtable(FIRST_PERSON_STATE_VTABLE, "FirstPersonState", fh, 30)
    dump_vtable(FREE_CAMERA_STATE_VTABLE, "FreeCameraState", fh, 30)
    dump_vtable(VATS_CAMERA_STATE_VTABLE, "VATSCameraState", fh, 30)
    dump_vtable(NI_CAMERA_VTABLE_RVA, "NiCamera", fh, 36)
    dump_vtable(MAIN_CULLING_CAMERA_VTABLE, "MainCullingCamera", fh, 12)
    dump_vtable(BS_FRUSTUM_FOV_CTRL_VTABLE, "BSFrustumFOVController", fh, 12)

    # --- Decomp a handful of PlayerCamera methods from vtable (virtuals)
    primary_vt_ea = rva2ea(PLAYER_CAMERA_VTABLE_RVA)
    log(f"\n==== PlayerCamera virtual methods (primary vtable) ====", fh)
    for slot in range(0, 16):
        ptr = ida_bytes.get_qword(primary_vt_ea + slot*8)
        if not ptr or ptr == idc.BADADDR:
            continue
        fn = ida_funcs.get_func(ptr)
        if not fn:
            continue
        # Only decompile small functions (Update, GetState, etc.)
        size = fn.end_ea - fn.start_ea
        if size > 0x300:
            # still dump but truncated
            decompile_dump(fn.start_ea, fh,
                           header=f"PlayerCamera::vtable[{slot}] (large {size} bytes)",
                           max_chars=2000)
        else:
            decompile_dump(fn.start_ea, fh,
                           header=f"PlayerCamera::vtable[{slot}]",
                           max_chars=3000)

    # --- Decomp NiCamera methods - last 6 slots (they're the camera-specific overrides)
    ni_vt_ea = rva2ea(NI_CAMERA_VTABLE_RVA)
    log(f"\n==== NiCamera virtual methods (overrides at end of vtable) ====", fh)
    for slot in range(26, 36):
        ptr = ida_bytes.get_qword(ni_vt_ea + slot*8)
        if not ptr or ptr == idc.BADADDR:
            continue
        fn = ida_funcs.get_func(ptr)
        if not fn: continue
        decompile_dump(fn.start_ea, fh,
                       header=f"NiCamera::vtable[{slot}]",
                       max_chars=4000)

    # --- Small consumer functions that use the singleton
    log(f"\n==== Sample consumers of PlayerCamera singleton ====", fh)
    for rva in SINGLETON_CONSUMERS_RVAS[:10]:
        ea = rva2ea(rva)
        fn = ida_funcs.get_func(ea)
        if not fn:
            continue
        size = fn.end_ea - fn.start_ea
        if 0x20 < size < 0x180:
            decompile_dump(fn.start_ea, fh, header=f"PlayerCamera consumer @RVA 0x{rva:X} (size {size})", max_chars=2500)

    # --- Also examine the int32 global the ctor reads at RVA 0x30DA180 (some flag/default)
    flag_ea = rva2ea(0x30DA180)
    log(f"\n==== Adjacent global read in ctor: RVA 0x30DA180 ====", fh)
    val = ida_bytes.get_dword(flag_ea)
    log(f"   dword value: 0x{val:X}", fh)
    list_xrefs_short(flag_ea, "0x30DA180 (ctor-read int)", fh, 20)

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
