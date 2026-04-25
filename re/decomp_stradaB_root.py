"""
decomp_stradaB_root.py

Phase 4: Drill into the scene root setup at sub_140C322C0.
  - Decompile sub_140C433A0 (used to ctor the "World" node)
  - Verify what exactly `qword_1432D2228` holds — name, type, vtable
  - Examine full body of NiNode vt58 (AttachChild candidate)
  - Decompile NiNode vt58/59/60 properly
  - Identify the type stored at qword_1432D2228 (look at the vtable that ends
    up in *qword_1432D2228 after ctor)
"""
import ida_auto
import ida_funcs
import ida_nalt
import ida_hexrays
import ida_pro
import ida_bytes
import ida_segment
import idautils
import idc

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\stradaB_root.txt"


def log(fh, msg):
    print(msg)
    fh.write(msg + "\n")
    fh.flush()


def rva(ea):
    return ea - ida_nalt.get_imagebase()


def decomp(ea, fh, label="", max_lines=250):
    log(fh, f"\n-- decomp {label} @ 0x{ea:X} (RVA 0x{rva(ea):X}) --")
    fn = ida_funcs.get_func(ea)
    if not fn:
        log(fh, "  [!] NO FUNC")
        return
    log(fh, f"  size=0x{fn.end_ea - fn.start_ea:X}")
    try:
        cf = ida_hexrays.decompile(ea)
        if cf:
            t = str(cf)
            lines = t.split("\n")
            if len(lines) > max_lines:
                lines = lines[:max_lines] + [f"  ... (truncated, {len(t.split(chr(10)))} total)"]
            log(fh, "\n".join(lines))
    except Exception as e:
        log(fh, f"  [!] decompile failed: {e}")


def scan_qword_writes(global_ea):
    seg = ida_segment.get_segm_by_name(".text")
    if not seg:
        return []
    out = []
    ea = seg.start_ea
    end = seg.end_ea
    while ea < end - 8:
        try:
            if ida_bytes.get_byte(ea) == 0x48 and ida_bytes.get_byte(ea+1) == 0x89:
                mr = ida_bytes.get_byte(ea+2)
                if (mr & 0xC7) == 0x05:
                    disp = ida_bytes.get_dword(ea+3)
                    if disp & 0x80000000:
                        disp -= 0x100000000
                    target = ea + 7 + disp
                    if target == global_ea:
                        fn = ida_funcs.get_func(ea)
                        out.append((ea, fn.start_ea if fn else 0))
        except Exception:
            pass
        ea += 1
    return out


def scan_qword_reads(global_ea):
    """mov rcx, [global]  or  mov rax, [global]"""
    seg = ida_segment.get_segm_by_name(".text")
    if not seg:
        return []
    out = []
    ea = seg.start_ea
    end = seg.end_ea
    while ea < end - 8:
        try:
            if ida_bytes.get_byte(ea) == 0x48 and ida_bytes.get_byte(ea+1) == 0x8B:
                mr = ida_bytes.get_byte(ea+2)
                if (mr & 0xC7) == 0x05:
                    disp = ida_bytes.get_dword(ea+3)
                    if disp & 0x80000000:
                        disp -= 0x100000000
                    target = ea + 7 + disp
                    if target == global_ea:
                        fn = ida_funcs.get_func(ea)
                        out.append((ea, fn.start_ea if fn else 0))
        except Exception:
            pass
        ea += 1
    return out


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    log(fh, "==== Strada B — scene root structure ====")
    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()
    log(fh, f"image base = 0x{ida_nalt.get_imagebase():X}")

    # Decompile the "World" ctor helper
    log(fh, "\n==== sub_140C433A0 — construct 'World' scene root ====")
    decomp(0x140C433A0, fh, "world_ctor sub_140C433A0", max_lines=150)

    # The full renderer init
    log(fh, "\n\n==== Renderer init sub_140C322C0 (full) ====")
    decomp(0x140C322C0, fh, "renderer_init sub_140C322C0", max_lines=500)

    # NiNode vt58 (AttachChild candidate) — full
    log(fh, "\n\n==== NiNode vt58 full body (AttachChild?) ====")
    decomp(0x1416BE170, fh, "NiNode vt58 sub_1416BE170", max_lines=180)

    # NiNode vt59, vt60 — siblings
    log(fh, "\n==== NiNode vt59 ====")
    decomp(0x1416BE2B0, fh, "NiNode vt59 sub_1416BE2B0", max_lines=100)
    log(fh, "\n==== NiNode vt60 ====")
    decomp(0x1416BE390, fh, "NiNode vt60 sub_1416BE390", max_lines=100)

    # Analyze qword_1432D2228 (scene root global)
    log(fh, "\n\n==== qword_1432D2228 (scene root 'World') ====")
    w = scan_qword_writes(0x1432D2228)
    log(fh, f"  writers: {len(w)}")
    for ins, fn in w[:20]:
        nm = ida_funcs.get_func_name(fn) or "?"
        log(fh, f"    write ins 0x{ins:X} in func 0x{fn:X} (RVA 0x{rva(fn):X}) {nm}")
    r = scan_qword_reads(0x1432D2228)
    log(fh, f"  readers: {len(r)}")
    for ins, fn in r[:30]:
        nm = ida_funcs.get_func_name(fn) or "?"
        log(fh, f"    read  ins 0x{ins:X} in func 0x{fn:X} (RVA 0x{rva(fn):X}) {nm}")

    # Analyze qword_143E47A10 (ShadowSceneNode global)
    log(fh, "\n\n==== qword_143E47A10 (ShadowSceneNode link) ====")
    w = scan_qword_writes(0x143E47A10)
    log(fh, f"  writers: {len(w)}")
    for ins, fn in w[:20]:
        nm = ida_funcs.get_func_name(fn) or "?"
        log(fh, f"    write ins 0x{ins:X} in func 0x{fn:X} (RVA 0x{rva(fn):X}) {nm}")
    r = scan_qword_reads(0x143E47A10)
    log(fh, f"  readers (first 30): {len(r)}")
    for ins, fn in r[:30]:
        nm = ida_funcs.get_func_name(fn) or "?"
        log(fh, f"    read  ins 0x{ins:X} in func 0x{fn:X} (RVA 0x{rva(fn):X}) {nm}")

    # Examine the vtable offset of the allocated "World" - we know it allocates 0x170 bytes
    # (same as BSTriShape) and calls sub_140C433A0. Let's see what vtable it sets.
    # Candidate class: might be a subclass like SceneGraph or NiNode with extra flags.
    log(fh, "\n\n==== sub_140C433A0 xrefs ====")
    for xr in list(idautils.XrefsTo(0x140C433A0, 0))[:20]:
        fn = ida_funcs.get_func(xr.frm)
        log(fh, f"  from 0x{xr.frm:X} in func 0x{fn.start_ea if fn else 0:X}")

    # Check vtable at offset +320 of "World" — this is where SSN is stored.
    # This confirms *World is a NiCamera-like struct. Let me see member layout.
    # From renderer init: *(QWORD*)(qword_1432D2228 + 320) = SSN
    # Also: qword_143E47A10 = *(QWORD*)(qword_1432D2228 + 320)
    # So +320 holds SSN.
    # Total size 0x170 = 368 — where NiCamera sizeof = 0x1A0 = 416. So it's NOT NiCamera.
    # Our prior memory: NiCamera RVA 0x267DD50, sizeof 0x1A0.
    # This 0x170 allocation returns obj whose v4[...] layout shows:
    #   +320 = SSN ptr
    #   +388 = xmmword_142F8C4F8 (16-byte OWORD — likely a Vector4 or a quaternion?)
    # Actually looking at sub_1416D0510 @ 0x1080230 ... that's a NiCamera! size=0x1A0.
    # So sub_140C322C0 allocates 0x170 and calls sub_140C433A0. Size 0x170 = BSTriShape OR
    # something else. Let me decompile sub_140C433A0.

    log(fh, "\n\n==== Renderer-specific scene node ctor ====")
    decomp(0x140C433A0, fh, "sub_140C433A0 (scene root ctor)", max_lines=200)

    # NiNode::ctor actual sizing — let's look at where the 0x140 alloc really is
    # Known: sub_1416BDEF0 allocates/inits 0x140 but NOT always — it's the
    # param-taking ctor that DOES NOT alloc (reusing `a1`). The REAL NiNode alloc-ctor
    # is `sub_1416BDFE0` (0x8C size, no alloc).
    # The allocating ctor + init is in `sub_1416BF780` (already seen) - fence of 0x140.
    # Let's confirm this path. And see its NAME writing.
    log(fh, "\n==== NiNode alloc-variant sub_1416BDA20 ====")
    # Already have. Let me look at the NAME setter at offset ~0x68 or similar
    decomp(0x1416BCD30, fh, "name_setter sub_1416BCD30 (used by SSN)", max_lines=40)
    decomp(0x14167BDC0, fh, "name_alloc sub_14167BDC0 (?)", max_lines=40)

    log(fh, "\n==== END ====")
    fh.close()
    ida_pro.qexit(0)


main()
