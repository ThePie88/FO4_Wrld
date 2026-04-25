"""
decomp_stradaB_layout.py

Phase 2:
  - Decompile ctors of NiNode/NiAVObject/BSGeometry/BSTriShape/BSDynamicTriShape/BSFadeNode.
  - Extract sizeof (from alloc call size arg), member writes (offsets),
    inheritance stacking (which sub-ctor is called first).
  - Decompile vtable[0] (destructor/dtor) & vtable[2] (RTTI name typically).
  - Find AttachChild / DetachChild: scan NiNode vtable slots [0x29..0x35].
  - Find PlayerCamera xrefs to BSFadeNode globals.
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

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\stradaB_layout.txt"


def log(fh, msg):
    print(msg)
    fh.write(msg + "\n")
    fh.flush()


def rva(ea):
    return ea - ida_nalt.get_imagebase()


def decomp(ea, fh, label="", max_lines=220):
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


def dump_vtable(fh, vt_ea, count=60, label=""):
    log(fh, f"\n-- VTABLE {label} @ 0x{vt_ea:X} (RVA 0x{rva(vt_ea):X}) --")
    for i in range(count):
        p = ida_bytes.get_qword(vt_ea + 8*i)
        if p == 0 or p < 0x140000000 or p > 0x145000000:
            log(fh, f"  [{i:3d}] END?  raw=0x{p:X}")
            break
        fn_name = ida_funcs.get_func_name(p) or "?"
        log(fh, f"  [{i:3d}] 0x{p:X}  RVA=0x{rva(p):X}  {fn_name}")


def find_sizeof_from_alloc(fh, ctor_ea):
    """Scan up to 20 instructions before each call inside ctor's CALLER for the alloc
    size-arg pattern. Ctors don't usually allocate; their caller does:
      mov edx, SIZE
      call Allocate(pool, size, align, flags)
    Actually in F4 we see sub_1416579C0(pool, size, align, flags).
    """
    log(fh, f"\n-- sizeof search for ctor 0x{ctor_ea:X} --")
    xrs = list(idautils.XrefsTo(ctor_ea, 0))
    for x in xrs[:6]:
        log(fh, f"  caller @ 0x{x.frm:X} (RVA 0x{rva(x.frm):X})")
        # Scan 200 bytes before call for `mov edx, IMM`
        cur = x.frm - 0x100
        while cur < x.frm:
            try:
                if ida_bytes.get_byte(cur) == 0xBA:  # mov edx, imm32
                    imm = ida_bytes.get_dword(cur+1)
                    if 0x40 <= imm < 0x4000:
                        log(fh, f"    candidate sizeof @ 0x{cur:X}: 0x{imm:X} ({imm})")
            except Exception:
                pass
            cur += 1


def find_string_ea(needle, exact=False):
    hits = []
    for s in idautils.Strings():
        try:
            v = str(s)
        except Exception:
            continue
        if (exact and v == needle) or ((not exact) and needle in v):
            hits.append((s.ea, v))
    return hits


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    log(fh, "==== Strada B — NiNode / BSTriShape layout RE ====")
    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()
    log(fh, f"image base = 0x{ida_nalt.get_imagebase():X}")

    # Known vtables
    VT = {
        "NiRefObject":     0x142462F88,
        "NiAVObject":      0x14267D0C0,
        "NiNode":          0x14267C888,
        "BSFadeNode":      0x1428FA3E8,
        "BSGeometry":      0x14267E0B8,
        "BSTriShape":      0x14267E948,
        "BSDynamicTriShape": 0x14267F948,
        "BSLightingShaderProperty": 0x1428F9FF8,
        "NiAlphaProperty": 0x142474400,
        "ShadowSceneNode": 0x142908F40,
    }
    for name, vt in VT.items():
        dump_vtable(fh, vt, 64, name)

    # Ctors from xrefs-to-vtable (biggest funcs)
    log(fh, "\n\n==== CTOR DECOMP ====")
    CTORS = [
        (0x1416BDA20, "NiNode::ctor (biggest xref)"),
        (0x1416BDEF0, "NiNode::variant2"),
        (0x1416BDFE0, "NiNode::variant3"),
        (0x1416BE080, "NiNode::variant4"),
        (0x1416BF780, "NiNode::variant5"),
        (0x1416BF930, "NiNode::vt0 (dtor?)"),
        (0x1416C7FC0, "NiAVObject::ctor"),
        (0x1416C8CD0, "NiAVObject::variant"),
        (0x1416C8E60, "NiAVObject::vt0 (dtor?)"),
        (0x1416D99E0, "BSTriShape::ctor"),
        (0x1416D9FD0, "BSTriShape::variant"),
        (0x1416DA0A0, "BSTriShape::variant2"),
        (0x1416D4BD0, "BSGeometry::ctor"),
        (0x142174DC0, "BSFadeNode::ctor"),
        (0x142174E60, "BSFadeNode::variant"),
        (0x1421B08A0, "ShadowSceneNode::ctor"),
        (0x1421B0EC0, "ShadowSceneNode::variant"),
    ]
    for ea, lbl in CTORS:
        decomp(ea, fh, lbl, max_lines=100)

    # sizeof hunting
    log(fh, "\n\n==== SIZEOF HUNT (scan callers of ctor for `mov edx, IMM`) ====")
    for ctor, lbl in [
        (0x1416BDA20, "NiNode"),
        (0x1416C7FC0, "NiAVObject"),
        (0x1416D99E0, "BSTriShape"),
        (0x1416D4BD0, "BSGeometry"),
        (0x142174DC0, "BSFadeNode"),
        (0x1421B08A0, "ShadowSceneNode"),
    ]:
        log(fh, f"\n{lbl}:")
        find_sizeof_from_alloc(fh, ctor)

    # Look for AttachChild / DetachChild strings (RTTI or log strings)
    log(fh, "\n\n==== AttachChild / scene-ops string search ====")
    for needle in ["AttachChild", "DetachChild", "SetAt", "AttachAt", "UpdateWorldData", "UpdateNodeBound", "UpdateBound"]:
        log(fh, f"\n-- '{needle}' --")
        hits = find_string_ea(needle, exact=False)
        for ea, v in hits[:10]:
            log(fh, f"  str @ 0x{ea:X}  '{v}'")
            for x in idautils.XrefsTo(ea, 0):
                fn = ida_funcs.get_func(x.frm)
                if fn:
                    log(fh, f"    xref from 0x{x.frm:X} in func 0x{fn.start_ea:X} (RVA 0x{rva(fn.start_ea):X})")

    # Find XrefsTo MemoryManager / NiObject::operator new. CommonLibF4: sub_1416579C0 is "Allocate".
    log(fh, "\n\n==== Allocator sub_1416579C0 info ====")
    decomp(0x1416579C0, fh, "sub_1416579C0 (candidate Allocate)", max_lines=120)
    # callers count
    xc = list(idautils.XrefsTo(0x1416579C0, 0))
    log(fh, f"  callers to 0x1416579C0: {len(xc)}")

    log(fh, "\n==== END ====")
    fh.close()
    ida_pro.qexit(0)


main()
