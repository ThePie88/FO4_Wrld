"""
decomp_stradaB_ops.py

Phase 3:
  - Decompile NiNode vtable entries 26-31 to identify AttachChild/DetachChild/SetAt
  - Decompile NiAVObject vtable entries around UpdateDownwardPass (~slot 33)
  - Find xrefs to "shadow scene node" string (→ ShadowSceneNode ctor)
  - Identify global assignment: who calls sub_1421B08A0 AND stores return into global?
  - Decompile sub_140A3C890 (scene graph creator?), sub_140C323D1 (likely startup binding)
  - Also analyze qword_143E475A0 (ShadowSceneNode table indexed by byte [this+548])
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

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\stradaB_ops.txt"


def log(fh, msg):
    print(msg)
    fh.write(msg + "\n")
    fh.flush()


def rva(ea):
    return ea - ida_nalt.get_imagebase()


def decomp(ea, fh, label="", max_lines=80):
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


def find_lea_sites(target_ea):
    """Find instructions that do `lea reg, [rip+disp] -> target_ea`."""
    seg = ida_segment.get_segm_by_name(".text")
    if not seg:
        return []
    out = []
    ea = seg.start_ea
    end = seg.end_ea
    while ea < end - 8:
        try:
            # Pattern: 48 8D XX XX XX XX XX  (REX.W + 8D = lea)
            if ida_bytes.get_byte(ea) == 0x48 and ida_bytes.get_byte(ea+1) == 0x8D:
                mr = ida_bytes.get_byte(ea+2)
                if (mr & 0xC7) == 0x05:  # mod=00, rm=101 rip-rel
                    disp = ida_bytes.get_dword(ea+3)
                    if disp & 0x80000000:
                        disp -= 0x100000000
                    tgt = ea + 7 + disp
                    if tgt == target_ea:
                        fn = ida_funcs.get_func(ea)
                        out.append((ea, fn.start_ea if fn else 0))
        except Exception:
            pass
        ea += 1
    return out


def scan_qword_writes(global_ea):
    """Find 'mov [global], reg' sites."""
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


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    log(fh, "==== Strada B — scene ops RE ====")
    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()
    log(fh, f"image base = 0x{ida_nalt.get_imagebase():X}")

    # Decompile critical NiNode vtable slots (26-31) and UpdateDownwardPass area
    log(fh, "\n==== NiNode vtable 26..31 (AttachChild family) + 32..47 ====")
    NINODE_SLOTS = [
        (0x1416BDA20, "NiNode vt26 AttachChild?"),
        (0x1416BDC30, "NiNode vt27 AttachChildAt?"),
        (0x1416BDC80, "NiNode vt28 DetachChild?"),
        (0x1416BDD20, "NiNode vt29 DetachChildAt?"),
        (0x1416BDDB0, "NiNode vt30 DetachChildFrom?"),
        (0x1416BDE40, "NiNode vt31 SetAt?"),
        (0x1416BF640, "NiNode vt32 UpdateSelectedDownward?"),
        (0x1416BEA10, "NiNode vt40"),
        (0x1416BE900, "NiNode vt41"),
        (0x1416BF700, "NiNode vt42"),
        (0x1416BE990, "NiNode vt46"),
        (0x1416BF500, "NiNode vt47 UpdateWorldData?"),
        (0x1416BEAC0, "NiNode vt48"),
        (0x1416BE170, "NiNode vt58"),
        (0x1416BE2B0, "NiNode vt59"),
        (0x1416BE390, "NiNode vt60"),
        (0x1416BE4D0, "NiNode vt63"),
    ]
    for ea, lbl in NINODE_SLOTS:
        decomp(ea, fh, lbl, max_lines=40)

    log(fh, "\n\n==== NiAVObject vtable slots 27..47 ====")
    NIAV_SLOTS = [
        (0x1416C7CC0, "NiAVObject vt27"),
        (0x1416C7DB0, "NiAVObject vt28 UpdateDownwardPass?"),
        (0x1416C7E40, "NiAVObject vt29"),
        (0x1416C7E90, "NiAVObject vt30"),
        (0x1416C7F30, "NiAVObject vt31"),
        (0x1416C8C00, "NiAVObject vt32"),
        (0x1416BAB30, "NiAVObject vt34"),
        (0x1416C8110, "NiAVObject vt40"),
        (0x1416C8160, "NiAVObject vt41"),
        (0x1416C81A0, "NiAVObject vt45"),
        (0x1416C8210, "NiAVObject vt46"),
        (0x1416C8230, "NiAVObject vt47"),
        (0x1416C8310, "NiAVObject vt48 UpdateTransforms?"),
        (0x1416C83A0, "NiAVObject vt49"),
        (0x1416C84A0, "NiAVObject vt50"),
        (0x1416C85A0, "NiAVObject vt52"),
        (0x1416C8A60, "NiAVObject vt53"),
    ]
    for ea, lbl in NIAV_SLOTS:
        decomp(ea, fh, lbl, max_lines=40)

    # Search for "shadow scene node" string → trace back to singleton writer
    log(fh, "\n\n==== ShadowSceneNode singleton discovery ====")
    for needle in ["shadow scene node", "ShadowSceneNode", "BSFadeNode", "SceneGraph",
                   "WorldRoot", "ObjectLODRoot", "WorldspaceRoot"]:
        log(fh, f"\n-- '{needle}' --")
        hits = find_string_ea(needle, exact=False)
        for ea, v in hits[:10]:
            log(fh, f"  str @ 0x{ea:X}  '{v}'")
            for x in idautils.XrefsTo(ea, 0):
                fn = ida_funcs.get_func(x.frm)
                if fn:
                    log(fh, f"    xref from 0x{x.frm:X} in func 0x{fn.start_ea:X} (RVA 0x{rva(fn.start_ea):X})")

    # qword_143E475A0 is the "ShadowSceneNode table" — from ctor:
    #   qword_143E475A0[*(u8 *)(a1 + 548)]
    # check its writers
    log(fh, "\n\n==== qword_143E475A0 — ShadowSceneNode table ====")
    writes = scan_qword_writes(0x143E475A0)
    log(fh, f"  writes: {len(writes)}")
    for ins, fn in writes[:20]:
        log(fh, f"    ins 0x{ins:X}  in 0x{fn:X} (RVA 0x{rva(fn):X}) {ida_funcs.get_func_name(fn) or '?'}")

    # Scan for callers of ShadowSceneNode::ctor, and find what they do with return value
    log(fh, "\n\n==== Callers of ShadowSceneNode::ctor (sub_1421B08A0) ====")
    for xr in idautils.XrefsTo(0x1421B08A0, 0):
        fn = ida_funcs.get_func(xr.frm)
        log(fh, f"  xref from 0x{xr.frm:X} in 0x{fn.start_ea if fn else 0:X}")

    # Decompile the callers
    SHADOW_CALLERS = [
        (0x140A3C050, "SSN caller 1 (guessed from 0xA3C223)"),
        (0x140A3C223, "at a3c223"),  # may not be a func start
        (0x140C32200, "Renderer init (from 0xC323D1)"),
        (0x141080000, "1080580 caller"),
    ]
    # Use fn starts found from xrefs
    seen = set()
    for xr in idautils.XrefsTo(0x1421B08A0, 0):
        fn = ida_funcs.get_func(xr.frm)
        if fn and fn.start_ea not in seen:
            seen.add(fn.start_ea)
            decomp(fn.start_ea, fh, f"SSN caller @ 0x{fn.start_ea:X}", max_lines=120)

    # Also check callers of BSFadeNode::ctor — the scene root is likely a BSFadeNode
    log(fh, "\n\n==== Callers of BSFadeNode::ctor (sub_142174DC0) ====")
    seen = set()
    for xr in idautils.XrefsTo(0x142174DC0, 0):
        fn = ida_funcs.get_func(xr.frm)
        if fn and fn.start_ea not in seen:
            seen.add(fn.start_ea)
            nm = ida_funcs.get_func_name(fn.start_ea) or "?"
            log(fh, f"  caller 0x{fn.start_ea:X} (RVA 0x{rva(fn.start_ea):X}) {nm}")

    # Deep dive into NiAVObject::ctor and NiAVObject::variant - look at +40 (parent) etc.
    # Done. Now look at a real-world allocation+attach site: we want to find where
    # some module does `alloc NiNode -> AttachChild to parent`. Sampling xrefs to NiNode vtable data slot.

    # Decompile a handful of known allocator callers that allocate 0x140 to confirm NiNode fingerprint.
    log(fh, "\n\n==== sub_1416BDA20 actual body (if AttachChild) ====")
    decomp(0x1416BDA20, fh, "NiNode vt26 body (full)", max_lines=200)
    # And its sibling `sub_1416BDC30`
    decomp(0x1416BDC30, fh, "NiNode vt27 body (full)", max_lines=200)
    decomp(0x1416BDC80, fh, "NiNode vt28 body (full)", max_lines=200)
    decomp(0x1416BDD20, fh, "NiNode vt29 body (full)", max_lines=200)
    decomp(0x1416BDDB0, fh, "NiNode vt30 body (full)", max_lines=200)
    decomp(0x1416BDE40, fh, "NiNode vt31 body (full)", max_lines=200)

    log(fh, "\n==== END ====")
    fh.close()
    ida_pro.qexit(0)


main()
