"""Quick decomp: sub_1416D5660 and its behavior. Does POSTALLOC_NORMAL init +0x108?"""
import ida_auto, ida_funcs, ida_nalt, ida_hexrays, ida_pro
import ida_bytes, ida_ua, idautils, idc
REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\stradaB_M2_d5660.txt"

def log(fh, msg):
    fh.write(msg + "\n"); fh.flush()
def rva(ea): return ea - ida_nalt.get_imagebase()

def decomp(ea, fh, label=""):
    log(fh, f"\n-- decomp {label} @ 0x{ea:X} (RVA 0x{rva(ea):X}) --")
    fn = ida_funcs.get_func(ea)
    if not fn:
        log(fh, "  NO FUNC"); return
    log(fh, f"  size=0x{fn.end_ea - fn.start_ea:X}")
    try:
        cf = ida_hexrays.decompile(ea)
        if cf: log(fh, str(cf))
    except Exception as e:
        log(fh, f"  [!] decomp failed: {e}")

def disasm(ea, fh, label="", cnt=100):
    log(fh, f"\n-- disasm {label} @ 0x{ea:X} (RVA 0x{rva(ea):X}) --")
    fn = ida_funcs.get_func(ea)
    if not fn:
        log(fh, "  NO FUNC"); return
    cur = ea; end = min(fn.end_ea, ea + cnt*16); i=0
    while cur < end and i < cnt:
        log(fh, f"  0x{cur:X}  {idc.generate_disasm_line(cur,0) or '?'}")
        cur = idc.next_head(cur, end); i+=1
        if cur == idc.BADADDR: break

def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait(); ida_hexrays.init_hexrays_plugin()
    B = ida_nalt.get_imagebase()

    # sub_1416D5660 — called by POSTALLOC_NORMAL
    decomp(B + 0x16D5660, fh, "sub_1416D5660 (POSTALLOC_NORMAL preamble)")
    disasm(B + 0x16D5660, fh, "sub_1416D5660 disasm", cnt=80)

    # sub_1416D5840 — BSGeometry dtor
    decomp(B + 0x16D5840, fh, "sub_1416D5840 BSGeometry::dtor?")

    # BSTriShape vt[0] sub_1416DA340 is dtor — check
    decomp(B + 0x16DA340, fh, "sub_1416DA340 BSTriShape dtor")

    # BSTriShape vt[32] sub_1416D5260 - render slot? size 0x100?
    decomp(B + 0x16D5260, fh, "BSTriShape/BSGeometry vt[32] sub_1416D5260")

    # BSTriShape vt[33] sub_1416D53A0
    decomp(B + 0x16D53A0, fh, "BSTriShape/BSGeometry vt[33] sub_1416D53A0")

    # BSTriShape vt[47] sub_1416D4D60
    decomp(B + 0x16D4D60, fh, "BSTriShape vt[47] sub_1416D4D60")

    # BSTriShape vt[48] sub_1416D4DC0
    decomp(B + 0x16D4DC0, fh, "BSTriShape vt[48] sub_1416D4DC0")

    # BSTriShape vt[50] sub_1416D4EA0 - interesting 0x63 bytes
    decomp(B + 0x16D4EA0, fh, "BSTriShape vt[50] sub_1416D4EA0")

    # BSTriShape vt[51] sub_1416D4F80 - update bounds, 0x279 bytes = big
    decomp(B + 0x16D4F80, fh, "BSTriShape vt[51] sub_1416D4F80 UpdateBounds?")

    # BSTriShape vt[58] sub_1416D4F10 (overrides NiNode's AttachChild slot!)
    # Because Tri has it, and AttachChild is slot 58... means BSTriShape overrides...
    decomp(B + 0x16D4F10, fh, "BSTriShape vt[58] sub_1416D4F10 (override of AttachChild?)")

    # MOST IMPORTANTLY — does sub_140C38F80 use children array?
    # Look at sub_1421F2D60 - it's called from scene_render, may be the walker
    decomp(B + 0x21F2D60, fh, "sub_1421F2D60 (SceneRender child-walker?)")

    # And qword_1430DA390 — what's the table the refid indexes?
    log(fh, "\n-- qword_1430DA390 — table of form-ids ==")
    for offset in range(0, 0x40, 8):
        qw = ida_bytes.get_qword(B + 0x30DA390 + offset)
        log(fh, f"  +0x{offset:X}: 0x{qw:X}")

    # Also check sub_1421E9500 (hit 8 times for 108h test — many TESForm methods?)
    # And sub_1421BC0F0 (hit 6 times)
    # These are likely the 3D-object dispatch subclass which is used when
    # rendering happens through the form-id table.
    # Lightweight: just decomp once to see pattern
    decomp(B + 0x21BC0F0, fh, "sub_1421BC0F0 — TESObjectREFR render prep?")

    ida_pro.qexit(0)

main()
