"""
decomp_nif_loader4.py — clarify sub_1416A6D00 (called by all callers of
sub_1417B3480) and the "hot path" that returns an existing cached
NiAVObject* vs needing to invoke the parser.
"""
import ida_auto
import ida_funcs
import ida_nalt
import ida_hexrays
import ida_pro
import ida_bytes
import ida_name
import idautils
import idc

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\stradaB_nif_loader_raw4.txt"


def log(fh, msg):
    print(msg)
    fh.write(msg + "\n")
    fh.flush()


def rva(ea):
    return ea - ida_nalt.get_imagebase()


def decomp_full(ea, fh, label="", max_lines=400):
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


def xrefs_to_addr(fh, ea, label, limit=60):
    log(fh, f"\n==== xrefs to {label} @ 0x{ea:X} (RVA 0x{rva(ea):X}) ====")
    results = []
    for xref in idautils.XrefsTo(ea, 0):
        fn = ida_funcs.get_func(xref.frm)
        fname = ida_funcs.get_func_name(xref.frm) or "?"
        fn_start = fn.start_ea if fn else 0
        fn_rva = rva(fn_start) if fn_start else 0
        log(fh, f"  xref from 0x{xref.frm:X} in {fname} (func @ 0x{fn_start:X} RVA 0x{fn_rva:X}) type={xref.type}")
        results.append((xref.frm, fn_start))
        if len(results) >= limit:
            break
    return results


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    log(fh, "==== NIF loader — final pass 4 ====")
    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()
    IMG = ida_nalt.get_imagebase()
    log(fh, f"image base = 0x{IMG:X}")

    # Core suspects:
    decomp_full(0x1416A6D00, fh, "sub_1416A6D00_cache_lookup_or_queue", max_lines=250)
    decomp_full(0x1416A6930, fh, "sub_1416A6930_variant", max_lines=250)
    decomp_full(0x1416A6FC0, fh, "sub_1416A6FC0", max_lines=100)
    decomp_full(0x14026E530, fh, "sub_14026E530_post_hit", max_lines=120)
    decomp_full(0x1416A6BC0, fh, "sub_1416A6BC0", max_lines=120)

    # sub_1417B3480 body in depth, esp. the non-truncated tail (previous pass1 was truncated)
    decomp_full(0x1417B3480, fh, "sub_1417B3480_full_body", max_lines=700)

    # sub_140459B50 — called in sub_140458740 by "a2" (TESObjectREFR-like)
    decomp_full(0x140459B50, fh, "sub_140459B50", max_lines=150)

    # sub_14033EE60 caller of sub_14026E1C0
    decomp_full(0x14033EE60, fh, "sub_14033EE60_caller_of_14026E1C0", max_lines=200)

    # sub_14033EE20/EE40/EE10/EE30 (IEntryDB vtable slot 22,23,24,27 — likely
    # Load/Lookup methods we care about)
    for ea in [0x14033EE20, 0x14033EE40, 0x14033EE10, 0x14033EE30, 0x14033EE50]:
        decomp_full(ea, fh, f"iEntryDB_vtable_slot @ 0x{ea:X}", max_lines=150)

    # Also: the sub_14033EE20 xref comes from callers — this is likely
    # "BSModelDB::Demand" or similar. Get its xrefs.
    xrefs_to_addr(fh, 0x14033EE20, "iEntryDB_vt22 (BSModelDB-Demand candidate)", limit=20)
    xrefs_to_addr(fh, 0x14033EE40, "iEntryDB_vt23", limit=20)
    xrefs_to_addr(fh, 0x14033EE10, "iEntryDB_vt24", limit=20)
    xrefs_to_addr(fh, 0x14033EE30, "iEntryDB_vt27", limit=20)

    # And finally check sub_14033D1E0 (caller of sub_14033EC90 in pass3)
    decomp_full(0x14033D1E0, fh, "sub_14033D1E0_caller_of_33EC90", max_lines=200)

    # qword_1430DD618 is the BSModelDB singleton? Check xrefs
    xrefs_to_addr(fh, 0x1430DD618, "qword_1430DD618_BSModelDB_singleton", limit=30)

    # Interrogate BSLeafAnimNode ctor for the alternative alloc pattern
    decomp_full(0x142177E60, fh, "sub_142177E60_BSLeafAnim_wrap_again", max_lines=100)
    decomp_full(0x142177590, fh, "sub_142177590_BSFadeNode_vtable_writer", max_lines=200)
    decomp_full(0x142175310, fh, "sub_142175310_BSFadeNode_vtable_writer", max_lines=200)

    # sub_1417B3D10 and sub_1417B3E90 — callers of sub_14033EC90
    decomp_full(0x1417B3D10, fh, "sub_1417B3D10_caller_of_33EC90", max_lines=200)
    decomp_full(0x1417B3E90, fh, "sub_1417B3E90_caller_of_33EC90", max_lines=200)

    # sub_1417B59C0 — also calls 33EC90
    decomp_full(0x1417B59C0, fh, "sub_1417B59C0_caller_of_33EC90", max_lines=200)

    # Check AssignSource vtable slot. It's called via (vt + 464) =
    # vt[58]. Is it canonical BSFadeNode::AssignSource?
    # BSFadeNode vtable @ 0x1428FA3E8. Dump slot 58
    log(fh, "\n\n=========================================")
    log(fh, "  BSFadeNode vtable slot 58 (AssignSource?)")
    log(fh, "=========================================")
    vt_base = 0x1428FA3E8
    for i in range(55, 70):
        ea = vt_base + 8 * i
        v = idc.get_qword(ea)
        nm = ida_funcs.get_func_name(v) or "?"
        log(fh, f"  vt[{i:2d}] @ 0x{ea:X}  -> 0x{v:X}  (RVA 0x{v - IMG:X})  {nm}")

    # sub_14167BCF0 = zero BSFixedString (called often)
    decomp_full(0x14167BCF0, fh, "sub_14167BCF0_BSFixedString_zero", max_lines=50)

    # and sub_14167C070 = BSFixedString::c_str accessor
    decomp_full(0x14167C070, fh, "sub_14167C070_BSFixedString_cstr", max_lines=50)

    # Sub_14167BDC0 = BSFixedString::ctor(from cstr)
    decomp_full(0x14167BDC0, fh, "sub_14167BDC0_BSFixedString_ctor_cstr", max_lines=100)

    log(fh, "\n==== END pass 4 ====")
    fh.close()
    ida_pro.qexit(0)


main()
