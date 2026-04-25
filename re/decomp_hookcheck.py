"""
URGENT: Verify hook candidates and find per-frame call sites for VP matrix
capture. Runs in idat.exe -A -S mode.
"""
import idaapi
import idautils
import idc
import ida_funcs
import ida_xref
import ida_bytes
import ida_ua

BASE = 0x140000000

OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\hookcheck_report.txt"


def dump(msg, f=None):
    print(msg)
    if f:
        f.write(msg + "\n")


def get_callers(ea):
    """return list of (caller_func_ea, call_site_ea)"""
    refs = []
    for ref in idautils.CodeRefsTo(ea, 0):
        f = ida_funcs.get_func(ref)
        if f:
            refs.append((f.start_ea, ref))
        else:
            refs.append((None, ref))
    return refs


def count_xrefs(ea):
    """count only code references to ea"""
    cnt = 0
    for _ in idautils.CodeRefsTo(ea, 0):
        cnt += 1
    return cnt


def dump_insn(ea):
    return idc.generate_disasm_line(ea, 0)


def caller_chain(ea, depth=4, path=None):
    """Walk up callers, collecting chains up to depth levels."""
    if path is None:
        path = []
    callers = get_callers(ea)
    if not callers or depth == 0:
        yield path + [ea]
        return
    seen = set()
    # dedupe by caller function
    uniq = []
    for (cf, cs) in callers:
        if cf and cf not in seen:
            seen.add(cf)
            uniq.append((cf, cs))
    if not uniq:
        yield path + [ea]
        return
    for (cf, cs) in uniq[:4]:
        if cf in path:
            yield path + [ea, cf, "LOOP"]
            continue
        yield from caller_chain(cf, depth - 1, path + [ea])


def probe(ea, name, f):
    dump("", f)
    dump(f"=== {name}  EA=0x{ea:X}  RVA=0x{ea - BASE:X} ===", f)
    fn = ida_funcs.get_func(ea)
    if not fn:
        dump(f"  !!! NO FUNCTION AT EA 0x{ea:X}", f)
        return
    dump(f"  size=0x{fn.end_ea - fn.start_ea:X}", f)
    # check prologue bytes
    b = ida_bytes.get_bytes(ea, 16)
    if b:
        dump(f"  prologue16: {b.hex()}", f)
    # xref count
    callers = get_callers(ea)
    dump(f"  callers: {len(callers)} call-sites", f)
    seen = {}
    for (cf, cs) in callers:
        if cf is not None:
            n = idc.get_func_name(cf) or f"sub_{cf:X}"
            key = cf
        else:
            n = f"<nofn @ {cs:X}>"
            key = cs
        seen.setdefault(key, [0, n])
        seen[key][0] += 1
    for k, (c, n) in sorted(seen.items(), key=lambda kv: -kv[1][0]):
        dump(f"     {c}x  {n}   0x{k:X}  RVA 0x{k-BASE:X}", f)


def find_vtable_slot(vt_ea, slot_index):
    """Read qword at vt_ea + slot_index*8"""
    addr = vt_ea + slot_index * 8
    v = ida_bytes.get_qword(addr)
    return addr, v


with open(OUT, "w") as f:
    dump("=" * 80, f)
    dump(" HOOK CHECK REPORT — VP matrix capture", f)
    dump("=" * 80, f)

    # ==================== Q1: PRODUCER diagnostics ====================
    dump("\n\n############ Q1: PRODUCER sub_1421DC480 ############", f)
    PROD = 0x1421DC480
    probe(PROD, "sub_1421DC480 (PRODUCER)", f)

    # full caller chain up 4 levels
    dump("\n  Caller chains (up to depth 4):", f)
    chains = list(caller_chain(PROD, depth=4))
    for c in chains[:30]:
        parts = []
        for x in c:
            if isinstance(x, int):
                n = idc.get_func_name(x) or f"sub_{x:X}"
                parts.append(f"{n}(RVA 0x{x-BASE:X})")
            else:
                parts.append(str(x))
        dump("    " + " -> ".join(parts), f)

    # ==================== Q2: CONSUMER diagnostics ====================
    dump("\n\n############ Q2: CONSUMER sub_14221E6A0 ############", f)
    CONS = 0x14221E6A0
    probe(CONS, "sub_14221E6A0 (CONSUMER)", f)

    # vtable slot check: was identified as vtbl 0x14290D158 slot[8]
    VT = 0x14290D158
    slot_addr, slot_val = find_vtable_slot(VT, 8)
    dump(f"\n  vtable 0x{VT:X} slot[8] @ 0x{slot_addr:X} -> 0x{slot_val:X}", f)
    dump(f"    matches sub_14221E6A0? {slot_val == CONS}", f)

    # dump surrounding vtable slots
    dump("\n  vtable 0x14290D158 slots [0..24]:", f)
    for i in range(25):
        a, v = find_vtable_slot(VT, i)
        fn = idc.get_func_name(v) or f"sub_{v:X}"
        dump(f"    [{i:2}] 0x{a:X} -> 0x{v:X} ({fn}, RVA 0x{v-BASE:X})", f)

    # caller chains for consumer
    dump("\n  Caller chains (up to depth 3):", f)
    chains = list(caller_chain(CONS, depth=3))
    for c in chains[:30]:
        parts = []
        for x in c:
            if isinstance(x, int):
                n = idc.get_func_name(x) or f"sub_{x:X}"
                parts.append(f"{n}(RVA 0x{x-BASE:X})")
            else:
                parts.append(str(x))
        dump("    " + " -> ".join(parts), f)

    # ==================== Q3: CB Map hooks ====================
    dump("\n\n############ Q3: CB_Map_A/B call sites ############", f)
    CBA = 0x1421A0680
    CBB = 0x1421A05E0
    for ea, nm in [(CBA, "CB_Map_A"), (CBB, "CB_Map_B")]:
        probe(ea, nm, f)

    # find functions that call CB_Map_A with a stored constant 0x80 offset write following
    dump("\n  Callers of CB_Map_A that write XMM to [result+0x80]:", f)
    for (cf, cs) in get_callers(CBA):
        if cf is None:
            continue
        # scan the instructions 0..64 after the call for a `movups xmmword ptr [rax+80h]` style
        cur = cs
        end = cur + 0x80
        hit = False
        while cur < end:
            nxt = idc.next_head(cur)
            if nxt == idc.BADADDR:
                break
            disasm = idc.generate_disasm_line(nxt, 0) or ""
            if ("+80h" in disasm or "+128" in disasm) and ("movup" in disasm.lower() or "movaps" in disasm.lower() or "movdq" in disasm.lower()):
                hit = True
                dump(f"    caller sub_{cf:X} (RVA 0x{cf-BASE:X}): {disasm}  @0x{nxt:X}", f)
                break
            cur = nxt
        if not hit:
            # show all movxxx ops nearby to capture 0x80 case
            pass

    # ==================== Q4: diagnostic hook helper ====================
    dump("\n\n############ Q4: Diagnostic — high-frequency callers ############", f)
    # Enumerate the MOST CALLED functions whose name starts with sub_142 in .text
    # to find candidates that definitely run per-frame. Only for functions
    # related to the render. Instead we enumerate candidates:
    # scene dispatcher candidates already noted in report:
    CANDIDATES = [
        (0x140C38910, "sub_140C38910 (scene setup, 20 setters)"),
        (0x140C38F80, "sub_140C38F80 (3D scene walker)"),
        (0x1410262F0, "sub_1410262F0 (PlayerCamera::Update)"),
        (0x1416D20B0, "sub_1416D20B0 (NiCamera view-mat update)"),
        (0x1421BE240, "sub_1421BE240 (4x4 matmul)"),
    ]
    for ea, nm in CANDIDATES:
        probe(ea, nm, f)

    dump("\n\nDONE.", f)

idc.qexit(0)
