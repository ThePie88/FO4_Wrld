"""Find TESObjectREFR::SetPosition engine function for proper ghost move.

Raw writes to REFR+0xD0 (the known pos offset) cause flicker because Havok
and the NiNode transform have their own position state that the engine
re-asserts each tick. The Papyrus native `ObjectReference.SetPosition(x, y, z)`
is the engine's sanctioned entry point — it syncs rigidbody, nitransform,
and AI/pathfinding simultaneously.

Strategy: same as the other RE scripts — find the "SetPosition" string in
the Papyrus native registrar (sub_14115EFB0 for ObjectReference), extract the
native function, decompile, follow any forwarders.

Note: Papyrus SetPosition takes 3 floats. The engine internals may take a
pointer to a vec3 or 3 separate floats — the decomp will clarify.
"""
import ida_auto
import ida_funcs
import ida_hexrays
import ida_nalt
import idc
import idautils
import ida_pro
import re

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\setposition_report.txt"

TARGETS = [
    "SetPosition",
    "MoveTo",
    "Teleport",
]

MAX_SCAN = 80


def log(msg, fh):
    print(msg); fh.write(msg + "\n"); fh.flush()


def decompile_safely(ea, max_len=3500):
    try:
        fn = ida_funcs.get_func(ea)
        if fn is None:
            return None
        cf = ida_hexrays.decompile(fn.start_ea)
        if cf is None:
            return None
        src = str(cf)
        return src if len(src) <= max_len else src[:max_len] + "\n...<truncated>"
    except Exception as e:
        return f"<decompile err: {e}>"


SUB_RE = re.compile(r"sub_([0-9A-Fa-f]{6,16})")


def forwarder_target(decomp_src):
    if decomp_src is None: return None
    body = " ".join(decomp_src.split())
    m = re.search(r"return\s+sub_([0-9A-Fa-f]{6,16})\s*\(", body)
    if not m: return None
    return int(m.group(1), 16)


def extract_native_from_xref(xref_ea, img):
    """Idiom A (GetPositionX-like): last `lea rax, sub_X` between xref and
    next call. Idiom B (GetParentCell-like): last `lea r9, sub_X` in that
    same window. We gather both and return (idiom_A_lea, idiom_B_lea)."""
    cur = xref_ea
    lea_rax = None
    lea_r9  = None
    # Forward scan: up to next call
    forward_steps = 0
    while forward_steps < MAX_SCAN:
        cur = idc.next_head(cur)
        forward_steps += 1
        if cur == idc.BADADDR: break
        mnem = idc.print_insn_mnem(cur)
        if mnem == "call":
            break
        if mnem == "lea":
            op0 = idc.print_operand(cur, 0); op1 = idc.print_operand(cur, 1)
            if op1.startswith("sub_"):
                target = idc.get_operand_value(cur, 1)
                if op0 == "rax": lea_rax = target
                elif op0 == "r9": lea_r9 = target
    # Also Idiom A: lea rax, sub_X AFTER the call (native stored into [X+50h])
    after_lea_rax = None
    after_steps = 0
    while after_steps < MAX_SCAN:
        cur = idc.next_head(cur)
        after_steps += 1
        if cur == idc.BADADDR: break
        mnem = idc.print_insn_mnem(cur)
        # stop at next string xref / next call (probably start of next native)
        if mnem == "call":
            # Only stop if more than a few steps in (first call is the
            # register call we already found)
            if after_steps > 3:
                break
        if mnem == "lea":
            op0 = idc.print_operand(cur, 0); op1 = idc.print_operand(cur, 1)
            if op0 == "rax" and op1.startswith("sub_"):
                after_lea_rax = idc.get_operand_value(cur, 1)
                break  # take the first (it's the native written to [X+50h])
    return (lea_rax, lea_r9, after_lea_rax)


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{img:X}", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] no hexrays", fh); fh.close(); ida_pro.qexit(2)

    strs = list(idautils.Strings())
    name_to_ea: dict[str, list[int]] = {}
    for s in strs:
        sval = str(s)
        if sval in TARGETS:
            name_to_ea.setdefault(sval, []).append(s.ea)

    for target in TARGETS:
        log(f"\n==== {target!r} ====", fh)
        if target not in name_to_ea:
            log("  <string not found>", fh)
            continue
        for str_ea in name_to_ea[target]:
            log(f"  string @ 0x{str_ea:X} (RVA 0x{str_ea - img:X})", fh)
            xrefs = list(idautils.XrefsTo(str_ea, 0))
            for x in xrefs[:5]:
                fn = ida_funcs.get_func(x.frm)
                if fn is None:
                    log(f"    xref 0x{x.frm:X} (no func)", fh); continue
                log(f"    xref 0x{x.frm:X} in registrar RVA 0x{fn.start_ea - img:X}", fh)
                lea_rax_before, lea_r9, lea_rax_after = extract_native_from_xref(x.frm, img)
                for label, native_ea in [
                    ("idiom-B r9 (before call)", lea_r9),
                    ("idiom-A rax (after call)", lea_rax_after),
                    ("rax (before call, rare)", lea_rax_before),
                ]:
                    if native_ea is None: continue
                    log(f"      [{label}] native @ RVA 0x{native_ea - img:X}", fh)
                    src = decompile_safely(native_ea)
                    if src:
                        log("      --- decompile native ---", fh)
                        log(src, fh)
                        log("      ---", fh)
                        fwd = forwarder_target(src)
                        if fwd is not None:
                            log(f"      forwarder -> helper RVA 0x{fwd - img:X}", fh)
                            helper_src = decompile_safely(fwd, max_len=5000)
                            if helper_src:
                                log("      --- decompile helper ---", fh)
                                log(helper_src, fh)
                                log("      ---", fh)

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
