"""Find TESObjectREFR offsets for parentCell / baseForm / worldSpace.

v2: fixed the native-extraction heuristic. In FO4's Papyrus registrar, native
registration is a linear sequence per native:
    lea  rcx, <VM>
    lea  rdx, <name_string>   ; xref to string lives here
    lea  r8,  <arg_desc>
    lea  r9,  <arg_desc>
    ...
    lea  rax, <native_impl>    ; native we want
    mov  [rsp+..], rax
    call <RegisterFunction>    ; <-- scope boundary
The previous v1 grabbed the FIRST `lea rax, sub_X` after the xref. That is
wrong when the scope ends before the next lea: v1 leaked into the NEXT native's
registration block, returning (e.g.) sub_1411567D0 for GetParentCell which is
actually GetPositionX (reads 0xD0). Fixed by scanning forward until the first
`call` and taking the last `lea rax, sub_X` within that window.

Also: for natives that just forward to a helper `sub_X(ref)`, we follow and
decompile that helper so we can see the actual struct offset it reads.
"""
import ida_auto
import ida_funcs
import ida_hexrays
import ida_nalt
import idc
import idautils
import ida_pro
import re

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\refr_offsets_report_v2.txt"

TARGETS = [
    "GetParentCell",
    "GetBaseObject",
    "GetWorldSpace",
    # for Actor subtype, to cross-verify base offset:
    "GetActorBase",
    "GetLeveledActorBase",
    # Control: we know GetPositionX reads *(float*)(ref+0xD0)
    "GetPositionX",
]

# Max instructions to scan forward from the xref looking for the `call`
# that terminates this native's registration block.
MAX_SCAN = 80


def log(msg, fh):
    print(msg)
    fh.write(msg + "\n")
    fh.flush()


def decompile_safely(ea, max_len=2500):
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


# Simple regex to find `sub_1XXXXXXXX` in decompiled source — so we can follow
# trivial forwarder natives into their helper.
SUB_RE = re.compile(r"sub_([0-9A-Fa-f]{6,16})")


def forwarder_target(decomp_src):
    """If the native is `return sub_X(arg);` return sub_X address, else None."""
    if decomp_src is None:
        return None
    # Collapse whitespace
    body = " ".join(decomp_src.split())
    # Match "return sub_XXXX(...);"
    m = re.search(r"return\s+sub_([0-9A-Fa-f]{6,16})\s*\(", body)
    if not m:
        return None
    return int(m.group(1), 16)


def extract_native_from_xref(xref_ea, img, fh):
    """Walk forward from xref_ea until the first CALL; return the LAST
    `lea rax, sub_X` encountered in that window (or None)."""
    cur = xref_ea
    last_lea_target = None
    for _ in range(MAX_SCAN):
        cur = idc.next_head(cur)
        if cur == idc.BADADDR:
            return last_lea_target
        mnem = idc.print_insn_mnem(cur)
        if mnem == "call":
            # End of registration block — the last lea rax we saw is the native.
            return last_lea_target
        if mnem == "lea":
            op0 = idc.print_operand(cur, 0)
            op1 = idc.print_operand(cur, 1)
            if op0 == "rax" and op1.startswith("sub_"):
                last_lea_target = idc.get_operand_value(cur, 1)
    return last_lea_target


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{img:X}", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] no hexrays", fh)
        fh.close()
        ida_pro.qexit(2)

    strs = list(idautils.Strings())
    # Map name -> first matching string EA (Papyrus native names are unique)
    name_to_ea = {}
    for s in strs:
        sval = str(s)
        if sval in TARGETS and sval not in name_to_ea:
            name_to_ea[sval] = s.ea

    for target in TARGETS:
        log(f"\n==== {target!r} ====", fh)
        if target not in name_to_ea:
            log(f"  <string not found in binary>", fh)
            continue
        str_ea = name_to_ea[target]
        log(f"  string @ 0x{str_ea:X} (RVA 0x{str_ea - img:X})", fh)
        xrefs = list(idautils.XrefsTo(str_ea, 0))
        for x in xrefs[:5]:
            fn = ida_funcs.get_func(x.frm)
            if fn is None:
                log(f"    xref 0x{x.frm:X} (no func)", fh)
                continue
            log(f"    xref 0x{x.frm:X} in registrar 0x{fn.start_ea:X} (RVA 0x{fn.start_ea - img:X})", fh)

            native_ea = extract_native_from_xref(x.frm, img, fh)
            if native_ea is None:
                log("      <no lea rax, sub_X before next call>", fh)
                continue

            log(f"      native @ 0x{native_ea:X} (RVA 0x{native_ea - img:X})", fh)
            src = decompile_safely(native_ea)
            if src is None:
                log("      <no decomp>", fh)
                continue
            log("      --- decompile native ---", fh)
            log(src, fh)
            log("      ---", fh)

            # If it's a forwarder, follow into the helper.
            helper_ea = forwarder_target(src)
            if helper_ea is not None:
                log(f"      forwarder -> helper @ 0x{helper_ea:X} (RVA 0x{helper_ea - img:X})", fh)
                helper_src = decompile_safely(helper_ea, max_len=4000)
                if helper_src is not None:
                    log("      --- decompile helper ---", fh)
                    log(helper_src, fh)
                    log("      ---", fh)

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
