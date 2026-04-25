"""Decompile the BSShader switch/jumptable functions that translate a
constant-enum-index into its string name. The order of cases in the jumptable
IS the order of fields in the corresponding constant buffer.

Identified "GetString" handlers (each is a switch { case N: return "CbFieldName"; }):

  0x226B6F0   BSDFPrePassShaderVertexConstants::GetString    (~28 cases)
  0x226C430   BSDFPrePassShaderPixelConstants::GetString    (uses bitflags)
  0x226C200   BSLightingShaderVertexConstants::GetString?
  0x226CC00   BSLightingShaderPixelConstants::GetString
  0x226D460   BSXShader / BSSkyShaderVertexConstants?
  0x226D5D0   shader samplers?

(The handler RVAs are the function-prolog bytes we already extracted; verify
the first-ref-string in each function body — that's the "Add-your-constant-to-..."
default case, which tells you WHICH class this is.)

For each handler:
  1. Decompile with Hex-Rays
  2. Identify the jump-table base (lea rdx,[rip+XXX])
  3. Walk the jump table, resolving each case-handler's "lea rax, string" target
  4. Print the enum-order list: index 0 -> name, 1 -> name, ...

That ordered list == the sequence of constants in the CB. Given each constant
is either float4 (0x10) or matrix (0x40), and the CB uses `packoffset(cN)`
packing (4-byte alignment, 16-byte row), we can compute offsets.

Output: re/shader_cb_layout_report.txt
"""

import idautils
import ida_auto
import ida_funcs
import ida_name
import ida_bytes
import ida_hexrays
import ida_ua
import idc

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\shader_cb_layout_report.txt"
IMAGE_BASE = 0x140000000


def log(fh, *a):
    s = " ".join(str(x) for x in a)
    print(s)
    fh.write(s + "\n")


def get_cstring(ea):
    out = b""
    for _ in range(200):
        b = ida_bytes.get_byte(ea)
        if b == 0 or not (0x20 <= b < 0x7F):
            break
        out += bytes([b])
        ea += 1
    return out.decode("ascii", errors="replace")


def walk_jumptable(fn_ea, fh):
    """Scan function body for:  lea rdx, [rip+JT] ; mov eax, ecx ; mov ecx, [rdx+rax*4] ; add rcx, rdx ; jmp rcx
    Then pull the jumptable entries (32-bit offsets added to JT base) and
    at each target read `lea rax, [rip+STR]` -> resolve the string.

    Also handle the simpler pattern:
      cmp ecx, N / ja dflt / lea rdx, [rip+JT] ...
    """
    f = ida_funcs.get_func(fn_ea)
    if not f:
        return
    log(fh, f"\n=== walk_jumptable {hex(fn_ea - IMAGE_BASE)} ===")
    end = f.end_ea

    # Find jumptable base: look for `lea rdx, [rip+disp]` and also cmp immediate
    ea = f.start_ea
    jt_base = None
    cmp_imm = None
    while ea < end:
        insn = ida_ua.insn_t()
        sz = ida_ua.decode_insn(insn, ea)
        if sz == 0:
            ea += 1
            continue
        mnem = insn.get_canon_mnem()
        if mnem == "cmp" and insn.ops[0].type == ida_ua.o_reg and insn.ops[1].type == ida_ua.o_imm:
            if cmp_imm is None:
                cmp_imm = insn.ops[1].value
        if mnem == "lea":
            # op1 is memory with RIP base -> addr = insn.ops[1].addr
            if insn.ops[1].type == ida_ua.o_mem:
                addr = insn.ops[1].addr
                # jt_base is typically in rdx before the jmp
                # take the FIRST lea that points into .text or .rdata
                if jt_base is None and addr >= IMAGE_BASE + 0x2438000:
                    jt_base = addr
        ea += sz

    if jt_base is None:
        log(fh, "  no jumptable base found")
        return

    log(fh, f"  cmp_imm={cmp_imm}  jt_base={hex(jt_base - IMAGE_BASE)}")
    n_cases = (cmp_imm + 1) if cmp_imm is not None else 40
    log(fh, f"  walking {n_cases} jumptable entries:")
    for i in range(min(n_cases, 64)):
        entry_off = jt_base + i * 4
        disp = ida_bytes.get_dword(entry_off)
        # Signed 32-bit
        if disp >= 0x80000000:
            disp -= 0x100000000
        handler = jt_base + disp
        # At the handler, usually: 48 8D 05 XX XX XX XX  C3
        if ida_bytes.get_byte(handler) == 0x48 and \
           ida_bytes.get_byte(handler + 1) == 0x8D and \
           ida_bytes.get_byte(handler + 2) == 0x05:
            str_disp = ida_bytes.get_dword(handler + 3)
            if str_disp >= 0x80000000:
                str_disp -= 0x100000000
            str_ea = handler + 7 + str_disp
            s = get_cstring(str_ea)
            log(fh, f"    [{i:3d}]  handler={hex(handler - IMAGE_BASE):>10s}  str={hex(str_ea - IMAGE_BASE):>10s}  \"{s}\"")
        else:
            b0 = ida_bytes.get_byte(handler)
            log(fh, f"    [{i:3d}]  handler={hex(handler - IMAGE_BASE):>10s}  (first byte {b0:02x} - not a direct lea)")


def identify_class_from_func(fn_ea):
    """Default-case of the switch is `lea rax, \"Add-your-constant-to-...\"` — the
    string tells us which class this GetString belongs to.
    """
    f = ida_funcs.get_func(fn_ea)
    if not f:
        return "?"
    ea = f.start_ea
    while ea < f.end_ea:
        insn = ida_ua.insn_t()
        sz = ida_ua.decode_insn(insn, ea)
        if sz == 0:
            ea += 1
            continue
        if insn.get_canon_mnem() == "lea" and insn.ops[1].type == ida_ua.o_mem:
            addr = insn.ops[1].addr
            if IMAGE_BASE + 0x2438000 <= addr < IMAGE_BASE + 0x2ECD000:
                s = get_cstring(addr)
                if "Add-your-constant-to-" in s:
                    return s
        ea += sz
    return "(no Add-your-constant-to- string found)"


def main():
    ida_auto.auto_wait()
    with open(REPORT, "w", encoding="utf-8") as fh:
        log(fh, "FO4 shader CB constant-name enumeration")
        log(fh, "=" * 60)

        # All candidate GetString functions from the CC-padding scan
        # (narrow zone 0x226Bxxx-0x226Dxxx where CB-name xrefs cluster)
        candidates = [
            0x226B6F0, 0x226C430, 0x226C200, 0x226C1E0, 0x226CC00,
            0x226D460, 0x226D5D0, 0x226D6D0, 0x226D730, 0x226B8E0,
            0x226BA10, 0x226BB40, 0x226AB20, 0x226AC10, 0x226AD00,
            0x226A3A0, 0x226A720, 0x226A840, 0x226A9C0, 0x226AA50,
            0x226D420, 0x226D430, 0x226D490, 0x226D510, 0x226D560,
            0x226D590, 0x226D9E0, 0x226DC30, 0x226DE30, 0x226DEE0,
        ]
        for rva in candidates:
            cls = identify_class_from_func(IMAGE_BASE + rva)
            log(fh, f"\n[{hex(rva):>10s}] class = {cls}")
            walk_jumptable(IMAGE_BASE + rva, fh)


main()
