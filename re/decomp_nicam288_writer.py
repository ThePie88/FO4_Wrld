"""
decomp_nicam288_writer.py

Goal: identify the function(s) that WRITE to offset +288 (0x120) inside a
NiCamera object. That offset holds a 64-byte 4x4 matrix (confirmed by
NiCamera::Clone @ vtable[26]). We need to know WHAT the matrix is
(ViewProj? World? Shadow? Auxiliary?) and to do that we read the
function name + body that writes to it.

Strategy:
 1. Decompile all 36 NiCamera virtual methods and grep each for
    '+ 288' / 'a1 + 288' / '+ 0x120' / '(rcx + 0x120)' patterns.
 2. Additionally linearly scan .text for `movups xmmword [reg+120h]`
    patterns (x64 typical write of 16 bytes to +288). Track unique
    function starts hitting this.
 3. Produce a ranked list of candidate writers with their decomp.

Output: re/nicam288_writers_report.txt
"""
import ida_auto, ida_bytes, ida_funcs, ida_hexrays, ida_nalt, ida_name
import ida_segment, ida_ua
import idautils, idc

OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\nicam288_writers_report.txt"

NI_CAMERA_VTBL_RVA = 0x267DD50

def image_base():
    return ida_nalt.get_imagebase()

def ea2rva(ea):
    return ea - image_base()

def rva2ea(rva):
    return image_base() + rva

def log(msg, fh):
    print(msg)
    fh.write(msg + "\n")
    fh.flush()

def safe_decomp_str(ea):
    try:
        cf = ida_hexrays.decompile(ea)
        if cf is None:
            return None
        return str(cf)
    except Exception:
        return None

def func_name_at(ea):
    fn = ida_funcs.get_func(ea)
    if not fn:
        return None
    return ida_funcs.get_func_name(fn.start_ea)

def grep_288(decomp_src):
    """Return list of snippets mentioning offset 288 (0x120)."""
    hits = []
    if not decomp_src:
        return hits
    needles = ("a1 + 288", "+ 288)", "+ 288]",
               "+ 0x120)", "+ 0x120]", "(a2 + 288)",
               "this + 288", "this + 0x120",
               "(v1 + 288)", "(v2 + 288)", "(v3 + 288)",
               "(v4 + 288)", "(v5 + 288)", "(v6 + 288)",
               "(v7 + 288)", "(v8 + 288)", "(v9 + 288)")
    for line in decomp_src.splitlines():
        if any(n in line for n in needles):
            hits.append(line.strip())
    return hits

def main():
    ida_auto.auto_wait()
    with open(OUT, "w", encoding="utf-8") as fh:
        log(f"image base: 0x{image_base():X}", fh)
        vtbl_ea = rva2ea(NI_CAMERA_VTBL_RVA)

        # --- 1. All NiCamera virtual methods (vtable slots 0..35) ---
        log("\n==== NiCamera vtable methods scanned for +288 access ====", fh)
        per_slot_hits = []
        for i in range(40):
            ptr = ida_bytes.get_qword(vtbl_ea + i*8)
            if ptr == 0 or ptr == idc.BADADDR:
                break
            fn = ida_funcs.get_func(ptr)
            if not fn:
                continue
            src = safe_decomp_str(fn.start_ea)
            hits = grep_288(src)
            name = func_name_at(ptr) or "?"
            if hits:
                log(f"  [{i:2}] RVA 0x{ea2rva(fn.start_ea):X} {name}  "
                    f"— {len(hits)} hits", fh)
                for h in hits[:8]:
                    log(f"       {h}", fh)
                per_slot_hits.append((i, fn.start_ea, name, hits))
            else:
                log(f"  [{i:2}] RVA 0x{ea2rva(fn.start_ea):X} {name}  "
                    f"(no +288 reference)", fh)

        # --- 2. Linear .text scan for 'movups xmmword [reg+120h]' writes ---
        # x64 instruction bytes for movups xmmword ptr [reg+120h], xmm0:
        # prefix_0F 11 followed by ModR/M with disp32=0x00000120.
        # Also movaps (prefix_0F 29) or 64-bit mov (48 89 .. 20 01 00 00).
        #
        # Simplest sane approach: scan all functions, decompile, grep for
        # writes (lines with " = " and "+ 288" on LHS).
        log("\n==== Full-function grep: functions whose decomp WRITES to +288 ====", fh)
        writers = []
        total_funcs = 0
        scanned_funcs = 0
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            if not seg or seg.type != ida_segment.SEG_CODE:
                continue
            ea = seg.start_ea
            end = seg.end_ea
            fn = ida_funcs.get_next_func(ea - 1)
            while fn and fn.start_ea < end:
                total_funcs += 1
                # Heuristic: only bother with funcs where the start has
                # some reasonable size (avoid tiny thunks).
                if fn.end_ea - fn.start_ea < 12:
                    fn = ida_funcs.get_next_func(fn.start_ea)
                    continue
                # Skip if start not in .text at all (shouldn't happen)
                src = safe_decomp_str(fn.start_ea)
                if not src:
                    fn = ida_funcs.get_next_func(fn.start_ea)
                    continue
                scanned_funcs += 1
                # Look for WRITE pattern: "(... + 288) = " or "(... + 0x120) = "
                write_hits = []
                for line in src.splitlines():
                    ls = line.strip()
                    if (("+ 288)" in ls or "+ 0x120)" in ls)
                        and "=" in ls
                        and ") = " in ls
                        # ensure LHS has the pattern, not RHS
                        and ls.index(") = ") > ls.find("+ 288") >= 0):
                        write_hits.append(ls)
                if write_hits:
                    writers.append((fn.start_ea,
                                     func_name_at(fn.start_ea) or "?",
                                     write_hits[:6]))
                fn = ida_funcs.get_next_func(fn.start_ea)

        log(f"\n  total funcs iterated: {total_funcs}, decomp-scanned: {scanned_funcs}", fh)
        log(f"  funcs with WRITE to +288: {len(writers)}", fh)
        for (fn_ea, name, hits) in writers[:60]:
            log(f"\n  ---- 0x{fn_ea:X} RVA 0x{ea2rva(fn_ea):X}  {name} ----", fh)
            for h in hits:
                log(f"    {h}", fh)

        # --- 3. Deep decomp of top 5 writers ---
        log(f"\n\n==== Deep decomp of first {min(5, len(writers))} writers ====", fh)
        for (fn_ea, name, _) in writers[:5]:
            src = safe_decomp_str(fn_ea)
            if src:
                log(f"\n######## {name} @ RVA 0x{ea2rva(fn_ea):X} ########", fh)
                if len(src) > 5000:
                    src = src[:5000] + f"\n... (truncated, total {len(src)} chars)"
                log(src, fh)

        log("\n==== Done ====", fh)

main()
