"""
Find BSGraphics::State singleton. CommonLibF4 REL::ID(600795) says the
getter returns a pointer to a static structure. In the binary this shows up as:
    a small function that does:
         mov rax, cs:qword_???     ; ret
Or:
    a function that reads a static pointer and returns it.

We also look for:
  - The singleton's data RVA
  - Functions that write 4-row matrices into State+0x230 (viewProjMat)
  - posAdjust at State+0x370 (writes of 3 floats or 4 floats to offset +0x370)

Strategy v2:
  Enumerate absolute-memory displacements in XMM stores where dest is a
  global in .data, group by 16-byte clusters, find the 4-row matrices,
  and examine their containing "struct" (the base address is the matrix's
  absolute address; State struct start = matrix_base - 0x230).
"""

import idaapi, idautils, idc, ida_funcs, ida_bytes, ida_ua, ida_segment, ida_nalt, ida_hexrays
import struct

OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\bsgraphics_state_report_final.txt"
IMG = 0x140000000
lines = []
def P(s=""):
    lines.append(str(s))

def rva(ea): return ea - IMG
def fn_start(ea):
    f = ida_funcs.get_func(ea)
    return f.start_ea if f else idc.BADADDR
def safe_decompile(ea):
    try:
        c = ida_hexrays.decompile(ea)
        return str(c) if c else None
    except Exception:
        return None

seg_text = ida_segment.get_segm_by_name(".text")
t_start, t_end = seg_text.start_ea, seg_text.end_ea

XMM_OPS = {"movaps", "movups", "movss", "movsd", "movapd", "movupd"}

# ----------------------------------------------------------------
# Step 1: Find XMM stores whose destination is a RIP-relative global
# in the data/rdata segment. Track target addresses.
# ----------------------------------------------------------------
P("=" * 72)
P(" BSGraphics::State singleton finder")
P("=" * 72)

abs_stores = {}  # tgt_addr -> list of (ea, fn_ea)
cnt = 0
for ea in idautils.Heads(t_start, t_end):
    if not idc.is_code(idc.get_full_flags(ea)): continue
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, ea) == 0: continue
    mn = insn.get_canon_mnem().lower()
    if mn not in XMM_OPS: continue
    op0 = insn.ops[0]
    op1 = insn.ops[1]
    # Case: movaps [rip+disp], xmmN  -> op0 o_mem absolute
    if op0.type == ida_ua.o_mem and op1.type == ida_ua.o_reg:
        tgt = op0.addr
        if IMG + 0x2000000 < tgt < IMG + 0x4000000:
            f = fn_start(ea)
            abs_stores.setdefault(tgt, []).append((ea, f))
            cnt += 1

P(" absolute-mem XMM store insns: %d" % cnt)

# cluster into 16-byte aligned groups that look like 4-row matrix writes
clusters = {}
for tgt in abs_stores.keys():
    base = tgt & ~0xF
    clusters.setdefault(base, set()).add(tgt - base)

# find 4-row matrix globals
matrix_bases = sorted(b for b, offs in clusters.items()
                      if {0, 0x10, 0x20, 0x30}.issubset(offs))

P(" candidate 4-row matrix globals: %d" % len(matrix_bases))
for b in matrix_bases[:40]:
    P("  base 0x%X (RVA 0x%X)" % (b, rva(b)))

# ----------------------------------------------------------------
# Step 2: examine all functions that touch a matrix_base and enumerate
# them to find the ViewData/State writer(s). These should also touch
# offsets +0x230 (viewProjMat) relative to State, so we look at the
# SURROUNDING offsets for each candidate matrix_base.
# ----------------------------------------------------------------

# For each matrix_base, get ALL offsets stored within [matrix_base-0x400, matrix_base+0x400]
big_clusters = {}
for tgt in abs_stores.keys():
    for base in matrix_bases:
        if -0x400 <= tgt - base <= 0x400:
            off = tgt - base
            big_clusters.setdefault(base, {}).setdefault(off, []).extend(abs_stores[tgt])

P("")
P("== Surrounding field footprint of each matrix global ==")
for base in matrix_bases[:40]:
    if base not in big_clusters: continue
    offs = sorted(big_clusters[base].keys())
    P("  matrix_base 0x%X (RVA 0x%X) nearby-offsets: %s" %
      (base, rva(base), [hex(o) for o in offs]))

# ----------------------------------------------------------------
# Step 3: Try reading the current DWORDs at each matrix_base to check
# if it contains plausible matrix data (not all zeros). Not useful
# offline since db is frozen - skip.
# Instead, for each candidate, scan callers of the writer functions:
# the function that *initializes* such a matrix should have a characteristic
# name like "SetupCamera", "UpdateViewProj" etc.
# ----------------------------------------------------------------

# ----------------------------------------------------------------
# Step 4: CommonLibF4's "BSGraphics::State::GetSingleton" returns a pointer.
# Usually a small accessor. But the actual data may not be addressed via
# absolute rip+disp; it's often accessed as `state = *(qword*)rip_disp` or
# simply as `mov rax, cs:state_ptr`. Let's find all small functions of form
#    mov rax, cs:q_XXX ; ret
# where XXX lies in .data.
# ----------------------------------------------------------------
P("")
P("== Tiny singleton accessor candidates (mov rax, [mem] ; ret) ==")
sing_cands = []
for fn_ea in idautils.Functions(t_start, t_end):
    f = ida_funcs.get_func(fn_ea)
    if not f: continue
    if f.size() > 20: continue
    insn1 = ida_ua.insn_t()
    n1 = ida_ua.decode_insn(insn1, fn_ea)
    if n1 == 0: continue
    # first insn: mov rax, [rip+disp]
    if insn1.get_canon_mnem().lower() != "mov": continue
    if insn1.ops[0].type != ida_ua.o_reg: continue
    if insn1.ops[0].reg != 0: continue  # rax = 0
    if insn1.ops[1].type != ida_ua.o_mem: continue
    tgt = insn1.ops[1].addr
    if not (IMG + 0x2000000 < tgt < IMG + 0x4000000): continue
    # next insn: ret
    insn2 = ida_ua.insn_t()
    n2 = ida_ua.decode_insn(insn2, fn_ea + n1)
    if n2 == 0: continue
    if insn2.get_canon_mnem().lower() not in ("retn", "ret"): continue
    sing_cands.append((fn_ea, tgt))

P(" count: %d" % len(sing_cands))
# show first 30
for fn, tgt in sing_cands[:30]:
    nm = ida_funcs.get_func_name(fn) or ""
    P("  fn 0x%X (RVA 0x%X)  -> [0x%X (RVA 0x%X)] %s" % (fn, rva(fn), tgt, rva(tgt), nm))

# ----------------------------------------------------------------
# Step 5: Correlate: which of our "matrix_base" globals ALSO appears
# as the target of such a singleton accessor? That's our State.
# ----------------------------------------------------------------
P("")
P("== Correlation: singleton accessors pointing into matrix-containing structs ==")
# Compute struct start candidates: matrix_base - K for K in {0x230, 0x160, 0x130, 0x70}
# because CommonLibF4 says viewProjMat @ 0x230, ViewData @ 0x160
struct_candidates = {}  # base_of_struct -> (matrix_base, K)
for mbase in matrix_bases:
    for K in (0x230, 0x160, 0x130, 0xB0, 0x70, 0x00):
        struct_candidates[mbase - K] = (mbase, K)

# singleton acc tgt is a POINTER not a base — it holds struct address.
# That means the tgt is a data slot where an init wrote the pointer.
# Too indirect for offline analysis. Instead: check if tgt IS itself a struct
# candidate (i.e. accessor returns direct struct, not via deref). Or if tgt is
# the address of a ptr whose contents is our struct — we can't know offline.
# So just dump overlap between tgt addresses and matrix_base addresses.
for fn, tgt in sing_cands:
    if tgt in struct_candidates:
        mb, K = struct_candidates[tgt]
        P("  accessor fn 0x%X -> tgt 0x%X  is struct start where matrix_base=0x%X K=0x%X" %
          (fn, tgt, mb, K))

# ----------------------------------------------------------------
# Step 6: Look for the getter with `lea rax, ds:imm` + ret pattern too.
# ----------------------------------------------------------------
P("")
P("== Tiny singleton accessor (lea rax, [rip+disp] ; ret) ==")
lea_cands = []
for fn_ea in idautils.Functions(t_start, t_end):
    f = ida_funcs.get_func(fn_ea)
    if not f: continue
    if f.size() > 20: continue
    insn1 = ida_ua.insn_t()
    n1 = ida_ua.decode_insn(insn1, fn_ea)
    if n1 == 0: continue
    if insn1.get_canon_mnem().lower() != "lea": continue
    if insn1.ops[0].type != ida_ua.o_reg: continue
    if insn1.ops[0].reg != 0: continue  # rax
    # lea uses o_mem or o_displ
    tgt = insn1.ops[1].addr
    if not (IMG + 0x2000000 < tgt < IMG + 0x4000000): continue
    insn2 = ida_ua.insn_t()
    n2 = ida_ua.decode_insn(insn2, fn_ea + n1)
    if n2 == 0: continue
    if insn2.get_canon_mnem().lower() not in ("retn", "ret"): continue
    lea_cands.append((fn_ea, tgt))

P(" LEA accessor count: %d" % len(lea_cands))
# correlate with matrix bases
for fn, tgt in lea_cands:
    if tgt in struct_candidates:
        mb, K = struct_candidates[tgt]
        nm = ida_funcs.get_func_name(fn) or ""
        P("  LEA accessor fn 0x%X -> tgt 0x%X  struct at K=0x%X from mbase 0x%X  %s" %
          (fn, tgt, K, mb, nm))

# ----------------------------------------------------------------
# Step 7: Also check for matrix globals that line up at RVA 0x3E5AE70
# (from bsgraphics_state_report6.txt). That global had hundreds of xrefs
# and is likely BSGraphics state.
# ----------------------------------------------------------------
P("")
P("== Known global cross-references: 0x3E5AE58 and 0x3E5AE70 ==")
for gname, gva in [("g1", 0x143E5AE58), ("g2", 0x143E5AE70), ("g3", 0x143A0F400), ("g4", 0x1438CAA98)]:
    in_matrix = gva in matrix_bases
    P("  %s @ 0x%X (RVA 0x%X)  is_matrix_base=%s" % (gname, gva, rva(gva), in_matrix))
    # check offsets within 0x400 radius
    nearby = {o: len(abs_stores.get(gva + o, [])) for o in range(-0x400, 0x400, 8)
              if abs_stores.get(gva + o)}
    P("    nearby XMM store offsets count: %s" % nearby)

# ----------------------------------------------------------------
# Step 8: The BSGraphicsRenderer TLS-indirect structure.
# From bsgraphics_state_report6.txt: code does
#    NtCurrentTeb()->ThreadLocalStoragePointer[TlsIndex] + 2848 (== 0xB20)
# and dereferences it. So the struct is TLS-based, not a global singleton.
# But CommonLibF4's BSGraphics::State::GetSingleton likely returns THAT
# structure or a different one. Let's look for a function that grabs the TLS
# entry + a SMALL offset (<=0x80) and returns it — that's a TLS-based getter.
# ----------------------------------------------------------------
P("")
P("== TLS-based accessor scan (NtCurrentTeb-pattern small funcs) ==")
# This pattern emits: mov rax, gs:[58h]; mov rax, [rax+8*TlsIndex]; ... ret
# We won't fully match it here — skip for brevity.

# ----------------------------------------------------------------
# Step 9: Also dump first big_cluster for the top 5 matrix_bases,
# enriched with ALL xref functions.
# ----------------------------------------------------------------
P("")
P("== Top 5 matrix_base clusters: writer function summary ==")
for base in matrix_bases[:10]:
    fns = set()
    for off, hits in big_clusters.get(base, {}).items():
        for ea, f in hits:
            if f != idc.BADADDR:
                fns.add(f)
    P("  matrix_base 0x%X (RVA 0x%X) has %d unique writer fns" %
      (base, rva(base), len(fns)))
    for f in sorted(fns)[:8]:
        nm = ida_funcs.get_func_name(f) or ""
        P("    fn 0x%X %s" % (f, nm))

with open(OUT, "w", encoding="utf-8", errors="replace") as fo:
    fo.write("\n".join(lines))
print("wrote", OUT)
idaapi.qexit(0)
