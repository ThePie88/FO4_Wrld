"""Depth RE v13 - Authoritative pass. Decompile ctx_A/ctx_B xref functions
to see REAL D3D11 calls being made.
"""
import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, struct

OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\depth_final_report13.txt"
LOG = []
def W(s): LOG.append(str(s)); print(s)
idaapi.auto_wait()
ida_hexrays.init_hexrays_plugin()
imagebase = idaapi.get_imagebase()
def rva(ea): return ea - imagebase

CTX_A = 0x1438CAA90
CTX_B = 0x1438CAAB8
DEVICE = 0x1438CAAA8

# Collect all functions that read ctx_A, ctx_B, or DEVICE
def get_reader_funcs(glob):
    fns = set()
    for xr in idautils.XrefsTo(glob):
        fn = idaapi.get_func(xr.frm)
        if fn: fns.add(fn.start_ea)
    return fns

ctx_funcs = get_reader_funcs(CTX_A) | get_reader_funcs(CTX_B)
dev_funcs = get_reader_funcs(DEVICE)

W(f"[*] ctx-reader funcs: {len(ctx_funcs)}")
W(f"[*] device-reader funcs: {len(dev_funcs)}")
for fe in sorted(ctx_funcs):
    W(f"   CTX reader: RVA{rva(fe):#x} ({idc.get_func_name(fe)})")
W("")
for fe in sorted(dev_funcs):
    W(f"   DEV reader: RVA{rva(fe):#x} ({idc.get_func_name(fe)})")

# Now decompile each device function and extract D3D11 call patterns
# Typical pattern: (*(X (__fastcall **)(Y, Z))(v1->lpVtbl->Method))(...) or more generally
# (*(f **)(*(_QWORD *)vctx + OFFSET))(vctx, ...)
# We'll look for lines containing "+ 0xA0LL)" or "+ 160LL)" with context var.

W("\n\n" + "="*72)
W("DEVICE reader functions — extract CreateDepthStencilState / CreateTexture2D / CreateDSV")
W("="*72)
for fe in sorted(dev_funcs):
    try:
        cf = ida_hexrays.decompile(fe)
        if not cf: continue
        src = str(cf)
        # Grab lines with 160LL, 72LL, 40LL, 160LL, 0xA0, 0x28, 0x48 references
        # More general: any "+ NNLL)" or "+ 0xNNLL)"
        interesting = []
        for i, line in enumerate(src.split("\n")):
            if any(k in line for k in (
                "160LL", "0xA0LL", "72LL", "0x48LL",
                "40LL", "0x28LL",
                "(__int64 (__fastcall **)",
                "(*(_QWORD *)",
                "DepthStencil", "Stencil",
            )):
                interesting.append((i, line))
        if interesting:
            W(f"\n-- RVA{rva(fe):#x} ({idc.get_func_name(fe)}) {len(interesting)} interesting lines --")
            for i, line in interesting[:30]:
                W(f"  {i:4d}: {line}")
    except Exception as e:
        pass

# Now do same for CTX reader funcs
W("\n\n" + "="*72)
W("CTX reader functions — extract OMSet / ClearDSV patterns")
W("="*72)
for fe in sorted(ctx_funcs):
    try:
        cf = ida_hexrays.decompile(fe)
        if not cf: continue
        src = str(cf)
        interesting = []
        for i, line in enumerate(src.split("\n")):
            if any(k in line for k in (
                "264LL", "0x108LL", "288LL", "0x120LL",
                "400LL", "0x190LL", "424LL", "0x1A8LL",
                "0x1a8", "0x108", "0x120",
                "(__int64 (__fastcall **)",
                "qword_1438CAA90", "qword_1438CAAB8",
            )):
                interesting.append((i, line))
        if interesting:
            W(f"\n-- RVA{rva(fe):#x} ({idc.get_func_name(fe)}) {len(interesting)} lines --")
            for i, line in interesting[:30]:
                W(f"  {i:4d}: {line}")
    except Exception as e:
        pass

# Look for specific offsets:
# ClearDepthStencilView = 424/0x1A8
# OMSetRenderTargets    = 264/0x108
# OMSetDepthStencilState= 288/0x120
# Now also scan for numeric markers (decimal) that correspond to our offsets.
W("\n\n" + "="*72)
W("Specific offset string search in ALL functions (including non-global-reader)")
W("="*72)

# Just grep the full idapp asm text for interesting offsets.
# Simpler: for each call site we already found with disp 0x1A8, print asm context
# and see if ANY of them match the BSGraphics ctx pattern properly.
# But since we saw 178 total, let's classify differently: for each of 178 sites,
# walk back to find the origin of the base register (may be deep).
W("\n[SCAN] Recursively trace base of call [reg+0x1A8h]:")
def trace_reg_to_global(call_ea, reg, depth=0, max_depth=6):
    """Walk backward from call_ea to find what `reg` ultimately comes from.
    Handles: mov reg, reg / mov reg, [reg] / mov reg, [reg+N] / mov reg, cs:global."""
    if depth > max_depth: return None
    cur = call_ea
    fn = idaapi.get_func(call_ea)
    if not fn: return None
    fn_start = fn.start_ea
    for _ in range(200):
        cur = idc.prev_head(cur)
        if cur < fn_start or cur == idaapi.BADADDR: return None
        m = idc.print_insn_mnem(cur).lower()
        op0_str = idc.print_operand(cur, 0).lower()
        if op0_str != reg: continue
        if m != "mov": return ("clobbered", cur)
        insn = idautils.DecodeInstruction(cur)
        if not insn: return None
        op1 = insn.ops[1]
        # mov reg, cs:global
        if op1.type == idaapi.o_mem:
            return ("global", op1.addr, cur, depth)
        # mov reg, [src_reg]
        if op1.type == idaapi.o_phrase:
            src_str = idc.print_operand(cur, 1).lower()
            # Extract inner reg
            inner = src_str.strip("[]").replace("qword ptr ", "").strip()
            # Strip "qword ptr" prefix variants
            if "[" in inner: inner = inner.split("[")[-1].strip("]")
            return trace_reg_to_global(cur, inner, depth+1, max_depth)
        # mov reg, [src_reg + N]
        if op1.type == idaapi.o_displ:
            src_str = idc.print_operand(cur, 1).lower()
            # Extract src reg
            import re
            m2 = re.search(r"\[([a-z0-9]+)", src_str)
            if m2:
                src = m2.group(1)
                # We don't know the offset, but often ctx is at rsp+N after save/restore
                if src in ("rsp", "rbp"): return ("stack", op1.addr, cur, depth)
                return trace_reg_to_global(cur, src, depth+1, max_depth)
            return ("displ", op1.addr, cur, depth)
        if op1.type == idaapi.o_reg:
            src = idc.print_operand(cur, 1).lower()
            return trace_reg_to_global(cur, src, depth+1, max_depth)
        return ("unknown", 0, cur, depth)
    return None

# Enumerate all 1A8 sites from the binary
num_funcs = ida_funcs.get_func_qty()
sites_1a8 = []
sites_a0 = []
sites_28 = []
sites_108 = []
sites_48 = []
for fi in range(num_funcs):
    fn = ida_funcs.getn_func(fi)
    if not fn: continue
    ea = fn.start_ea
    while ea < fn.end_ea:
        insn = idautils.DecodeInstruction(ea)
        if not insn:
            ea = idc.next_head(ea, fn.end_ea)
            if ea == idaapi.BADADDR: break
            continue
        m = insn.get_canon_mnem()
        if m.startswith("call"):
            op = insn.ops[0]
            if op.type == idaapi.o_displ:
                d = op.addr & 0xFFFFFFFFFFFFFFFF
                if d == 0x1A8: sites_1a8.append(ea)
                elif d == 0xA0: sites_a0.append(ea)
                elif d == 0x28: sites_28.append(ea)
                elif d == 0x108: sites_108.append(ea)
                elif d == 0x48: sites_48.append(ea)
        ea += insn.size
        if insn.size == 0: break

W(f"  sites disp 0x1A8: {len(sites_1a8)}")
W(f"  sites disp 0xA0:  {len(sites_a0)}")
W(f"  sites disp 0x28:  {len(sites_28)}")
W(f"  sites disp 0x108: {len(sites_108)}")
W(f"  sites disp 0x48:  {len(sites_48)}")

# Trace origin of each ClearDSV site
def classify_sites_deep(sites):
    tags = {}
    details = []
    for ea in sites:
        base = None
        try:
            opstr = idc.print_operand(ea, 0).lower()
            import re
            m = re.search(r"\[([a-z0-9]+)", opstr)
            if m: base = m.group(1)
        except: pass
        if not base:
            tags["no_base"] = tags.get("no_base", 0) + 1
            details.append((ea, "no_base", None))
            continue
        res = trace_reg_to_global(ea, base, 0, 8)
        if not res:
            tags["no_trace"] = tags.get("no_trace", 0) + 1
            details.append((ea, "no_trace", None))
            continue
        kind = res[0]
        if kind == "global":
            val = res[1]
            if val == CTX_A: k = "ctx_A"
            elif val == CTX_B: k = "ctx_B"
            elif val == DEVICE: k = "device"
            else: k = f"other_{val:#x}"
            tags[k] = tags.get(k, 0) + 1
            details.append((ea, k, val))
        else:
            tags[kind] = tags.get(kind, 0) + 1
            details.append((ea, kind, res))
    return tags, details

for lbl, sites in (("ClearDSV 0x1A8", sites_1a8), ("CreateDSS 0xA0", sites_a0),
                   ("CreateTex2D 0x28", sites_28), ("OMSetRT 0x108", sites_108),
                   ("CreateDSV 0x48", sites_48)):
    tags, details = classify_sites_deep(sites)
    W(f"\n{lbl} — classification tags (deep trace): {tags}")
    # Show first 20 that had ctx or device tag
    for ea, tag, extra in details[:40]:
        if tag in ("ctx_A", "ctx_B", "device") or "other" in tag:
            fn = idaapi.get_func(ea); fr = rva(fn.start_ea) if fn else 0
            W(f"    RVA{rva(ea):#x} tag={tag}  fn RVA{fr:#x}")

W("\n[DONE]")
with open(OUT, "w", encoding="utf-8") as f: f.write("\n".join(LOG))
idc.qexit(0)
