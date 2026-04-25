"""Debug: count ALL call [reg+disp] for ALL disp, print disp values of interest."""
import idaapi, idautils, idc, ida_funcs

OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\depth_final_report10.txt"
LOG = []
def W(s): LOG.append(str(s)); print(s)
idaapi.auto_wait()
imagebase = idaapi.get_imagebase()
def rva(ea): return ea - imagebase

TARGETS = {
    0x28:"CreateTexture2D",
    0x48:"CreateDepthStencilView",
    0xA0:"CreateDepthStencilState",
    0xE8:"GetData (sanity)",
    0x108:"OMSetRenderTargets",
    0x120:"OMSetDepthStencilState",
    0x190:"ClearRenderTargetView",
    0x1A8:"ClearDepthStencilView",
}

counts = {d:[] for d in TARGETS}
num_funcs = ida_funcs.get_func_qty()
for fi in range(num_funcs):
    fn = ida_funcs.getn_func(fi)
    if not fn: continue
    ea = fn.start_ea
    while ea < fn.end_ea:
        insn = idautils.DecodeInstruction(ea)
        if not insn: ea = idc.next_head(ea, fn.end_ea); continue
        if insn.itype in (idaapi.NN_call, idaapi.NN_callfi):
            op = insn.ops[0]
            if op.type == idaapi.o_displ:
                d = op.addr & 0xFFFFFFFFFFFFFFFF
                if d > 0x7FFFFFFFFFFFFFFF: d -= 0x10000000000000000
                if d in TARGETS:
                    counts[d].append(ea)
        ea += insn.size

W("[*] counts of indirect calls by disp:")
for d, lst in sorted(counts.items()):
    W(f"   disp={d:#x} ({TARGETS[d]}): {len(lst)} calls")

# Show samples for each
for d, lst in counts.items():
    if not lst: continue
    W(f"\n  {TARGETS[d]} (disp={d:#x}) — first 15 sites:")
    for ea in lst[:15]:
        fn = idaapi.get_func(ea)
        fr = rva(fn.start_ea) if fn else 0
        dl = idc.generate_disasm_line(ea, 0)
        W(f"    {ea:#x}: {dl}  (fn RVA{fr:#x})")

W("\n[DONE]")
with open(OUT, "w", encoding="utf-8") as f: f.write("\n".join(LOG))
idc.qexit(0)
