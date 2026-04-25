"""Same as 10 but with diagnostic counters."""
import idaapi, idautils, idc, ida_funcs

OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\depth_final_report10b.txt"
LOG = []
def W(s): LOG.append(str(s)); print(s)
idaapi.auto_wait()

TARGETS = {0x28,0x48,0xA0,0xE8,0x108,0x120,0x190,0x1A8}
num_funcs = ida_funcs.get_func_qty()
W(f"[*] total functions: {num_funcs}")

total_insns = 0
total_calls = 0
total_displ_calls = 0
displ_hist = {}

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
        total_insns += 1
        if insn.itype in (idaapi.NN_call, idaapi.NN_callfi):
            total_calls += 1
            op = insn.ops[0]
            if op.type == idaapi.o_displ:
                total_displ_calls += 1
                d = op.addr & 0xFFFFFFFFFFFFFFFF
                displ_hist[d] = displ_hist.get(d, 0) + 1
        ea += insn.size
        if insn.size == 0:  # safety
            break

W(f"[*] insns scanned: {total_insns}")
W(f"[*] total calls: {total_calls}")
W(f"[*] total displ calls: {total_displ_calls}")
# Top 100 disp values
top = sorted(displ_hist.items(), key=lambda kv:-kv[1])[:60]
W("[*] top 60 disp values:")
for d, c in top:
    W(f"   disp={d:#x}  count={c}")
# Specific targets
W("[*] our targets:")
for t in sorted(TARGETS):
    W(f"   disp={t:#x}: {displ_hist.get(t, 0)}")

with open(OUT, "w", encoding="utf-8") as f: f.write("\n".join(LOG))
idc.qexit(0)
