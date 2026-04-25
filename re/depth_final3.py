"""Depth RE v3 - probe operand types for vtable calls."""
import idaapi, idautils, idc, ida_funcs, struct

OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\depth_final_report3.txt"
LOG = []
def W(s=""):
    LOG.append(str(s))
    print(s)

idaapi.auto_wait()
imagebase = idaapi.get_imagebase()
W(f"[*] imagebase = {imagebase:#x}")

# Probe ALL call insns, count per op-type / disp values seen
OPTYPES = {0:"void",1:"reg",2:"mem",3:"phrase",4:"displ",5:"imm",6:"far",7:"near",8:"idpspec0"}

num_funcs = ida_funcs.get_func_qty()
W(f"[*] total functions: {num_funcs}")

call_probe = {}  # op_type -> count
disp_histogram = {}  # disp value -> count (for displ operands)

# Also collect sample bytes for first few 'call [reg+disp]'
samples = []

total_call_indirect = 0
total_insns = 0
for fi in range(num_funcs):
    fn = ida_funcs.getn_func(fi)
    if not fn:
        continue
    ea = fn.start_ea
    while ea < fn.end_ea:
        insn = idautils.DecodeInstruction(ea)
        if not insn:
            ea = idc.next_head(ea, fn.end_ea)
            if ea == idaapi.BADADDR:
                break
            continue
        total_insns += 1
        if insn.itype in (idaapi.NN_call, idaapi.NN_callfi, idaapi.NN_callni):
            op = insn.ops[0]
            call_probe[op.type] = call_probe.get(op.type, 0) + 1
            if op.type == idaapi.o_displ:
                total_call_indirect += 1
                disp = op.addr
                # canonicalize to signed
                if disp > 0x7FFFFFFFFFFFFFFF:
                    disp -= 0x10000000000000000
                disp_histogram[disp] = disp_histogram.get(disp, 0) + 1
                if len(samples) < 25 and disp in (0x1A8, 0x1A0, 0x108, 0x120, 0x28, 0xA0, 0x48):
                    samples.append((ea, disp, idc.generate_disasm_line(ea, 0)))
        ea = ea + insn.size
W(f"[*] total insns: {total_insns}")
W(f"[*] call op types: { {OPTYPES.get(k,k): v for k,v in call_probe.items()} }")
W(f"[*] total call displ: {total_call_indirect}")
W("[*] top 40 disp values for 'call [reg+disp]':")
for d, c in sorted(disp_histogram.items(), key=lambda kv:-kv[1])[:40]:
    W(f"   disp={d:#x}  count={c}")
W("[*] samples at slot-of-interest displ:")
for ea, disp, dl in samples:
    W(f"   {ea:#x}  disp={disp:#x}  {dl}")

with open(OUT, "w", encoding="utf-8") as f:
    f.write("\n".join(LOG))
W(f"\nReport: {OUT}")
idc.qexit(0)
