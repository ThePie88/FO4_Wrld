"""All writes by sub_142171620 (BSLSP ctor) + sub_142160DA0 (parent init) +
   sub_142161B10 (install material) — establishes what's STILL uninit after our code runs."""
import os
RE_DIR = r"C:\Users\filip\Desktop\FalloutWorld\re"
EXE    = os.path.join(RE_DIR, "Fallout4.exe")
IMG    = 0x140000000
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import *
pe = pefile.PE(EXE, fast_load=True)
for s in pe.sections:
    n = s.Name.rstrip(b'\x00').decode('ascii', errors='replace')
    if n == '.text':
        text_va = IMG + s.VirtualAddress
        text_data = s.get_data()
        break
def read(va, n):
    off = va - text_va
    return text_data[off:off+n]
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

def writes_from(va, sz):
    buf = read(va, sz)
    reg_tag = {X86_REG_RCX:"THIS"}
    writes = {}
    for ins in md.disasm(buf, va):
        if ins.mnemonic in ('mov','movsd','movss','movaps','movups','movdqa','movdqu','and','or'):
            if len(ins.operands) < 2:
                continue
            dst = ins.operands[0]
            src = ins.operands[1]
            if dst.type == X86_OP_REG and src.type == X86_OP_REG:
                reg_tag[dst.reg] = reg_tag.get(src.reg)
            elif dst.type == X86_OP_REG:
                reg_tag[dst.reg] = None
            elif dst.type == X86_OP_MEM:
                m = dst.mem
                base_tag = reg_tag.get(m.base) if m.base else None
                if base_tag == "THIS":
                    writes.setdefault(m.disp, []).append((dst.size, ins.address, ins.mnemonic, ins.op_str))
    return writes

for (name, va, sz) in [
    ("sub_142160DA0 (parent init for BSLSP)", 0x142160DA0, 0x80),
    ("sub_142171620 (BSLSP ctor)",            0x142171620, 0x110),
    ("sub_142161B10 (install material)",      0x142161B10, 0x120),
]:
    print(f"\n== {name} @ {va:#x} ==")
    w = writes_from(va, sz)
    for d in sorted(w):
        for sz2, addr, mn, ops in w[d]:
            print(f"  +{d:#06x}  sz={sz2}  @ {addr:#x}  {mn} {ops}")
