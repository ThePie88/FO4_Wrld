"""Identify every offset the material ctor TOUCHES, identify the GAPS that remain
   uninitialized even after ctor runs."""
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

def fn_writes(va, sz):
    """Return dict disp → (size_bytes_written, source_va)"""
    buf = read(va, sz)
    out = {}
    # Track what base reg represents: on entry rcx = THIS
    reg_tag = {X86_REG_RCX:"THIS", X86_REG_RBX:None, X86_REG_RAX:None}
    for ins in md.disasm(buf, va):
        if ins.mnemonic in ('mov','movsd','movss','movaps','movups','movdqa','movdqu'):
            if len(ins.operands) < 2:
                continue
            dst = ins.operands[0]
            src = ins.operands[1]
            # reg<-reg copy
            if dst.type == X86_OP_REG and src.type == X86_OP_REG:
                reg_tag[dst.reg] = reg_tag.get(src.reg)
            # reg<-mem  (doesn't propagate THIS unless something special)
            elif dst.type == X86_OP_REG:
                reg_tag[dst.reg] = None
            # mem<-* : write
            elif dst.type == X86_OP_MEM:
                m = dst.mem
                base_tag = reg_tag.get(m.base) if m.base else None
                if base_tag == "THIS":
                    size = dst.size
                    out.setdefault(m.disp, []).append((size, ins.address, ins.mnemonic, ins.op_str))
    return out

writes = fn_writes(0x1421C5CE0, 0x13D)
print(f"BSLightingShaderMaterialBase ctor writes ({len(writes)} distinct offsets):")
covered = set()
for disp in sorted(writes):
    for sz, addr, mn, ops in writes[disp]:
        print(f"  +{disp:#06x}  sz={sz}  @ {addr:#x}  {mn} {ops}")
        for b in range(disp, disp+sz):
            covered.add(b)

print(f"\nTotal bytes covered in [0x0, 0xC0): {len([b for b in covered if 0 <= b < 0xC0])}/192")
print(f"Gaps (uncovered offsets) in [0x0, 0xC0):")
gaps_start = None
gaps = []
for b in range(0, 0xC0):
    if b in covered:
        if gaps_start is not None:
            gaps.append((gaps_start, b))
            gaps_start = None
    else:
        if gaps_start is None:
            gaps_start = b
if gaps_start is not None:
    gaps.append((gaps_start, 0xC0))
for (a, b) in gaps:
    print(f"  +{a:#06x} .. +{b:#06x}  ({b-a} bytes)")

print()
print("NiRefObject base is typically the first 0x10 bytes (vtable + refcount)")
print("- +0x00 vtable -> covered")
print("- +0x08 refcount(+0x08) -> normally NiRefObject::ctor sets refcount=0; ")
print("  ctor_1421C5CE0 does NOT explicitly write it (no +0x8 line)")
print("  but sub_1421D6700 at entry probably DOES.")
