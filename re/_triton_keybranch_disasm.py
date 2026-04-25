"""Dump disassembly around the critical early-reject in sub_142172540
   plus full disasm of vt[51] and vt[50]."""

import os
RE_DIR = r"C:\Users\filip\Desktop\FalloutWorld\re"
EXE    = os.path.join(RE_DIR, "Fallout4.exe")
IMG    = 0x140000000

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE(EXE, fast_load=True)
for s in pe.sections:
    n = s.Name.rstrip(b'\x00').decode('ascii', errors='replace')
    if n == '.text':
        text_va   = IMG + s.VirtualAddress
        text_data = s.get_data()
        break

def read(va, n):
    off = va - text_va
    return text_data[off:off+n]

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = False

def dump_range(start, stop, label):
    print(f"\n;==== {label}: {start:#x} .. {stop:#x} ====")
    buf = read(start, stop-start)
    for ins in md.disasm(buf, start):
        print(f"  {ins.address:#010x}  {ins.mnemonic:<8} {ins.op_str}")

# vt[51] full (0xD bytes)
dump_range(0x142174C60, 0x142174C60+0xD, "BSLSP vt[51] sub_142174C60 (returns float)")
# vt[50] full (0x30)
dump_range(0x142174C70, 0x142174C70+0x30, "BSLSP vt[50] sub_142174C70")

# Early-reject header in sub_142172540 (first 220 bytes)
dump_range(0x142172540, 0x142172540+0x220, "sub_142172540 header+early-reject")

# LABEL_52 area (float multiplies) — decomp shows around line 998 of raw
# that's near 0x142172b7d area? look up by computing - the code is at roughly
# a1+40 / a1+44 writes then v14[1] check.
dump_range(0x142172A00, 0x142172A00+0x200, "sub_142172540 LABEL_52 region")

# Near the spinwait for BTED tag + vt invocations
dump_range(0x142172B00, 0x142172B00+0x200, "sub_142172540 effect-chain1")

# Key guard: shader+88 ( = material) load — we saw mem-chain (mem(THIS+0x58)+0x80)
# That's in vt[51]: BSLSP vt[51] reads mat+0x80 (first float).
# Material+0x80 is initialized by ctor to 1065353216 = 1.0f (glossiness).
# Also check vt[51] code bytes — what exactly?

# The render path also does:
#   v21 = *(float *)(*(_QWORD *)(a1 + 88) + 128LL);   // mat+0x80
# That's mat+128 (0x80), same field. Good.

# Let me also dump the short chain between LABEL_52 and the first Dispatch:
dump_range(0x142172C00, 0x142172C00+0x100, "sub_142172540 post-alpha-combine")

# Dump sub_1421F9F00 (material cache probe) start — relevant for fresh-mat:
dump_range(0x1421F9F00, 0x1421F9F00+0x80, "sub_1421F9F00 material cache entry")

# sub_1421C6870 prologue (killswitch area)
dump_range(0x1421C6870, 0x1421C6870+0x120, "sub_1421C6870 bind header")

# sub_1421C5CE0 (material ctor) full
dump_range(0x1421C5CE0, 0x1421C5CE0+0x13D, "sub_1421C5CE0 material ctor full")

# sub_142171620 BSLSP ctor
dump_range(0x142171620, 0x142171620+0x110, "sub_142171620 BSLSP ctor")

# check what's at RVA 0x2164478 (qword_143E475F5 adjacent?)
# look up section for 0x143E475F5 / 0x143E488C0
# print the PE sections:
print("\n;==== PE sections ====")
for s in pe.sections:
    nn = s.Name.rstrip(b'\x00').decode('ascii', errors='replace')
    print(f"  {nn:<10}  VA={IMG+s.VirtualAddress:#x}  VSIZE={s.Misc_VirtualSize:#x}  RAWSZ={s.SizeOfRawData:#x}")
