"""Trace sub_142172540 LABEL_52 → dispatch, identify the full flow after early reject passes."""
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
        text_va = IMG + s.VirtualAddress
        text_data = s.get_data()
        break
def read(va, n):
    off = va - text_va
    return text_data[off:off+n]

md = Cs(CS_ARCH_X86, CS_MODE_64)

# LABEL_52 is around 0x142172820 / 0x14217283c based on the `v21 = ...` load of mat+128.
# Let me dump 0x142172780 .. 0x142172a00 covering the "post-LABEL_52 + alpha combine".
start = 0x142172780
end   = 0x142172a00
buf = read(start, end-start)
for ins in md.disasm(buf, start):
    print(f"{ins.address:#010x}  {ins.mnemonic:<8} {ins.op_str}")
