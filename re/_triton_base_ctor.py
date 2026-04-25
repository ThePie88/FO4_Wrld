"""Peek at sub_1421D6700 (NiRefObject base?) to confirm it zero-inits +0x08-0x38."""
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
for (name, va, sz) in [
    ("sub_1421D6700 (material base pre-init)", 0x1421D6700, 0x80),
    ("sub_1421D6750 (material base dtor?)", 0x1421D6750, 0x60),
    ("sub_14217A910 (tex load helper)", 0x14217A910, 0x100),
    ("sub_1416BAB90 (texset helper)", 0x1416BAB90, 0x40),
    ("sub_1421C6870 mid (after xmm memset)", 0x1421C6990, 0x180),
]:
    print(f"\n;==== {name} @ {va:#x} ====")
    buf = read(va, sz)
    for ins in md.disasm(buf, va):
        print(f"  {ins.address:#010x}  {ins.mnemonic:<8} {ins.op_str}")
