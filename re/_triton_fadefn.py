"""Peek at sub_142161F20 fade function and sub_142161EC0 default-fade."""
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
    ("sub_142161F20", 0x142161F20, 0x100),
    ("sub_142161EC0", 0x142161EC0, 0x60),
    ("sub_1421C7770 (lazy default-mat init)", 0x1421C7770, 0x80),
    ("sub_142173390 (early dispatch helper)", 0x142173390, 0x80),
    ("sub_1421F9F00 full prologue+hash", 0x1421F9F00, 0x200),
    ("sub_142161B10 (install material)", 0x142161B10, 0x120),
    ("sub_142171050 (BSLSP allocator)", 0x142171050, 0xA0),
]:
    print(f"\n;==== {name} @ {va:#x} ====")
    buf = read(va, sz)
    for ins in md.disasm(buf, va):
        print(f"  {ins.address:#010x}  {ins.mnemonic:<8} {ins.op_str}")
