"""sub_1421C7800 — the material CLONE fn. Tells us the REAL sizeof-base."""
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
    ("sub_1421C7800 (material clone?)", 0x1421C7800, 0x100),
    ("sub_1421C61C0 (vt[3] size ~0x80?)", 0x1421C61C0, 0xA0),
    ("sub_1421C5F90 (vt[2] clone?)",    0x1421C5F90, 0xA0),
    # also the 0xC8 ctor from 1421C8710 — that hints a subclass
    ("sub_1421C8710 (subclass alloc 0xC8)", 0x1421C8710, 0xA0),
    ("sub_1421C7010 subclass 0xC0 alloc", 0x1421C7010, 0xA0),
    ("sub_1421C71D5 subclass 0xD0 alloc", 0x1421C71D5, 0xC0),
    ("sub_1421C9CC0 (copy ctor?)",      0x1421C9CC0, 0x80),
    ("vt[2] sub_1421C5F90",             0x1421C5F90, 0x100),
    ("vt[3] sub_1421C61C0",             0x1421C61C0, 0x100),
]:
    print(f"\n;==== {name} @ {va:#x} ====")
    buf = read(va, sz)
    for ins in md.disasm(buf, va):
        print(f"  {ins.address:#010x}  {ins.mnemonic:<8} {ins.op_str}")
