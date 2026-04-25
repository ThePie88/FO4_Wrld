"""Find BSLightingShaderMaterialBase vtable, dump first 32 slots, check the hash/clone/vt[7] fns."""
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
    elif n == '.rdata':
        rdata_va = IMG + s.VirtualAddress
        rdata_data = s.get_data()
def read_any(va, n):
    for vastart, vadata in [(text_va, text_data), (rdata_va, rdata_data)]:
        if vastart <= va < vastart + len(vadata):
            off = va - vastart
            return vadata[off:off+n]
    return None
md = Cs(CS_ARCH_X86, CS_MODE_64)

# The material ctor writes the vtable at [rbx] via rax. Look at that lea:
# 0x1421C5CEE: lea rax, [rip + 0x743FDB]
# Compute: 0x1421C5CEE + 7 + 0x743FDB = ?
# lea reads ip_after = 0x1421c5cf5, +0x743fdb = 0x142909cd0 ... close to vtable
VT_LEA_VA = 0x1421C5CEE
# lea opcode is 48 8D 05 DB 3F 74 00 : 7 bytes
# disp is in bytes [3..6]
off = VT_LEA_VA - text_va
b = text_data[off:off+7]
print(f"lea bytes: {b.hex()}")
# actually let's just disasm it
for ins in md.disasm(text_data[off:off+10], VT_LEA_VA):
    print(f"  {ins.address:#x}  {ins.mnemonic} {ins.op_str}")
    if 'rip' in ins.op_str:
        # extract disp
        parts = ins.op_str.split('+')
        disp = int(parts[1].strip(']').strip(), 0)
        target = ins.address + ins.size + disp
        print(f"  -> vtable @ {target:#x}")
        VT_VA = target
    break

# Now dump first 32 slots of that vtable
print(f"\n== BSLightingShaderMaterialBase vtable @ {VT_VA:#x} first 32 slots ==")
vt_bytes = read_any(VT_VA, 32*8)
for i in range(32):
    target = int.from_bytes(vt_bytes[i*8:i*8+8], 'little')
    rva = target - IMG
    print(f"  [{i:3d}]  {target:#x}  RVA={rva:#x}")

# Then the BSShaderMaterialBase (or equivalent) vtable typically has these slots:
# vt[1] = clone / deep-copy, vt[7] = register-in-cache, vt[24] = hash-key
# Let's disasm a few:
for i in [1, 7, 20, 24, 28]:
    target = int.from_bytes(vt_bytes[i*8:i*8+8], 'little')
    print(f"\n-- vt[{i}] @ {target:#x} --")
    buf = read_any(target, 0x60)
    if buf is None: continue
    for ins in md.disasm(buf, target):
        if ins.mnemonic == 'ret' or ins.mnemonic.startswith('j') and ins.mnemonic != 'jmp':
            print(f"  {ins.address:#x}  {ins.mnemonic} {ins.op_str}")
            if ins.mnemonic == 'ret':
                break
        else:
            print(f"  {ins.address:#x}  {ins.mnemonic} {ins.op_str}")
