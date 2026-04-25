"""Find true sizeof(BSLightingShaderMaterialBase) by checking all callers of sub_1421C5CE0 and sub_1421C59B0.
   Look for `mov ... 0xNNN` immediately preceded/followed by the call to the allocator."""
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

# scan .text looking for "call 1421C5CE0" / "call 1421C59B0" patterns
CS_CALL_REL = 0xE8   # opcode for CALL rel32
CTOR = 0x1421C5CE0
ALLOC_MAT_A = 0x1421C59B0

def find_calls_to(target):
    # x86 relative call: E8 xx xx xx xx — next_ip + disp32 = target
    calls = []
    for off in range(len(text_data)-5):
        if text_data[off] == CS_CALL_REL:
            disp = int.from_bytes(text_data[off+1:off+5], 'little', signed=True)
            ip_after = text_va + off + 5
            if ip_after + disp == target:
                calls.append(text_va + off)
    return calls

for target, name in [(CTOR, "ctor 1421C5CE0"), (ALLOC_MAT_A, "grass-ctor 1421C59B0")]:
    calls = find_calls_to(target)
    print(f"\n=== calls to {name}: {len(calls)} ===")
    for c in calls[:40]:
        # disasm 16 insns before and 2 after
        start = c - 0x60
        buf = read(start, 0x80)
        print(f"\n  [call @ {c:#x}]  preceding context:")
        for ins in md.disasm(buf, start):
            marker = "  ** " if ins.address == c else "     "
            print(f"    {marker}{ins.address:#010x}  {ins.mnemonic:<8} {ins.op_str}")
