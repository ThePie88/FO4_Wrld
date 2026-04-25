# Plan C — Symbolic analysis of BSLSP vt[43] SetupGeometry (sub_142172540)
# Triton unavailable on Windows Py3.12, falling back to angr + capstone manual
# symbolic trace. Goal: identify EVERY field of `this` (BSLSP) and `this+0x58`
# (material) read in branch conditions, and what concrete values let the path
# reach the DX11 dispatch.

import sys, os, struct, json
from collections import defaultdict

RE_DIR = r"C:\Users\filip\Desktop\FalloutWorld\re"
EXE    = os.path.join(RE_DIR, "Fallout4.exe")
IMG    = 0x140000000

# ---- 1. Load PE, find text section ------------------------------------
import pefile
pe = pefile.PE(EXE, fast_load=True)
for s in pe.sections:
    name = s.Name.rstrip(b'\x00').decode('ascii', errors='replace')
    if name == '.text':
        text_va   = IMG + s.VirtualAddress
        text_data = s.get_data()
        text_size = len(text_data)
        break

print(f"[+] text at {text_va:#x} size={text_size:#x}")

def va2off(va):
    return va - text_va

def read(va, n):
    o = va2off(va)
    return text_data[o:o+n]

# ---- 2. Capstone disassembler -----------------------------------------
from capstone import *
from capstone.x86 import *
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

# ---- 3. Disassemble sub_142172540 (full), sub_142174C60, sub_1421C5CE0 -
TARGETS = {
    "sub_142172540": (0x142172540, 0xE45),
    "sub_142174C60": (0x142174C60, 0x0D),
    "sub_142174C70": (0x142174C70, 0x30),   # vt[50] neighbor
    "sub_1421C5CE0": (0x1421C5CE0, 0x13D),
    "sub_1421718C0": (0x1421718C0, 0x10),  # vt[42] AttachGeometry
    "sub_142161090": (0x142161090, 0x150),  # called early by vt[43]
    "sub_142160F80": (0x142160F80, 0x60),   # "reset material ptr → abort"
    "sub_1421611A0": (0x1421611A0, 0x100),  # the acquire-effect-state fn
    "sub_142215990": (0x142215990, 0x80),
}

def disasm_span(start_va, size):
    buf = read(start_va, size)
    out = []
    for ins in md.disasm(buf, start_va):
        out.append(ins)
    return out

# ---- 4. Branch analyzer ----------------------------------------------
BRANCH_MNEMONICS = {
    "je","jne","jg","jge","jl","jle","ja","jae","jb","jbe",
    "jo","jno","js","jns","jp","jnp","jcxz","jecxz","jrcxz",
    "jz","jnz","jc","jnc","jmp"
}

def operand_repr(ins, op):
    if op.type == X86_OP_MEM:
        m = op.mem
        base = ins.reg_name(m.base) if m.base else ""
        idx  = ins.reg_name(m.index) if m.index else ""
        disp = m.disp
        scale= m.scale
        s = "["
        s += base
        if idx:
            s += f"+{idx}*{scale}"
        if disp:
            s += f"{'+' if disp>=0 else '-'}{abs(disp):#x}"
        s += "]"
        return s
    elif op.type == X86_OP_REG:
        return ins.reg_name(op.reg)
    elif op.type == X86_OP_IMM:
        return f"{op.imm:#x}"
    return "?"

# ---- 5. Run on sub_142172540 -----------------------------------------
def analyze_fn(name, va, size):
    print(f"\n=== {name} @ {va:#x} size={size:#x} ===")
    ins_list = disasm_span(va, size)
    branches = []
    mem_reads_this = defaultdict(int)  # offsets read from rcx/r12/etc assumed == this
    mem_reads_mat  = defaultdict(int)  # offsets read from material pointer
    calls  = []
    for ins in ins_list:
        if ins.mnemonic in BRANCH_MNEMONICS:
            branches.append(ins)
        if ins.mnemonic == "call":
            ops = [operand_repr(ins, o) for o in ins.operands]
            calls.append((ins.address, ins.mnemonic, ops, ins.op_str))
    return ins_list, branches, calls

for name, (va, size) in TARGETS.items():
    try:
        ins_list, branches, calls = analyze_fn(name, va, size)
        print(f"  insn   = {len(ins_list)}")
        print(f"  branch = {len(branches)}")
        print(f"  call   = {len(calls)}")
    except Exception as e:
        print(f"  !! {e}")
