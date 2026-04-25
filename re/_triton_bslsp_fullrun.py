"""
Plan C — symbolic trace of sub_142172540 (BSLSP vt[43] SetupGeometry).

APPROACH: taint-style mini-symexec.
  - Initial taints:
      rcx  = THIS  (BSLSP pointer)
      rdx  = a2    (geo / state block, e.g. BSGeometry)
      r8d  = a3    (int, "pass kind" selector)
      r9   = a4    (extra state ptr, used as v98)

  - Each mov/cmp/test/... that touches [reg+disp] is logged as
        load_this[disp]   if reg == r15 / tracked_this alias
        load_mat [disp]   if reg aliases *(this+0x58)

  - We specifically flag every branch whose flags-producing comparand
    touches THIS or MAT-derived memory.

Lightweight — we don't build full constraints; we build a human-readable
annotated trace so the dossier can reason about exact fields.

Fallback behind angr because Windows-Triton is unavailable.
"""

import os, struct, sys, re
from collections import defaultdict, OrderedDict

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
        text_va   = IMG + s.VirtualAddress
        text_data = s.get_data()
        break

def read(va, n):
    off = va - text_va
    return text_data[off:off+n]

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

# ---------------------------------------------------------------------------
# Taint tracker — very simple
# ---------------------------------------------------------------------------
# We assign string 'tags' to registers. When a move copies between regs, the
# tag propagates. When a load happens [reg+disp], we record.
#
# We seed:
#   rcx → "THIS"
#   rdx → "A2"
#   r8  → "A3"
#   r9  → "A4"
# Win64 calling convention.
#
# Loads we care about:
#   mov X, [THIS+disp]               → event load_this(disp)
#   mov X, [THIS+0x58]               → MAT aliases X afterwards
#   mov X, [X+disp]  when X=MAT      → event load_mat(disp)
#   mov X, [A2+disp]                 → event load_a2(disp)   (BSGeometry fields)
#   mov X, [MAT+... something like [R+0x88]] etc.
#
# When a tainted value is cmp'd or test'd, we record the branch target and tag.

REGS_64 = {
    X86_REG_RAX:"rax", X86_REG_RBX:"rbx", X86_REG_RCX:"rcx", X86_REG_RDX:"rdx",
    X86_REG_RSI:"rsi", X86_REG_RDI:"rdi", X86_REG_RBP:"rbp", X86_REG_RSP:"rsp",
    X86_REG_R8:"r8", X86_REG_R9:"r9", X86_REG_R10:"r10", X86_REG_R11:"r11",
    X86_REG_R12:"r12", X86_REG_R13:"r13", X86_REG_R14:"r14", X86_REG_R15:"r15",
    X86_REG_RIP:"rip",
}
# mapping of sub-registers to their 64-bit parent
SUB2FULL = {}
def _map_sub(sub, full):
    SUB2FULL[sub] = full

for (full_e, full_name) in REGS_64.items():
    _map_sub(full_e, full_e)

# 32/16/8-bit aliasing
SUBPARENT = {
    X86_REG_EAX:X86_REG_RAX, X86_REG_AX:X86_REG_RAX, X86_REG_AL:X86_REG_RAX, X86_REG_AH:X86_REG_RAX,
    X86_REG_EBX:X86_REG_RBX, X86_REG_BX:X86_REG_RBX, X86_REG_BL:X86_REG_RBX, X86_REG_BH:X86_REG_RBX,
    X86_REG_ECX:X86_REG_RCX, X86_REG_CX:X86_REG_RCX, X86_REG_CL:X86_REG_RCX, X86_REG_CH:X86_REG_RCX,
    X86_REG_EDX:X86_REG_RDX, X86_REG_DX:X86_REG_RDX, X86_REG_DL:X86_REG_RDX, X86_REG_DH:X86_REG_RDX,
    X86_REG_ESI:X86_REG_RSI, X86_REG_SI:X86_REG_RSI, X86_REG_SIL:X86_REG_RSI,
    X86_REG_EDI:X86_REG_RDI, X86_REG_DI:X86_REG_RDI, X86_REG_DIL:X86_REG_RDI,
    X86_REG_EBP:X86_REG_RBP, X86_REG_BP:X86_REG_RBP, X86_REG_BPL:X86_REG_RBP,
    X86_REG_ESP:X86_REG_RSP, X86_REG_SP:X86_REG_RSP, X86_REG_SPL:X86_REG_RSP,
    X86_REG_R8D:X86_REG_R8, X86_REG_R8W:X86_REG_R8, X86_REG_R8B:X86_REG_R8,
    X86_REG_R9D:X86_REG_R9, X86_REG_R9W:X86_REG_R9, X86_REG_R9B:X86_REG_R9,
    X86_REG_R10D:X86_REG_R10, X86_REG_R10W:X86_REG_R10, X86_REG_R10B:X86_REG_R10,
    X86_REG_R11D:X86_REG_R11, X86_REG_R11W:X86_REG_R11, X86_REG_R11B:X86_REG_R11,
    X86_REG_R12D:X86_REG_R12, X86_REG_R12W:X86_REG_R12, X86_REG_R12B:X86_REG_R12,
    X86_REG_R13D:X86_REG_R13, X86_REG_R13W:X86_REG_R13, X86_REG_R13B:X86_REG_R13,
    X86_REG_R14D:X86_REG_R14, X86_REG_R14W:X86_REG_R14, X86_REG_R14B:X86_REG_R14,
    X86_REG_R15D:X86_REG_R15, X86_REG_R15W:X86_REG_R15, X86_REG_R15B:X86_REG_R15,
}

def parent_reg(r):
    if r in SUBPARENT:
        return SUBPARENT[r]
    return r


class TaintState:
    def __init__(self):
        self.reg_taint = {}                      # parent_reg -> tag (string)
        self.events    = []                       # list of (va, kind, detail)
        self.branches  = []                       # (va, flags-set-by-va, tag)
        self.last_flag_setter = None              # (va, ins, lhs_tag, rhs_tag, lhs_repr, rhs_repr)
        self.call_edges = []                      # (va, callee_str)
        self.loads_this  = defaultdict(set)       # disp -> set(va)
        self.loads_mat   = defaultdict(set)
        self.loads_a2    = defaultdict(set)
        self.writes_mat  = defaultdict(set)

    def set_reg(self, r, tag):
        p = parent_reg(r)
        if tag is None:
            self.reg_taint.pop(p, None)
        else:
            self.reg_taint[p] = tag

    def get_reg(self, r):
        return self.reg_taint.get(parent_reg(r))

    def copy_reg(self, dst, src):
        t = self.get_reg(src)
        self.set_reg(dst, t)


def mem_operand_tag(state, ins, op):
    """Return (tag, disp, pretty) describing a memory operand's base taint."""
    m = op.mem
    if m.base == X86_REG_INVALID:
        return (None, None, f"disp={m.disp:#x}")
    base_tag = state.get_reg(m.base)
    return (base_tag, m.disp, f"[{ins.reg_name(m.base)}{'+' if m.disp>=0 else '-'}{abs(m.disp):#x}]")


def step_instruction(ins, state):
    """Update taint. Log interesting events."""
    m   = ins.mnemonic
    ops = ins.operands

    # --- branches (jcc) ---
    if m.startswith('j') and ins.id != X86_INS_JMP:
        if state.last_flag_setter:
            va, setter_ins, lhs_tag, rhs_tag, lhs_repr, rhs_repr = state.last_flag_setter
            tags = [t for t in (lhs_tag, rhs_tag) if t]
            target = ops[0].imm if (ops and ops[0].type == X86_OP_IMM) else None
            state.branches.append((ins.address, m, target, setter_ins.mnemonic,
                                   lhs_tag, rhs_tag, lhs_repr, rhs_repr, setter_ins.address))
        return

    # --- flags-setting ops (cmp, test, sub that sets cmp) ---
    if m in ('cmp', 'test'):
        lhs = ops[0]; rhs = ops[1]
        ltag, rtag, lrep, rrep = None, None, None, None
        if lhs.type == X86_OP_REG:
            ltag = state.get_reg(lhs.reg)
            lrep = ins.reg_name(lhs.reg)
        elif lhs.type == X86_OP_MEM:
            bt, disp, pretty = mem_operand_tag(state, ins, lhs)
            ltag = f"mem({bt}+{disp:#x})" if bt else None
            lrep = pretty
            if bt == "THIS":
                state.loads_this[disp].add(ins.address)
            elif bt == "MAT":
                state.loads_mat[disp].add(ins.address)
            elif bt == "A2":
                state.loads_a2[disp].add(ins.address)
        elif lhs.type == X86_OP_IMM:
            lrep = f"{lhs.imm:#x}"
        if rhs.type == X86_OP_REG:
            rtag = state.get_reg(rhs.reg)
            rrep = ins.reg_name(rhs.reg)
        elif rhs.type == X86_OP_MEM:
            bt, disp, pretty = mem_operand_tag(state, ins, rhs)
            rtag = f"mem({bt}+{disp:#x})" if bt else None
            rrep = pretty
            if bt == "THIS":
                state.loads_this[disp].add(ins.address)
            elif bt == "MAT":
                state.loads_mat[disp].add(ins.address)
            elif bt == "A2":
                state.loads_a2[disp].add(ins.address)
        elif rhs.type == X86_OP_IMM:
            rrep = f"{rhs.imm:#x}"
        state.last_flag_setter = (ins.address, ins, ltag, rtag, lrep, rrep)
        return

    # xorps xmm, xmm  or xor reg,reg → zero
    if m == 'xor' and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG and ops[0].reg == ops[1].reg:
        state.set_reg(ops[0].reg, None)
        return

    # mov rdst, rsrc  / movzx / movsx / movss etc.
    if m in ('mov','movzx','movsx','movsxd','movaps','movups','movdqa','movdqu','movss','movsd','lea'):
        if len(ops) < 2:
            return
        dst = ops[0]; src = ops[1]
        if dst.type == X86_OP_REG:
            dst_reg = dst.reg
            if src.type == X86_OP_REG:
                state.copy_reg(dst_reg, src.reg)
            elif src.type == X86_OP_MEM:
                bt, disp, pretty = mem_operand_tag(state, ins, src)
                if bt == "THIS":
                    state.loads_this[disp].add(ins.address)
                    # the MAT pointer lives at THIS+0x58
                    if disp == 0x58 and m in ('mov',):
                        state.set_reg(dst_reg, "MAT")
                    else:
                        state.set_reg(dst_reg, f"mem(THIS+{disp:#x})")
                elif bt == "MAT":
                    state.loads_mat[disp].add(ins.address)
                    state.set_reg(dst_reg, f"mem(MAT+{disp:#x})")
                elif bt == "A2":
                    state.loads_a2[disp].add(ins.address)
                    state.set_reg(dst_reg, f"mem(A2+{disp:#x})")
                else:
                    state.set_reg(dst_reg, None)
            elif src.type == X86_OP_IMM:
                state.set_reg(dst_reg, f"imm({src.imm:#x})")
        elif dst.type == X86_OP_MEM:
            # WRITE to MAT or THIS
            bt, disp, pretty = mem_operand_tag(state, ins, dst)
            if bt == "MAT":
                state.writes_mat[disp].add(ins.address)
        return

    # arithmetic ops that kill flags
    if m in ('add','sub','shl','shr','sar','or','and','xor','inc','dec','imul','mul'):
        state.last_flag_setter = None
        # kill taint on dst
        if ops and ops[0].type == X86_OP_REG:
            state.set_reg(ops[0].reg, None)
        return

    # call
    if m == 'call':
        callee_va = None
        callee_str = ins.op_str
        if ops[0].type == X86_OP_IMM:
            callee_va = ops[0].imm
            callee_str = f"sub_{callee_va:08X}"
        elif ops[0].type == X86_OP_MEM:
            bt, disp, pretty = mem_operand_tag(state, ins, ops[0])
            if bt == "THIS" and disp == 0:   # calling vtable
                callee_str = f"THIS.vtable[0]"  # not used – vt[x] comes via [rax+disp]
            callee_str = f"CALL_MEM{pretty}"
        state.call_edges.append((ins.address, callee_str))
        # clobber volatile caller-save regs
        for r in [X86_REG_RAX, X86_REG_RCX, X86_REG_RDX, X86_REG_R8, X86_REG_R9, X86_REG_R10, X86_REG_R11]:
            state.set_reg(r, None)
        state.last_flag_setter = None
        return

    # ret / default — clear nothing
    return


# ---------------------------------------------------------------------------
# driver
# ---------------------------------------------------------------------------
def linear_trace(va_start, size):
    buf = read(va_start, size)
    state = TaintState()
    state.set_reg(X86_REG_RCX, "THIS")
    state.set_reg(X86_REG_RDX, "A2")
    state.set_reg(X86_REG_R8,  "A3")
    state.set_reg(X86_REG_R9,  "A4")

    ins_list = list(md.disasm(buf, va_start))
    for ins in ins_list:
        step_instruction(ins, state)
    return state, ins_list


def dump_state(name, state, ins_list, outfh):
    outfh.write(f"\n### {name} linear-trace summary\n")
    outfh.write(f"  instructions         : {len(ins_list)}\n")
    outfh.write(f"  THIS loads (offsets) : {len(state.loads_this)}\n")
    outfh.write(f"  MAT  loads (offsets) : {len(state.loads_mat)}\n")
    outfh.write(f"  A2   loads (offsets) : {len(state.loads_a2)}\n")
    outfh.write(f"  branches touching taint: ")
    t_branches = [b for b in state.branches if (b[4] and ("THIS" in b[4] or "MAT" in b[4] or "A2" in b[4])) or (b[5] and ("THIS" in b[5] or "MAT" in b[5] or "A2" in b[5]))]
    outfh.write(f"{len(t_branches)} / {len(state.branches)}\n")

    outfh.write("\n  -- THIS offsets read --\n")
    for d in sorted(state.loads_this):
        vas = sorted(state.loads_this[d])
        outfh.write(f"    +{d:#06x}  @ {', '.join(f'{v:#x}' for v in vas[:6])}{'...' if len(vas)>6 else ''}\n")

    outfh.write("\n  -- MAT (=THIS+0x58) offsets read --\n")
    for d in sorted(state.loads_mat):
        vas = sorted(state.loads_mat[d])
        outfh.write(f"    +{d:#06x}  @ {', '.join(f'{v:#x}' for v in vas[:6])}{'...' if len(vas)>6 else ''}\n")

    outfh.write("\n  -- A2 (BSGeometry) offsets read --\n")
    for d in sorted(state.loads_a2):
        vas = sorted(state.loads_a2[d])
        outfh.write(f"    +{d:#06x}  @ {', '.join(f'{v:#x}' for v in vas[:6])}{'...' if len(vas)>6 else ''}\n")

    outfh.write("\n  -- MAT writes --\n")
    for d in sorted(state.writes_mat):
        outfh.write(f"    +{d:#06x}\n")

    outfh.write("\n  -- Branches gated by THIS/MAT/A2 memory --\n")
    for b in t_branches[:120]:
        va, jmnemonic, target, setter_mnem, lt, rt, lr, rr, set_va = b
        outfh.write(f"    {va:#010x}  {setter_mnem} {lr!r}, {rr!r}  -> {jmnemonic} {target:#x}\n"
                    f"                        L={lt!s:<28} R={rt!s}\n")

    outfh.write("\n  -- Calls made --\n")
    for va, cs in state.call_edges[:80]:
        outfh.write(f"    {va:#010x}  call {cs}\n")


if __name__ == '__main__':
    OUT = os.path.join(RE_DIR, "_triton_trace_output.txt")
    with open(OUT, 'w', encoding='utf-8') as out:
        for name, (va, size) in [
            ("sub_142172540 (BSLSP vt[43] SetupGeometry)", (0x142172540, 0xE45)),
            ("sub_142174C60 (BSLSP vt[51] returns float)",  (0x142174C60, 0x0D)),
            ("sub_142174C70 (BSLSP vt[50])",                (0x142174C70, 0x30)),
            ("sub_1421C5CE0 (Material ctor)",               (0x1421C5CE0, 0x13D)),
            ("sub_1421718C0 (BSLSP vt[42])",                (0x1421718C0, 0x10)),
            ("sub_142161090 (acquire-effect-state)",        (0x142161090, 0x150)),
            ("sub_142160F80 (reset material → abort)",      (0x142160F80, 0x60)),
            ("sub_1421611A0 (append effect to list)",       (0x1421611A0, 0x100)),
            ("sub_142215990 (post-acquire state fixup)",    (0x142215990, 0x80)),
        ]:
            state, ins_list = linear_trace(va, size)
            dump_state(name, state, ins_list, out)
    print(f"wrote {OUT}")
