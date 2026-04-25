"""angr symbolic execution of BSLSP vt[43] sub_142172540.

Extracts the offsets read from 'this' (BSLSP), material (BSLSP+0x48 and +0x58),
geometry (a2), render ctx (a4), and the constraints to reach the draw dispatch.

Run:  python angr_bslsp_vt43.py
Out:  re/_angr_bslsp_vt43.log
"""
import sys, time
import angr
import claripy
import logging

logging.getLogger("angr").setLevel(logging.ERROR)
logging.getLogger("cle").setLevel(logging.ERROR)
logging.getLogger("pyvex").setLevel(logging.ERROR)
logging.getLogger("claripy").setLevel(logging.ERROR)

BIN = r"C:\Users\filip\Desktop\FalloutWorld\re\Fallout4.exe"
LOG = r"C:\Users\filip\Desktop\FalloutWorld\re\_angr_bslsp_vt43.log"

IMG_BASE = 0x140000000
FN = 0x142172540  # sub_142172540 = BSLSP vt[43]

BSLSP_ADDR = 0x10000000
MAT_ADDR   = 0x20000000
GEOM_ADDR  = 0x30000000
CTX_ADDR   = 0x40000000
VT_BSLSP   = 0x50000000
VT_GEOM    = 0x51000000
VT_MAT     = 0x52000000
STACK_TOP  = 0x7FFFF008  # Win x64: entry rsp %16 == 8

TEB_BASE = 0x71000000
TLS_ARR  = 0x72000000
TLS_SLOT = 0x73000000


def log(fh, msg):
    print(msg, flush=True); fh.write(msg + "\n"); fh.flush()


class NopRet(angr.SimProcedure):
    """Return 0 (false) — most NULL checks take safe branch."""
    NAME = "NopRet"
    def run(self, *args):
        return claripy.BVV(0, 64)


class ReturnOne(angr.SimProcedure):
    def run(self, *args):
        return claripy.BVV(1, 64)


class Alloc(angr.SimProcedure):
    _ctr = 0x60000000
    def run(self, *args):
        a = Alloc._ctr
        Alloc._ctr += 0x1000
        return claripy.BVV(a, 64)


class SymCall(angr.SimProcedure):
    def run(self, *args):
        return claripy.BVS("sym_ret", 64)


def install_hooks(proj, fh):
    """Hook every heavy helper vt[43] could call.

    If a target doesn't exist in the loaded exe, `proj.hook` just registers
    an address mapping — no error.
    """
    NULL = NopRet
    ONE = ReturnOne
    ALLOC = Alloc
    SYM = SymCall

    hooks = {
        # ---- memory / lazy init ----
        0x141657F90: NULL,        # lazy init
        0x1416579C0: ALLOC,       # BSSmallBlockAllocator::Allocate
        0x14165C3F0: NULL,
        0x141656E30: SYM,         # returns some ptr
        0x1418214C0: NULL,        # log/telemetry
        0x1401E00D0: NULL,        # idk
        # ---- BSLSP helpers ----
        0x142160C10: NULL,
        0x142160F80: NULL,        # flush
        0x142160FF0: NULL,
        0x142161090: ALLOC,       # allocate BSShaderAccumulator entry
        0x1421611A0: ALLOC,       # push draw record
        0x142161B10: NULL,
        0x142161EC0: ONE,
        0x142161F20: ONE,
        0x142162020: NULL,
        0x142162090: NULL,
        0x142171830: NULL,
        0x142173390: NULL,        # LABEL_231 shortcut branch — we skip this
        0x142174150: NULL,
        0x142174520: NULL,
        0x142174800: NULL,
        0x142174820: NULL,
        0x142174A00: NULL,
        0x142174C30: NULL,
        0x142174C40: NULL,
        # vt[51] = 0x142174C60 — 3-insn float getter; let angr execute it directly.
        0x142174C70: NULL,
        0x142215990: NULL,
        0x142200170: ALLOC,
        0x14223A6C0: ALLOC,
        0x14223BC70: NULL,
        # ---- geometry helpers ----
        0x1416DE030: SYM,
        0x1416D5640: NULL,        # skip 0x80000040 branch
        0x1416D5930: NULL,
        0x1416BD0B0: NULL,        # skip 0x40000000 branch
        # ---- string / init ----
        0x14167BCF0: NULL,
        0x14167BDC0: NULL,
        0x14167C200: NULL,
        0x1417E8950: NULL,
        # ---- atomics / perf ----
        0x1422B7498: NULL,
        0x1422B70BC: NULL,
        0x1422B7438: NULL,
    }
    installed = 0
    for addr, proc in hooks.items():
        try:
            proj.hook(addr, proc())
            installed += 1
        except Exception:
            pass
    log(fh, f"    hooked {installed} helpers")


def prep_state(proj):
    opts_add = {
        angr.options.LAZY_SOLVES,
        angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
        angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
    }
    opts_rm = {
        angr.options.STRICT_PAGE_ACCESS,
    }
    state = proj.factory.blank_state(addr=FN, add_options=opts_add, remove_options=opts_rm)

    # Stack aligned for x64 Windows ABI (rsp%16 == 8 at entry)
    state.regs.rsp = claripy.BVV(STACK_TOP, 64)
    # Return address so the function can 'ret' cleanly.
    state.memory.store(STACK_TOP, claripy.BVV(0xdeadbeefcafef00d, 64), endness='Iend_LE')

    # TLS / TEB  —  required for the function prologue to survive.
    state.regs.gs = claripy.BVV(TEB_BASE, 64)
    state.memory.store(TEB_BASE + 0x58, claripy.BVV(TLS_ARR, 64), endness='Iend_LE')
    state.memory.store(TLS_ARR, claripy.BVV(TLS_SLOT, 64), endness='Iend_LE')

    # BSLSP layout.
    # We seed ALL known fields, leave the rest zero (permissive default).
    # Layout info (from mat dossier + decomp v9 usage):
    #   +0x00: vtable ptr
    #   +0x28: float? (checked as "!= 0.0"? — v22 path)
    #   +0x2C: flags int (written = a3 << 8 or 0x7FFFFFFF)
    #   +0x30: flags extra?
    #   +0x38: v9 flags  *(QWORD)(a1+48) = v9  ← BITS control everything
    #   +0x48: v11 config obj *(QWORD)(a1+72)  -- per disasm: +0x48
    #   +0x50: material ptr B *(QWORD)(a1+80)  -- v70
    #   +0x58: material ptr A *(QWORD)(a1+88)  -- used for +128 (shader float)
    #   +0x64: float v23 (a1+100 == a1+0x64)
    #   +0x70: ??? (a1+0x70/112)
    #   +0xD4: vec3 float *(a1+212)  -- sub_142161F20 target buffer (a1+212)
    #
    # 'v9 = *(a1+48)' means BSLSP+0x30, not +0x48!
    # Decomp shows `*(_QWORD *)(a1 + 48) = v9`; 48 decimal = 0x30.
    # So the 'flags' word IS BSLSP+0x30, NOT +0x48.
    # Re-derive offsets (decimal->hex):
    #   a1+40 (0x28) = alpha float
    #   a1+44 (0x2C) = flags dword
    #   a1+48 (0x30) = v9 (qword flags) ← HOT
    #   a1+56 (0x38) = v8 = v14 "chain" (written by sub_142161090)
    #   a1+72 (0x48) = v11 config obj (reads +264, +286, +416, +420)
    #   a1+80 (0x50) = v61/v70 (another pointer, reads *->+32)
    #   a1+88 (0x58) = *(a1+88) → then read at +128 = f float
    #   a1+100 (0x64) = alpha scalar float (mul)
    #   a1+176 (0xB0) = used for "LABEL_231 return path"
    #   a1+212 (0xD4) = vec3 float buffer
    state.memory.store(BSLSP_ADDR + 0x00, claripy.BVV(VT_BSLSP, 64), endness='Iend_LE')

    # v9 flags: use ctor default (0) — makes v10=TRUE (bit 20 clear → je
    # taken → dil=1). Rejects 1-4 all PASS with proper ctor'd BSLSP + mat.
    state.memory.store(BSLSP_ADDR + 0x30, claripy.BVV(0, 64), endness='Iend_LE')

    # v11 config (BSLSP+0x48) points to something in .rdata or similar.
    state.memory.store(BSLSP_ADDR + 0x48, claripy.BVV(MAT_ADDR, 64), endness='Iend_LE')
    # Seed v11 fields:
    state.memory.store(MAT_ADDR + 0x108, claripy.BVV(0, 32), endness='Iend_LE')      # +264 flags dword
    state.memory.store(MAT_ADDR + 0x11E, claripy.BVV(0, 8), endness='Iend_LE')       # +286 byte
    state.memory.store(MAT_ADDR + 0x11D, claripy.BVV(0, 8), endness='Iend_LE')       # +285 byte
    state.memory.store(MAT_ADDR + 0x1A0, claripy.BVV(0x3F800000, 32), endness='Iend_LE')  # +416 = 1.0f
    state.memory.store(MAT_ADDR + 0x1A4, claripy.BVV(0x3F800000, 32), endness='Iend_LE')  # +420 = 1.0f

    # Material B at BSLSP+0x50 (tested for not-NULL and *->+32 read).
    state.memory.store(BSLSP_ADDR + 0x50, claripy.BVV(MAT_ADDR + 0x800, 64), endness='Iend_LE')
    state.memory.store(MAT_ADDR + 0x820, claripy.BVV(0, 64), endness='Iend_LE')  # *(v70+32) = 0  → skip 0x1000000 branch

    # Material A at BSLSP+0x58 (the shader-float source at +128):
    state.memory.store(BSLSP_ADDR + 0x58, claripy.BVV(MAT_ADDR + 0x400, 64), endness='Iend_LE')
    state.memory.store(MAT_ADDR + 0x480, claripy.BVV(0x3F800000, 32), endness='Iend_LE')  # +128 = 1.0f

    # Alpha fields on BSLSP itself (ctor defaults)
    state.memory.store(BSLSP_ADDR + 0x28, claripy.BVV(0x3F800000, 32), endness='Iend_LE')  # 1.0f
    state.memory.store(BSLSP_ADDR + 0x2C, claripy.BVV(0x7FFFFFFF, 32), endness='Iend_LE')  # ctor default
    state.memory.store(BSLSP_ADDR + 0x64, claripy.BVV(0x3F800000, 32), endness='Iend_LE')  # 1.0f

    # vtable slots on BSLSP — populate only known-indexed slots called.
    # decomp calls:   vt[51] = *(rax+0x198) (408 bytes = 51*8)
    # It's called in the v10 guard:
    #   (*(float (__fastcall **)(__int64))(*(_QWORD *)a1 + 408LL))(a1)
    # Our hook at 0x142174C60 handles it — but we need the slot to POINT to 0x142174C60.
    for i in range(80):
        state.memory.store(VT_BSLSP + 8 * i, claripy.BVV(0x142174C60, 64), endness='Iend_LE')
    # vt[2] (first used for RTTI/type check) → returns &unk_143E488B0 in decomp
    state.memory.store(VT_BSLSP + 8 * 2, claripy.BVV(0x142174C60, 64), endness='Iend_LE')

    # GEOM (a2) layout:
    state.memory.store(GEOM_ADDR + 0x00, claripy.BVV(VT_GEOM, 64), endness='Iend_LE')
    state.memory.store(GEOM_ADDR + 0x108, claripy.BVV(0, 32), endness='Iend_LE')      # a2[66] flags
    state.memory.store(GEOM_ADDR + 0x130, claripy.BVV(0, 64), endness='Iend_LE')      # alpha prop ptr (NULL → skip)
    state.memory.store(GEOM_ADDR + 0x158, claripy.BVV(0, 8), endness='Iend_LE')       # material type byte
    state.memory.store(GEOM_ADDR + 0x160, claripy.BVV(0, 32), endness='Iend_LE')      # a2[88] dword
    # Populate GEOM vtable — slot 63 (504 = 63*8), slot 2.
    for i in range(70):
        state.memory.store(VT_GEOM + 8 * i, claripy.BVV(0x142174C60, 64), endness='Iend_LE')

    # CTX (a4) / v98:
    state.memory.store(CTX_ADDR + 0xB0, claripy.BVV(1, 8), endness='Iend_LE')
    state.memory.store(CTX_ADDR + 0xB1, claripy.BVV(0, 8), endness='Iend_LE')

    # Force the 'v14[1] != qword_143E4BBD8' branch to be taken —
    # without this, the function short-circuits at the 'alpha unchanged'
    # fast-path and returns without touching the full setup.
    # qword_143E4BBD8 is .bss by default = 0.  Set it to a sentinel.
    state.memory.store(0x143E4BBD8, claripy.BVV(0xBBBBBBBBBBBBBBBB, 64), endness='Iend_LE')

    # x64 fastcall: rcx=this, rdx=a2, r8=a3, r9=a4 (first 4 args in regs)
    state.regs.rcx = BSLSP_ADDR
    state.regs.rdx = GEOM_ADDR
    state.regs.r8  = 24
    state.regs.r9  = CTX_ADDR

    return state


def main():
    fh = open(LOG, "w", encoding="utf-8")
    t0 = time.time()
    log(fh, f"[+] angr load {BIN}")
    proj = angr.Project(BIN, auto_load_libs=False)
    log(fh, f"    base=0x{proj.loader.main_object.mapped_base:X} arch={proj.arch}")
    log(fh, f"    [+] load took {time.time()-t0:.1f}s")

    install_hooks(proj, fh)

    state = prep_state(proj)
    log(fh, f"[+] state prepared, ip=0x{state.addr:X}")

    # memory-watch
    reads = {"BSLSP": [], "MAT": [], "GEOM": [], "CTX": [], "UNKNOWN": []}
    def watch(state):
        addr = state.inspect.mem_read_address
        if addr is None: return
        try:
            ai = state.solver.eval(addr)
        except Exception:
            return
        for name, base, size in [
            ("BSLSP", BSLSP_ADDR, 0x200),
            ("MAT",   MAT_ADDR,   0x1000),
            ("GEOM",  GEOM_ADDR,  0x200),
            ("CTX",   CTX_ADDR,   0x200),
        ]:
            if base <= ai < base + size:
                pc = state.addr
                length = state.inspect.mem_read_length
                try:
                    length_i = state.solver.eval(length)
                except Exception:
                    length_i = 0
                reads[name].append((pc, ai - base, length_i))
                return
        # else leave

    state.inspect.b('mem_read', when=angr.BP_AFTER, action=watch)

    simgr = proj.factory.simulation_manager(state)
    log(fh, f"[+] begin explore, budget 60s / 500 steps")

    t0 = time.time()
    steps = 0
    MAX_SECONDS = 120
    MAX_STEPS = 2000
    while simgr.active and steps < MAX_STEPS and (time.time() - t0) < MAX_SECONDS:
        simgr.step()
        steps += 1
        if steps % 50 == 0:
            log(fh, f"    step {steps}: active={len(simgr.active)} deadended={len(simgr.deadended)} "
                    f"errored={len(simgr.errored)} t={time.time()-t0:.1f}s "
                    f"addrs={[hex(s.addr) for s in simgr.active][:3]}")
        # Path explosion safeguard: merge if > 8 active states.
        if len(simgr.active) > 8:
            simgr.move(from_stash='active', to_stash='pruned',
                       filter_func=lambda s: True)
            # keep top 4
            simgr.active.extend(simgr.pruned[:4])
            simgr.pruned = simgr.pruned[4:]

    log(fh, f"[+] done, steps={steps}, elapsed={time.time()-t0:.1f}s")
    log(fh, f"    final: active={len(simgr.active)} deadended={len(simgr.deadended)} errored={len(simgr.errored)}")

    if simgr.active:
        for s in simgr.active[:4]:
            log(fh, f"    ACTIVE @ 0x{s.addr:X}, history len={len(s.history.bbl_addrs.hardcopy)}")

    # Aggregate reads
    log(fh, "\n==== READS ====")
    for name in ("BSLSP", "MAT", "GEOM", "CTX"):
        agg = {}
        for pc, off, sz in reads[name]:
            agg.setdefault(off, []).append((pc, sz))
        log(fh, f"\n--- {name} @ 0x{({'BSLSP':BSLSP_ADDR,'MAT':MAT_ADDR,'GEOM':GEOM_ADDR,'CTX':CTX_ADDR}[name]):X} ({len(agg)} offsets) ---")
        for off in sorted(agg):
            pcs_sz = agg[off]
            szs = sorted(set(sz for _, sz in pcs_sz))
            # unique PCs
            pcs = sorted(set(pc for pc, _ in pcs_sz))
            log(fh, f"   +0x{off:03X} (sz={szs}, reads_count={len(pcs_sz)}, PCs={[hex(p) for p in pcs[:4]]})")

    # Deadended / errored
    for i, s in enumerate(simgr.deadended[:4]):
        log(fh, f"\n--- deadended state {i} @0x{s.addr:X}, constraints={len(s.solver.constraints)} ---")
        for c in s.solver.constraints[:30]:
            log(fh, f"    {c}")

    for i, s in enumerate(simgr.errored[:6]):
        log(fh, f"\n--- errored state {i} @0x{s.state.addr:X}: {s.error} ---")

    # History for any active state at cutoff — to show last basic blocks
    if simgr.active:
        s = simgr.active[0]
        log(fh, f"\n--- active state[0] last 20 bbls ---")
        bbls = s.history.bbl_addrs.hardcopy
        for a in bbls[-20:]:
            log(fh, f"    0x{a:X}")

    # Trace errored states too — they hit the ret sentinel after going thru the function.
    for i, s in enumerate(simgr.errored[:4]):
        log(fh, f"\n--- errored state {i} bbls (last 40) ---")
        bbls = s.state.history.bbl_addrs.hardcopy
        for a in bbls[-40:]:
            log(fh, f"    0x{a:X}")

    fh.close()


if __name__ == "__main__":
    main()
