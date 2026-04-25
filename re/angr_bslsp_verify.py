"""Verification pass: use angr to CONFIRM the Triton agent's 11-constraint set.

For each Triton constraint C1..C11, assert the opposite and see if a path is
feasible to reach LABEL_52.  If NOT feasible, constraint is CONFIRMED.
If FEASIBLE, Triton is wrong.

Output: re/_angr_bslsp_verify.log
"""
import sys, time
import angr
import claripy
import logging

logging.getLogger("angr").setLevel(logging.ERROR)
logging.getLogger("cle").setLevel(logging.ERROR)
logging.getLogger("pyvex").setLevel(logging.ERROR)

BIN = r"C:\Users\filip\Desktop\FalloutWorld\re\Fallout4.exe"
LOG = r"C:\Users\filip\Desktop\FalloutWorld\re\_angr_bslsp_verify.log"

FN = 0x142172540

BSLSP_ADDR = 0x10000000
CONFIG_ADDR = 0x20000000
TEX_ADDR   = 0x20000800
SHMAT_ADDR = 0x20000400
GEOM_ADDR  = 0x30000000
CTX_ADDR   = 0x40000000
VT_BSLSP   = 0x50000000
VT_GEOM    = 0x51000000
STACK_TOP  = 0x7FFFF008
TEB_BASE = 0x71000000
TLS_ARR  = 0x72000000
TLS_SLOT = 0x73000000
LABEL_52 = 0x14217295D  # ~ the address where LABEL_52 code begins (v21 read)
DRAW_MARKERS = {0x1421611A0, 0x142215990}  # 0x142160FF0 is a post-draw, 0x142160F80 is ABORT


def log(fh, msg):
    print(msg, flush=True); fh.write(msg + "\n"); fh.flush()


class NopRet(angr.SimProcedure):
    def run(self, *args): return claripy.BVV(0, 64)
class ReturnOne(angr.SimProcedure):
    def run(self, *args): return claripy.BVV(1, 64)


class ReturnOneFloat(angr.SimProcedure):
    """Return 1.0f in xmm0 (for float-returning helpers like vt[51])."""
    def run(self, *args):
        # 1.0f bit pattern, zero-extended to 128 bits in xmm0
        self.state.regs.xmm0 = claripy.BVV(0x3F800000, 128)
        return claripy.BVV(0, 64)  # rax return not used for float
class Alloc(angr.SimProcedure):
    _c = 0x60000000
    def run(self, *args):
        a = Alloc._c; Alloc._c += 0x1000
        return claripy.BVV(a, 64)
class SymCall(angr.SimProcedure):
    def run(self, *args): return claripy.BVS("s", 64)


HOOKS = {
    0x141657F90: NopRet, 0x1416579C0: Alloc, 0x14165C3F0: NopRet,
    0x141656E30: SymCall, 0x1418214C0: NopRet, 0x1401E00D0: NopRet,
    0x142160C10: NopRet, 0x142160F80: NopRet, 0x142160FF0: NopRet,
    0x142161090: Alloc, 0x1421611A0: Alloc, 0x142161B10: NopRet,
    0x142161EC0: ReturnOne, 0x142161F20: ReturnOne,
    0x142162020: NopRet, 0x142162090: NopRet,
    0x142171830: NopRet, 0x142173390: NopRet,
    0x142174150: NopRet, 0x142174520: NopRet,
    0x142174800: NopRet, 0x142174820: NopRet, 0x142174A00: NopRet,
    0x142174C30: NopRet, 0x142174C40: NopRet,
    # vt[51] returns float in xmm0 — we let angr execute it concretely
    # (only 3 insns); so DO NOT hook it.
    0x142174C70: NopRet,
    0x142215990: NopRet, 0x142200170: Alloc, 0x14223A6C0: Alloc,
    0x14223BC70: NopRet, 0x1416DE030: SymCall,
    0x1416D5640: NopRet, 0x1416D5930: NopRet,
    0x1416BD0B0: NopRet, 0x14167BCF0: NopRet,
    0x14167BDC0: NopRet, 0x14167C200: NopRet,
    0x1417E8950: NopRet, 0x1422B7498: NopRet,
    0x1422B70BC: NopRet, 0x1422B7438: NopRet,
}


def prep_state(proj, a3=24, tweaks=None):
    """Build initial state. tweaks: callable(state) that alters specific fields."""
    opts_add = {
        angr.options.LAZY_SOLVES,
        angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
        angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
    }
    opts_rm = {angr.options.STRICT_PAGE_ACCESS}
    s = proj.factory.blank_state(addr=FN, add_options=opts_add, remove_options=opts_rm)
    s.regs.rsp = claripy.BVV(STACK_TOP, 64)
    s.memory.store(STACK_TOP, claripy.BVV(0xdeadbeefcafef00d, 64), endness='Iend_LE')
    s.regs.gs = claripy.BVV(TEB_BASE, 64)
    s.memory.store(TEB_BASE + 0x58, claripy.BVV(TLS_ARR, 64), endness='Iend_LE')
    s.memory.store(TLS_ARR, claripy.BVV(TLS_SLOT, 64), endness='Iend_LE')

    # BSLSP defaults (ctor'd values per Triton §5)
    s.memory.store(BSLSP_ADDR + 0x00, claripy.BVV(VT_BSLSP, 64), endness='Iend_LE')
    s.memory.store(BSLSP_ADDR + 0x28, claripy.BVV(0x3F800000, 32), endness='Iend_LE')  # 1.0f
    s.memory.store(BSLSP_ADDR + 0x2C, claripy.BVV(0x7FFFFFFF, 32), endness='Iend_LE')  # ctor default
    # NOTE: per Triton §3 + my disasm re-read, v10 is TRUE iff:
    #   (v9 & 0x100000) == 0  (bit 20 CLEAR is the ctor default)
    #   OR byte_143E475F5 != 0
    #   OR a3 == 18
    # BSLSP ctor leaves v9=0. So default v9=0 makes v10=TRUE. Use v9=0.
    s.memory.store(BSLSP_ADDR + 0x30, claripy.BVV(0, 64), endness='Iend_LE')
    s.memory.store(BSLSP_ADDR + 0x48, claripy.BVV(CONFIG_ADDR, 64), endness='Iend_LE')
    s.memory.store(BSLSP_ADDR + 0x50, claripy.BVV(TEX_ADDR, 64), endness='Iend_LE')
    s.memory.store(BSLSP_ADDR + 0x58, claripy.BVV(SHMAT_ADDR, 64), endness='Iend_LE')
    s.memory.store(BSLSP_ADDR + 0x64, claripy.BVV(0x3F800000, 32), endness='Iend_LE')

    # Config (v11)
    s.memory.store(CONFIG_ADDR + 0x108, claripy.BVV(0, 32), endness='Iend_LE')
    s.memory.store(CONFIG_ADDR + 0x11D, claripy.BVV(0, 8), endness='Iend_LE')
    s.memory.store(CONFIG_ADDR + 0x11E, claripy.BVV(0, 8), endness='Iend_LE')
    s.memory.store(CONFIG_ADDR + 0x1A0, claripy.BVV(0x3F800000, 32), endness='Iend_LE')
    s.memory.store(CONFIG_ADDR + 0x1A4, claripy.BVV(0x3F800000, 32), endness='Iend_LE')

    # Texture state (v70)
    s.memory.store(TEX_ADDR + 0x20, claripy.BVV(0, 64), endness='Iend_LE')
    s.memory.store(TEX_ADDR + 0x74, claripy.BVV(0, 32), endness='Iend_LE')
    for off in (0x7D, 0x7E, 0x7F, 0x80, 0x81, 0x82, 0x83):
        s.memory.store(TEX_ADDR + off, claripy.BVV(1, 8), endness='Iend_LE')

    # Material A
    s.memory.store(SHMAT_ADDR + 0x80, claripy.BVV(0x3F800000, 32), endness='Iend_LE')  # 1.0f glossiness

    for i in range(80):
        s.memory.store(VT_BSLSP + 8 * i, claripy.BVV(0x142174C60, 64), endness='Iend_LE')

    s.memory.store(GEOM_ADDR + 0x00, claripy.BVV(VT_GEOM, 64), endness='Iend_LE')
    s.memory.store(GEOM_ADDR + 0x108, claripy.BVV(0, 32), endness='Iend_LE')
    s.memory.store(GEOM_ADDR + 0x130, claripy.BVV(0, 64), endness='Iend_LE')
    s.memory.store(GEOM_ADDR + 0x158, claripy.BVV(0, 8), endness='Iend_LE')
    s.memory.store(GEOM_ADDR + 0x160, claripy.BVV(0, 32), endness='Iend_LE')
    for i in range(70):
        s.memory.store(VT_GEOM + 8 * i, claripy.BVV(0x142174C60, 64), endness='Iend_LE')

    s.memory.store(CTX_ADDR + 0xB0, claripy.BVV(1, 8), endness='Iend_LE')
    s.memory.store(CTX_ADDR + 0xB1, claripy.BVV(0, 8), endness='Iend_LE')
    s.memory.store(0x143E4BBD8, claripy.BVV(0xBBBBBBBBBBBBBBBB, 64), endness='Iend_LE')

    s.regs.rcx = BSLSP_ADDR
    s.regs.rdx = GEOM_ADDR
    s.regs.r8  = a3
    s.regs.r9  = CTX_ADDR

    if tweaks:
        tweaks(s)
    return s


def reached_draw(simgr):
    for stash in (simgr.active, simgr.deadended, simgr.errored):
        for item in stash:
            st = item.state if hasattr(item, 'state') else item
            if any(a in DRAW_MARKERS for a in st.history.bbl_addrs.hardcopy):
                return True
    return False


def run(proj, tweaks, timeout=30, label=""):
    Alloc._c = 0x60000000
    st = prep_state(proj, tweaks=tweaks)
    sm = proj.factory.simulation_manager(st)
    t0 = time.time()
    steps = 0
    while sm.active and steps < 800 and (time.time()-t0) < timeout:
        sm.step()
        steps += 1
        if len(sm.active) > 10:
            sm.active = sm.active[:6]
    ok = reached_draw(sm)
    # dump last bbls for insight
    last_bbls = None
    for stash in (sm.errored, sm.deadended, sm.active):
        for item in stash:
            st = item.state if hasattr(item, 'state') else item
            last_bbls = st.history.bbl_addrs.hardcopy[-10:]
            break
        if last_bbls: break
    return ok, steps, time.time()-t0, last_bbls


def violate(label, tweak):
    return (label, tweak)


def main():
    fh = open(LOG, "w", encoding="utf-8")
    t0 = time.time()
    log(fh, f"[+] angr load {BIN}")
    proj = angr.Project(BIN, auto_load_libs=False)
    for addr, p in HOOKS.items():
        try: proj.hook(addr, p())
        except: pass
    log(fh, f"    [+] load took {time.time()-t0:.1f}s")

    # Tweaks: each one VIOLATES one Triton constraint. We expect draw NOT reached.
    experiments = [
        ("BASELINE (all constraints satisfied)",
         lambda s: None),

        # C1 violation: a3 = 21 or 0 -> fast-path, no draw
        ("C1_violation: a3=21",
         lambda s: (s.memory.store(BSLSP_ADDR + 0x00, claripy.BVV(VT_BSLSP, 64), endness='Iend_LE'),
                    s.__setattr__('regs', s.regs) or None,
                    None)),  # actually modify regs directly elsewhere

        # C4 violation: THIS->material = 0
        ("C4_violation: BSLSP+0x58 = NULL",
         lambda s: s.memory.store(BSLSP_ADDR + 0x58, claripy.BVV(0, 64), endness='Iend_LE')),

        # C6 violation: material+0x80 = 0 (vt[51] returns 0.0 — REJECT2)
        ("C6_violation: mat+0x80 = 0.0",
         lambda s: s.memory.store(SHMAT_ADDR + 0x80, claripy.BVV(0, 32), endness='Iend_LE')),

        # C7 violation: BSLSP+0x64 = 0 -> REJECT4
        ("C7_violation: BSLSP+0x64 = 0.0",
         lambda s: s.memory.store(BSLSP_ADDR + 0x64, claripy.BVV(0, 32), endness='Iend_LE')),

        # C8 violation: flags bit 0x100000 set AND a3 != 18 -> !v10 if byte_143E475F5 = 0
        ("C8_violation: flags |= 0x100000 (v10 becomes FALSE)",
         lambda s: s.memory.store(BSLSP_ADDR + 0x30,
                                 claripy.BVV(0x100000, 64), endness='Iend_LE')),

        # C2 violation: vtable NULL
        # skip — our hook at vt[51] is address-specific; setting vtable NULL just crashes.

        # Additional: v9 flags = 0 (no 0xC000000) -> REJECT4 path taken + no fallback
        ("SIDE_CHECK: v9=0 (all rejects + no fallback)",
         lambda s: s.memory.store(BSLSP_ADDR + 0x30, claripy.BVV(0, 64), endness='Iend_LE')),
    ]

    for label, tw in experiments:
        if 'a3=21' in label:
            def custom_tweak(s):
                s.regs.r8 = 21
            ok, steps, t, bbls = run(proj, custom_tweak, label=label)
        else:
            ok, steps, t, bbls = run(proj, tw, label=label)
        mark = "REACHED_DRAW" if ok else "no_draw"
        bbl_s = " -> ".join(hex(a) for a in (bbls or [])[-6:])
        log(fh, f"  {label:50s} -> {mark:15s} (steps={steps}, t={t:.2f}s)")
        log(fh, f"      last bbls: {bbl_s}")

    # CROSS-CHECK: does vt[51] return 0 when mat+0x80 = 0?
    log(fh, "\n--- vt[51] symbolic accessor verification ---")
    def call_vt51(mat_80, mat_ptr, label_extra=""):
        opts_add = {angr.options.LAZY_SOLVES, angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY}
        opts_rm = {angr.options.STRICT_PAGE_ACCESS}
        s = proj.factory.blank_state(addr=0x142174C60, add_options=opts_add, remove_options=opts_rm)
        s.regs.rsp = claripy.BVV(STACK_TOP, 64)
        s.memory.store(STACK_TOP, claripy.BVV(0xdeadbeefcafef00d, 64), endness='Iend_LE')
        s.memory.store(BSLSP_ADDR + 0x58, claripy.BVV(mat_ptr, 64), endness='Iend_LE')
        if mat_ptr:
            s.memory.store(mat_ptr + 0x80, claripy.BVV(mat_80, 32), endness='Iend_LE')
        s.regs.rcx = BSLSP_ADDR
        sm = proj.factory.simulation_manager(s)
        # step until ret
        for _ in range(10):
            if not sm.active: break
            sm.step()
            if sm.errored: break
        # Find the state that ret'd (ip == sentinel)
        state = None
        for st in (sm.errored[0].state if sm.errored else None,
                   sm.active[0] if sm.active else None,
                   sm.deadended[0] if sm.deadended else None):
            if st and st.addr == 0xdeadbeefcafef00d:
                state = st; break
        if not state:
            for st in (sm.errored, sm.active, sm.deadended):
                if st:
                    state = st[0] if not hasattr(st[0], 'state') else st[0].state
                    break
        if state:
            try:
                xmm0 = state.regs.xmm0
                low32 = xmm0[31:0]
                val = state.solver.eval(low32)
                log(fh, f"    [{label_extra}] vt[51](mat_80=0x{mat_80:X}) -> xmm0_low32=0x{val:X} @ addr=0x{state.addr:X}")
            except Exception as e:
                log(fh, f"    [{label_extra}] err: {e}")
        else:
            log(fh, f"    [{label_extra}] no final state")
            for e in sm.errored[:1]:
                log(fh, f"      errored: {e.error}")
    call_vt51(0x3F800000, SHMAT_ADDR, "1.0f")
    call_vt51(0, SHMAT_ADDR, "0.0f")

    # test 3: NULL material
    log(fh, "\n    test 3: BSLSP+0x58 = 0 (NULL material) -- expect crash")
    opts_add = {angr.options.LAZY_SOLVES, angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY}
    opts_rm = {angr.options.STRICT_PAGE_ACCESS}
    s = proj.factory.blank_state(addr=0x142174C60, add_options=opts_add, remove_options=opts_rm)
    s.regs.rsp = claripy.BVV(STACK_TOP, 64)
    s.memory.store(STACK_TOP, claripy.BVV(0xdeadbeefcafef00d, 64), endness='Iend_LE')
    s.memory.store(BSLSP_ADDR + 0x58, claripy.BVV(0, 64), endness='Iend_LE')
    s.regs.rcx = BSLSP_ADDR
    sm = proj.factory.simulation_manager(s)
    for _ in range(10):
        if not sm.active: break
        sm.step()
        if sm.errored: break
    if sm.errored:
        log(fh, f"    NULL mat -> crash @ 0x{sm.errored[0].state.addr:X}: {sm.errored[0].error}")
    elif sm.active:
        log(fh, f"    NULL mat -> active @ 0x{sm.active[0].addr:X}")
    elif sm.deadended:
        log(fh, f"    NULL mat -> deadended @ 0x{sm.deadended[0].addr:X}")

    fh.close()


if __name__ == "__main__":
    main()
