"""Targeted angr: confirm the CONCRETE values that make vt[43] reach draw
dispatch, AND enumerate what goes wrong if each is zero/missing.

Run variants:
  concrete      : all fields populated from known-good
  zerofill_mat  : *(BSLSP+0x58) is entirely zero (our crash case)
  null_tex      : BSLSP+0x50 is NULL
  null_cfg      : BSLSP+0x48 is NULL

For each variant, report: reached draw dispatch? path ending?
"""
import sys, time
import angr
import claripy
import logging

logging.getLogger("angr").setLevel(logging.ERROR)
logging.getLogger("cle").setLevel(logging.ERROR)
logging.getLogger("pyvex").setLevel(logging.ERROR)

BIN = r"C:\Users\filip\Desktop\FalloutWorld\re\Fallout4.exe"
LOG = r"C:\Users\filip\Desktop\FalloutWorld\re\_angr_bslsp_targeted.log"

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


def log(fh, msg):
    print(msg, flush=True); fh.write(msg + "\n"); fh.flush()


class NopRet(angr.SimProcedure):
    def run(self, *args): return claripy.BVV(0, 64)
class ReturnOne(angr.SimProcedure):
    def run(self, *args): return claripy.BVV(1, 64)
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
    0x142174C60: ReturnOne, 0x142174C70: NopRet,
    0x142215990: NopRet, 0x142200170: Alloc, 0x14223A6C0: Alloc,
    0x14223BC70: NopRet, 0x1416DE030: SymCall,
    0x1416D5640: NopRet, 0x1416D5930: NopRet,
    0x1416BD0B0: NopRet, 0x14167BCF0: NopRet,
    0x14167BDC0: NopRet, 0x14167C200: NopRet,
    0x1417E8950: NopRet, 0x1422B7498: NopRet,
    0x1422B70BC: NopRet, 0x1422B7438: NopRet,
}

DRAW_MARKERS = {0x1421611A0, 0x142215990, 0x142160FF0}


def prep(proj, scenario):
    """Scenario: 'concrete' | 'zerofill_mat_58' | 'zerofill_tex' | 'null_cfg' | 'null_tex' | 'null_mat'.
    """
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

    # BSLSP
    s.memory.store(BSLSP_ADDR + 0x00, claripy.BVV(VT_BSLSP, 64), endness='Iend_LE')

    # v9 flags at BSLSP+0x30 — required 0xC000000 | 0x100000
    s.memory.store(BSLSP_ADDR + 0x30, claripy.BVV(0x4100000, 64), endness='Iend_LE')

    # Pointer slots
    cfg_ptr = 0 if scenario == 'null_cfg' else CONFIG_ADDR
    tex_ptr = 0 if scenario == 'null_tex' else TEX_ADDR
    mat_ptr = 0 if scenario == 'null_mat' else SHMAT_ADDR

    s.memory.store(BSLSP_ADDR + 0x48, claripy.BVV(cfg_ptr, 64), endness='Iend_LE')
    s.memory.store(BSLSP_ADDR + 0x50, claripy.BVV(tex_ptr, 64), endness='Iend_LE')
    s.memory.store(BSLSP_ADDR + 0x58, claripy.BVV(mat_ptr, 64), endness='Iend_LE')

    # BSLSP scalar fields
    s.memory.store(BSLSP_ADDR + 0x28, claripy.BVV(0x3F800000, 32), endness='Iend_LE')
    s.memory.store(BSLSP_ADDR + 0x2C, claripy.BVV(0, 32), endness='Iend_LE')
    s.memory.store(BSLSP_ADDR + 0x64, claripy.BVV(0x3F800000, 32), endness='Iend_LE')

    # Config block (v11) at +0x48
    if cfg_ptr:
        s.memory.store(CONFIG_ADDR + 0x108, claripy.BVV(0, 32), endness='Iend_LE')
        s.memory.store(CONFIG_ADDR + 0x11D, claripy.BVV(0, 8), endness='Iend_LE')
        s.memory.store(CONFIG_ADDR + 0x11E, claripy.BVV(0, 8), endness='Iend_LE')
        s.memory.store(CONFIG_ADDR + 0x1A0, claripy.BVV(0x3F800000, 32), endness='Iend_LE')
        s.memory.store(CONFIG_ADDR + 0x1A4, claripy.BVV(0x3F800000, 32), endness='Iend_LE')

    # Tex state block at +0x50  — scenario-specific
    if tex_ptr:
        if scenario == 'zerofill_tex':
            # leave all zeros → bytes at +0x7D..0x83 = 0 so the |0x20/0x400/0x800/...
            # bits in v79 are NOT or'd in. Should still execute.
            pass
        else:
            # Seed a "typical" texture block state
            s.memory.store(TEX_ADDR + 0x20, claripy.BVV(0, 64), endness='Iend_LE')
            s.memory.store(TEX_ADDR + 0x74, claripy.BVV(0, 32), endness='Iend_LE')
            for off in (0x7D, 0x7E, 0x7F, 0x80, 0x81, 0x82, 0x83):
                s.memory.store(TEX_ADDR + off, claripy.BVV(1, 8), endness='Iend_LE')

    # Material A at +0x58 (shader float source)
    if mat_ptr:
        if scenario == 'zerofill_mat_58':
            # Test: does LEAVING ALL mat_58 bytes zero crash/short-circuit?
            s.memory.store(SHMAT_ADDR, claripy.BVV(0, 8 * 0x200), endness='Iend_LE')
        else:
            s.memory.store(SHMAT_ADDR + 0x80, claripy.BVV(0x3F800000, 32), endness='Iend_LE')

    # vtable for BSLSP - all slots point to vt[51] (hooked)
    for i in range(80):
        s.memory.store(VT_BSLSP + 8 * i, claripy.BVV(0x142174C60, 64), endness='Iend_LE')

    # GEOM
    s.memory.store(GEOM_ADDR + 0x00, claripy.BVV(VT_GEOM, 64), endness='Iend_LE')
    s.memory.store(GEOM_ADDR + 0x108, claripy.BVV(0, 32), endness='Iend_LE')
    s.memory.store(GEOM_ADDR + 0x130, claripy.BVV(0, 64), endness='Iend_LE')
    s.memory.store(GEOM_ADDR + 0x158, claripy.BVV(0, 8), endness='Iend_LE')
    s.memory.store(GEOM_ADDR + 0x160, claripy.BVV(0, 32), endness='Iend_LE')
    for i in range(70):
        s.memory.store(VT_GEOM + 8 * i, claripy.BVV(0x142174C60, 64), endness='Iend_LE')

    # CTX
    s.memory.store(CTX_ADDR + 0xB0, claripy.BVV(1, 8), endness='Iend_LE')
    s.memory.store(CTX_ADDR + 0xB1, claripy.BVV(0, 8), endness='Iend_LE')

    # force v14[1] check to take jne
    s.memory.store(0x143E4BBD8, claripy.BVV(0xBBBBBBBBBBBBBBBB, 64), endness='Iend_LE')

    s.regs.rcx = BSLSP_ADDR
    s.regs.rdx = GEOM_ADDR
    s.regs.r8  = 24
    s.regs.r9  = CTX_ADDR
    return s


def run_scenario(proj, scenario, fh):
    log(fh, f"\n======== SCENARIO: {scenario} ========")
    # Reset alloc counter
    Alloc._c = 0x60000000 + hash(scenario) & 0xFFFFFFF000  # spread
    state = prep(proj, scenario)
    simgr = proj.factory.simulation_manager(state)
    t0 = time.time()
    steps = 0
    while simgr.active and steps < 1000 and (time.time()-t0) < 60:
        simgr.step()
        steps += 1
        if len(simgr.active) > 10:
            simgr.active = simgr.active[:6]

    # Aggregate: any state reached a draw marker in its bbl history?
    reached = 0
    last_bbls = []
    last_addrs = []
    for stash in (simgr.active, simgr.deadended, simgr.errored):
        for item in stash:
            s = item.state if hasattr(item, 'state') else item
            hs = s.history.bbl_addrs.hardcopy
            if any(a in DRAW_MARKERS for a in hs):
                reached += 1
            last_bbls.append(hs[-8:])
            last_addrs.append(s.addr if hasattr(s, 'addr') else None)

    log(fh, f"    steps={steps}, t={time.time()-t0:.1f}s")
    log(fh, f"    active={len(simgr.active)} errored={len(simgr.errored)} "
            f"deadended={len(simgr.deadended)}")
    log(fh, f"    reached_draw_dispatch = {reached}/{len(last_bbls)} states")
    # Print last bbls for the first 3 states
    for i, hs in enumerate(last_bbls[:3]):
        addrs_str = " -> ".join(hex(a) for a in hs)
        log(fh, f"    path[{i}] end: {addrs_str}")


def main():
    fh = open(LOG, "w", encoding="utf-8")
    t0 = time.time()
    log(fh, f"[+] angr load")
    proj = angr.Project(BIN, auto_load_libs=False)
    for addr, p in HOOKS.items():
        try: proj.hook(addr, p())
        except: pass
    log(fh, f"    loaded in {time.time()-t0:.1f}s")

    for sc in ('concrete', 'zerofill_mat_58', 'zerofill_tex', 'null_cfg', 'null_tex', 'null_mat'):
        run_scenario(proj, sc, fh)

    fh.close()


if __name__ == "__main__":
    main()
