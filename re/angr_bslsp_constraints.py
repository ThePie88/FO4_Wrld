"""Second-pass angr analysis: EXTRACT CONSTRAINTS on symbolic fields.

Run after angr_bslsp_vt43.py confirmed the path works. Now we make the
'suspect' fields SYMBOLIC and see what the exploration demands.

Symbolic fields:
  - BSLSP+0x30 : v9 flags (HOT, qword)
  - BSLSP+0x28 : alpha float
  - BSLSP+0x64 : scale float
  - BSLSP+0x2C : flags dword
  - *(BSLSP+0x50) + 0x7D..0x83 : texture slot bytes  (7 bytes)
  - *(BSLSP+0x48) + 0x108 : flags DWORD (v11+264)
  - *(BSLSP+0x48) + 0x1A0 : alpha threshold (v11+416) float
  - *(BSLSP+0x58) + 0x80 : shader float (mat A +128)

Targets:
  - find=0x1421732EA (function ret).
  - avoid=0x000 (unmapped).

Output: re/_angr_bslsp_constraints.log
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
LOG = r"C:\Users\filip\Desktop\FalloutWorld\re\_angr_bslsp_constraints.log"

IMG_BASE = 0x140000000
FN = 0x142172540

BSLSP_ADDR = 0x10000000
CONFIG_ADDR = 0x20000000     # v11 (BSLSP+0x48)
TEX_ADDR   = 0x20000800      # texture state block (BSLSP+0x50)
SHMAT_ADDR = 0x20000400      # material A (BSLSP+0x58)
GEOM_ADDR  = 0x30000000
CTX_ADDR   = 0x40000000
VT_BSLSP   = 0x50000000
VT_GEOM    = 0x51000000
STACK_TOP  = 0x7FFFF008

TEB_BASE = 0x71000000
TLS_ARR  = 0x72000000
TLS_SLOT = 0x73000000

RET_SENTINEL = 0xdeadbeefcafef00d


def log(fh, msg):
    print(msg, flush=True); fh.write(msg + "\n"); fh.flush()


class NopRet(angr.SimProcedure):
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
        return claripy.BVS("sym", 64)


def install_hooks(proj):
    hooks = {
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
    for addr, p in hooks.items():
        try: proj.hook(addr, p())
        except: pass


def prep_state(proj):
    opts_add = {
        angr.options.LAZY_SOLVES,
        angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
        angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
    }
    opts_rm = {angr.options.STRICT_PAGE_ACCESS}
    state = proj.factory.blank_state(addr=FN, add_options=opts_add, remove_options=opts_rm)

    state.regs.rsp = claripy.BVV(STACK_TOP, 64)
    state.memory.store(STACK_TOP, claripy.BVV(RET_SENTINEL, 64), endness='Iend_LE')
    state.regs.gs = claripy.BVV(TEB_BASE, 64)
    state.memory.store(TEB_BASE + 0x58, claripy.BVV(TLS_ARR, 64), endness='Iend_LE')
    state.memory.store(TLS_ARR, claripy.BVV(TLS_SLOT, 64), endness='Iend_LE')

    # BSLSP — vtable + pointers
    state.memory.store(BSLSP_ADDR + 0x00, claripy.BVV(VT_BSLSP, 64), endness='Iend_LE')
    state.memory.store(BSLSP_ADDR + 0x48, claripy.BVV(CONFIG_ADDR, 64), endness='Iend_LE')
    state.memory.store(BSLSP_ADDR + 0x50, claripy.BVV(TEX_ADDR, 64), endness='Iend_LE')
    state.memory.store(BSLSP_ADDR + 0x58, claripy.BVV(SHMAT_ADDR, 64), endness='Iend_LE')

    # MAKE SYMBOLIC: BSLSP+0x28 (alpha), 0x2C (flags), 0x30 (v9 HOT flags), 0x64 (scale)
    v_alpha  = claripy.BVS("alpha", 32)
    v_flags  = claripy.BVS("flags", 32)
    v_v9     = claripy.BVS("v9", 64)
    v_scale  = claripy.BVS("scale", 32)
    state.memory.store(BSLSP_ADDR + 0x28, v_alpha, endness='Iend_LE')
    state.memory.store(BSLSP_ADDR + 0x2C, v_flags, endness='Iend_LE')
    state.memory.store(BSLSP_ADDR + 0x30, v_v9, endness='Iend_LE')
    state.memory.store(BSLSP_ADDR + 0x64, v_scale, endness='Iend_LE')

    # Guide v9 to force the 'enter full render' path
    state.solver.add((v_v9 & 0xC000000) != 0)
    state.solver.add((v_v9 & 0x100000) != 0)

    # Config (v11) at +0x48: symbolic flags, concrete floats.
    v_cfg_flags = claripy.BVS("cfg_flags", 32)
    state.memory.store(CONFIG_ADDR + 0x108, v_cfg_flags, endness='Iend_LE')
    state.memory.store(CONFIG_ADDR + 0x11D, claripy.BVV(0, 8), endness='Iend_LE')
    state.memory.store(CONFIG_ADDR + 0x11E, claripy.BVV(0, 8), endness='Iend_LE')
    state.memory.store(CONFIG_ADDR + 0x1A0, claripy.BVV(0x3F800000, 32), endness='Iend_LE')  # 1.0f
    state.memory.store(CONFIG_ADDR + 0x1A4, claripy.BVV(0x3F800000, 32), endness='Iend_LE')

    # Texture state block (v70) — symbolic byte array +0x7D..+0x83 +0x20/+0x74
    v_tex_bytes = [claripy.BVS(f"tex_b{i:X}", 8) for i in range(0x7D, 0x84)]
    for i, bv in enumerate(v_tex_bytes):
        state.memory.store(TEX_ADDR + 0x7D + i, bv, endness='Iend_LE')
    # +0x20: checked for not-NULL to set 0x1000000 flag
    v_tex_20 = claripy.BVS("tex_20", 64)
    state.memory.store(TEX_ADDR + 0x20, v_tex_20, endness='Iend_LE')
    # +0x74: int (flag field)
    v_tex_74 = claripy.BVS("tex_74", 32)
    state.memory.store(TEX_ADDR + 0x74, v_tex_74, endness='Iend_LE')

    # Shader material A (BSLSP+0x58) — symbolic float @ +0x80
    v_shmat_80 = claripy.BVS("shmat_80", 32)
    state.memory.store(SHMAT_ADDR + 0x80, v_shmat_80, endness='Iend_LE')

    # vtable slots on BSLSP (the vt[51] gets hooked, others nop)
    for i in range(80):
        state.memory.store(VT_BSLSP + 8 * i, claripy.BVV(0x142174C60, 64), endness='Iend_LE')

    # GEOM
    state.memory.store(GEOM_ADDR + 0x00, claripy.BVV(VT_GEOM, 64), endness='Iend_LE')
    state.memory.store(GEOM_ADDR + 0x108, claripy.BVV(0, 32), endness='Iend_LE')
    state.memory.store(GEOM_ADDR + 0x130, claripy.BVV(0, 64), endness='Iend_LE')
    state.memory.store(GEOM_ADDR + 0x158, claripy.BVV(0, 8), endness='Iend_LE')
    state.memory.store(GEOM_ADDR + 0x160, claripy.BVV(0, 32), endness='Iend_LE')
    for i in range(70):
        state.memory.store(VT_GEOM + 8 * i, claripy.BVV(0x142174C60, 64), endness='Iend_LE')

    # CTX
    state.memory.store(CTX_ADDR + 0xB0, claripy.BVV(1, 8), endness='Iend_LE')
    state.memory.store(CTX_ADDR + 0xB1, claripy.BVV(0, 8), endness='Iend_LE')

    # force v14[1] != qword_143E4BBD8
    state.memory.store(0x143E4BBD8, claripy.BVV(0xBBBBBBBBBBBBBBBB, 64), endness='Iend_LE')

    state.regs.rcx = BSLSP_ADDR
    state.regs.rdx = GEOM_ADDR
    state.regs.r8  = 24
    state.regs.r9  = CTX_ADDR

    # Store symbols on state for later extraction
    state.globals['v_v9']     = v_v9
    state.globals['v_alpha']  = v_alpha
    state.globals['v_flags']  = v_flags
    state.globals['v_scale']  = v_scale
    state.globals['v_cfg_flags'] = v_cfg_flags
    state.globals['v_tex_20'] = v_tex_20
    state.globals['v_tex_74'] = v_tex_74
    state.globals['v_shmat_80']  = v_shmat_80
    state.globals['v_tex_bytes'] = v_tex_bytes

    return state


def main():
    fh = open(LOG, "w", encoding="utf-8")
    t0 = time.time()
    log(fh, f"[+] angr load {BIN}")
    proj = angr.Project(BIN, auto_load_libs=False)
    install_hooks(proj)
    log(fh, f"    [+] load took {time.time()-t0:.1f}s")

    state = prep_state(proj)
    log(fh, f"[+] state prepared, ip=0x{state.addr:X}")

    simgr = proj.factory.simulation_manager(state)

    # Find: sentinel PC. Avoid: nothing specific (function body exits naturally).
    log(fh, "[+] exploring with symbolic flags, budget 90s")
    t0 = time.time()
    steps = 0
    MAX_S = 90
    MAX_STEPS = 2500
    while simgr.active and steps < MAX_STEPS and (time.time()-t0) < MAX_S:
        simgr.step()
        steps += 1
        if steps % 50 == 0:
            log(fh, f"    step {steps}: active={len(simgr.active)} errored={len(simgr.errored)}"
                    f" deadended={len(simgr.deadended)} t={time.time()-t0:.1f}s")
        # Path explosion — aggressive veto
        if len(simgr.active) > 12:
            # Cull states still deep in symbolic explosion
            keep = simgr.active[:6]
            simgr.active = keep

    log(fh, f"[+] done, steps={steps}, elapsed={time.time()-t0:.1f}s")
    log(fh, f"    final: active={len(simgr.active)} errored={len(simgr.errored)} "
            f"deadended={len(simgr.deadended)}")

    # Find states that reached 0x1421611A0 (draw push hook) in history
    DRAW_MARKERS = {0x1421611A0, 0x142215990, 0x142160FF0}
    reached_draw = []
    def hist_has_marker(s):
        for a in s.history.bbl_addrs.hardcopy:
            if a in DRAW_MARKERS:
                return True
        return False
    for stash in (simgr.errored, simgr.active, simgr.deadended):
        for item in stash:
            s = item.state if hasattr(item, 'state') else item
            if hist_has_marker(s):
                reached_draw.append(s)

    log(fh, f"\n==== states that reached draw dispatch: {len(reached_draw)} ====")
    for i, s in enumerate(reached_draw[:4]):
        log(fh, f"\n--- state {i} @0x{s.addr:X}, constraints={len(s.solver.constraints)} ---")
        # Try to concretize each symbolic
        for name in ['v_v9', 'v_alpha', 'v_flags', 'v_scale',
                     'v_cfg_flags', 'v_tex_20', 'v_tex_74', 'v_shmat_80']:
            sym = s.globals.get(name)
            if sym is None: continue
            try:
                val = s.solver.eval(sym)
                minv = s.solver.min(sym)
                maxv = s.solver.max(sym)
                log(fh, f"    {name:16s}: concrete=0x{val:X}  min=0x{minv:X}  max=0x{maxv:X}")
            except Exception as e:
                log(fh, f"    {name:16s}: ERR {e}")
        # Texture byte array
        tex_bytes = s.globals.get('v_tex_bytes')
        if tex_bytes:
            for i, bv in enumerate(tex_bytes):
                try:
                    mn = s.solver.min(bv)
                    mx = s.solver.max(bv)
                    log(fh, f"    tex+0x{0x7D + i:02X}       : min=0x{mn:X} max=0x{mx:X}")
                except Exception as e:
                    log(fh, f"    tex+0x{0x7D + i:02X}       : ERR {e}")
        # Dump top constraints
        log(fh, "    --- constraints (truncated) ---")
        for c in s.solver.constraints[:20]:
            s_ = str(c)
            if len(s_) > 200: s_ = s_[:200] + "..."
            log(fh, f"      {s_}")

    # States that did NOT reach draw dispatch → "invisible" / "crashed" paths
    not_reached = []
    for stash in (simgr.errored, simgr.active, simgr.deadended):
        for item in stash:
            s = item.state if hasattr(item, 'state') else item
            if not hist_has_marker(s):
                not_reached.append(s)

    log(fh, f"\n==== states that did NOT reach draw (invisible paths): {len(not_reached)} ====")
    for i, s in enumerate(not_reached[:4]):
        log(fh, f"\n--- state {i} @0x{s.addr:X} ---")
        bbls = s.history.bbl_addrs.hardcopy[-15:]
        for a in bbls: log(fh, f"    0x{a:X}")
        for name in ['v_v9', 'v_shmat_80']:
            sym = s.globals.get(name)
            if sym is None: continue
            try:
                val = s.solver.eval(sym)
                log(fh, f"    {name:16s}: concrete=0x{val:X}")
            except Exception: pass

    fh.close()


if __name__ == "__main__":
    main()
