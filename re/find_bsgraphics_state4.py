"""find_bsgraphics_state4.py

New approach: find SetCamera anchor. CommonLibF4 documents:
  BSShaderAccumulator::SetCameraData(NiCamera*, ...)
  NiCamera has ViewProj at +288 (0x120).

BSShaderAccumulator vtable is at RVA 0x290A6B0. The 26 Set/Restore methods are
at 0x239490..0x2395F0 but they are all `return 0` stubs (= default nullsubs).
The REAL camera setter is in vtable slots 23-25 differently laid out. Actually
slot indices 22..25 = Set-like. Let me look at BSShaderAccumulator non-virtual
methods: xrefs to vtable are the ctors.

Alternative anchor: a function that READS from NiCamera+0x120 (viewProj) and
WRITES to [global_ptr + 0xD0] or similar. Search:
  mov rax, [rip+G1]        ; load State*
  movaps xmm0, [rbx+0x120] ; load NiCamera.worldToCam viewMat OR viewProj
  movaps [rax+0xD0], xmm0

Or anchor on NiCamera vtable RVA 0x267DD50 — find callers that write singletons.

Yet another: search for string "BSGraphics::Renderer" or similar in debug/RTTI.
"""
import ida_auto, ida_bytes, ida_funcs, ida_hexrays, ida_nalt, ida_name
import ida_segment, ida_ua
import idautils, idc

OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\bsgraphics_state_report4.txt"
def ib(): return ida_nalt.get_imagebase()
def rva(ea): return ea - ib()
def log(m, fh): print(m); fh.write(m+"\n"); fh.flush()

def main():
    with open(OUT,'w',encoding='utf8') as fh:
        log(f"image base 0x{ib():X}", fh)

        # A: find any string containing 'BSGraphics' and xref
        log("\n== A: ALL BSGraphics-containing strings ==", fh)
        seen = 0
        gs = []
        for sea in idautils.Strings():
            try:
                s = str(sea)
                if 'BSGraphics' in s and 'Pool' not in s and 'Alloc' not in s:
                    log(f"  @0x{sea.ea:X} (RVA 0x{rva(sea.ea):X}) '{s[:140]}'", fh)
                    gs.append(sea.ea); seen += 1
                    if seen > 80: break
            except: pass
        log(f"  total shown: {seen}", fh)

        # B: look at xrefs to the NiCamera vtable (RVA 0x267DD50) — binders/ctors
        log("\n== B: NiCamera vtable xrefs ==", fh)
        NICAM = ib() + 0x267DD50
        ni_refs = []
        for x in idautils.XrefsTo(NICAM, 0):
            fn = ida_funcs.get_func(x.frm)
            if fn: ni_refs.append(fn.start_ea)
        ni_refs = list(set(ni_refs))
        log(f"  unique NiCamera ctor callers: {len(ni_refs)} -> {[hex(rva(f)) for f in ni_refs[:10]]}", fh)

        # C: decomp slots 22-25 of BSShaderAccumulator (they may be nullsubs in 1.11.191;
        # try the non-virtual helper funcs near the vtable)
        # skip

        # D: read-NiCam+0x120, write-global+0xD0 pattern
        log("\n== D: NiCam[+0x120]->global[+0xD0] pattern ==", fh)
        TEXT = ida_segment.get_segm_by_name('.text')
        DATA = [ida_segment.get_segm_by_name(n) for n in ('.data','.bss','.rdata')]
        DATA = [d for d in DATA if d]
        def in_data(ea):
            for d in DATA:
                if d.start_ea <= ea < d.end_ea: return True
            return False
        hits = []
        for fnea in idautils.Functions(TEXT.start_ea, TEXT.end_ea):
            fn = ida_funcs.get_func(fnea)
            if not fn: continue
            sz = fn.end_ea - fn.start_ea
            if sz < 0x20 or sz > 0x600: continue
            # Find reads with disp >= 0x120 (NiCam viewMat/projMat) AND writes at +0xD0
            read_disps = set()
            write_disps = set()
            global_loads = []
            ea = fn.start_ea
            while ea < fn.end_ea:
                ins = ida_ua.insn_t()
                if not ida_ua.decode_insn(ins, ea):
                    ea += 1; continue
                m = ins.get_canon_mnem()
                # global load
                if m == 'mov' and ins.ops[0].type == ida_ua.o_reg and ins.ops[1].type == ida_ua.o_mem and in_data(ins.ops[1].addr):
                    global_loads.append(ins.ops[1].addr)
                # reads from [reg+disp]: source operand is displ
                if m in ('movaps','movups','movdqa','movdqu','mov'):
                    if ins.ops[1].type == ida_ua.o_displ:
                        read_disps.add(ins.ops[1].addr)
                    if ins.ops[0].type == ida_ua.o_displ:
                        write_disps.add(ins.ops[0].addr)
                ea += ins.size
            if {0x120, 0x130, 0x140, 0x150}.issubset(read_disps) and {0xD0, 0xE0, 0xF0, 0x100}.issubset(write_disps) and global_loads:
                hits.append((fn.start_ea, global_loads))
                if len(hits) > 20: break
        log(f"  hits: {len(hits)}", fh)
        for (fn, gls) in hits[:10]:
            log(f"    fn RVA 0x{rva(fn):X} globals={[hex(rva(g)) for g in gls[:8]]}", fh)

        # E: ANY function that writes 4 consecutive __m128 to [reg+0xD0..0x100] where reg is not rsp/rbp
        log("\n== E: writer +0xD0..+0x100 where base != rsp/rbp ==", fh)
        RSP=4; RBP=5
        hits2 = []
        for fnea in idautils.Functions(TEXT.start_ea, TEXT.end_ea):
            fn = ida_funcs.get_func(fnea)
            if not fn: continue
            sz = fn.end_ea - fn.start_ea
            if sz < 0x20 or sz > 0x500: continue
            writes = {}
            global_loads = []
            ea = fn.start_ea
            while ea < fn.end_ea:
                ins = ida_ua.insn_t()
                if not ida_ua.decode_insn(ins, ea):
                    ea += 1; continue
                m = ins.get_canon_mnem()
                if m == 'mov' and ins.ops[0].type == ida_ua.o_reg and ins.ops[1].type == ida_ua.o_mem and in_data(ins.ops[1].addr):
                    global_loads.append(ins.ops[1].addr)
                if m in ('movaps','movups','movdqa','movdqu'):
                    if ins.ops[0].type == ida_ua.o_displ:
                        writes.setdefault(ins.ops[0].reg, set()).add(ins.ops[0].addr)
                ea += ins.size
            for reg, ds in writes.items():
                if reg in (RSP, RBP): continue
                if {0xD0, 0xE0, 0xF0, 0x100}.issubset(ds):
                    hits2.append((fn.start_ea, reg, sorted(ds), global_loads))
                    break
            if len(hits2) > 40: break
        log(f"  hits2: {len(hits2)}", fh)
        for (fn, reg, ds, gls) in hits2[:15]:
            log(f"    fn RVA 0x{rva(fn):X} reg={reg} disps={[hex(d) for d in ds[:20]]} globals={[hex(rva(g)) for g in gls[:6]]}", fh)

        # Decomp first few hits2
        for (fn, reg, ds, gls) in hits2[:5]:
            try:
                cf = ida_hexrays.decompile(fn)
                if cf:
                    log(f"\n--- fn RVA 0x{rva(fn):X} ---", fh)
                    log(str(cf)[:5000], fh)
            except Exception as e:
                log(f"  decomp err: {e}", fh)

        log("\n== DONE ==", fh)

main()
