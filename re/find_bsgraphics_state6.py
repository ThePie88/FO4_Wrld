"""find_bsgraphics_state6.py — last-ditch via shader_cb globals and NiCamera-concat anchor"""
import ida_hexrays, ida_funcs, ida_nalt, ida_bytes, ida_segment, idautils, idc, ida_ua
OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\bsgraphics_state_report6.txt"
def ib(): return ida_nalt.get_imagebase()
def rva(ea): return ea - ib()
def log(m, fh): print(m); fh.write(m+"\n"); fh.flush()

def decomp(fea, fh, label, maxc=6000):
    fn = ida_funcs.get_func(fea)
    if not fn: log(f"  no fn 0x{fea:X}", fh); return None
    try:
        cf = ida_hexrays.decompile(fn.start_ea)
        if not cf: return None
        txt = str(cf)
        log(f"\n==== {label} @ RVA 0x{rva(fn.start_ea):X} (sz 0x{fn.end_ea-fn.start_ea:X}) ====", fh)
        log(txt[:maxc] + ("\n..." if len(txt) > maxc else ""), fh)
        return txt
    except Exception as e:
        log(f"  err: {e}", fh); return None

def main():
    with open(OUT,'w',encoding='utf8') as fh:
        log(f"image base 0x{ib():X}", fh)

        # A: What functions store/read these known-CB-ptr globals from shader_cb_report
        log("\n== A: xrefs to CB globals 0x3E5AE58 0x3E5AE70 0x3A0F400 ==", fh)
        for g_rva in (0x3E5AE58, 0x3E5AE70, 0x3A0F400):
            gea = ib() + g_rva
            refs = []
            for x in idautils.XrefsTo(gea, 0):
                fn = ida_funcs.get_func(x.frm)
                refs.append((x.frm, fn.start_ea if fn else None))
            log(f"  global 0x{g_rva:X}: {len(refs)} xrefs", fh)
            for (site, fn) in refs[:20]:
                log(f"    site 0x{rva(site):X} fn 0x{rva(fn):X}" if fn else f"    site 0x{rva(site):X} NO FN", fh)

        # B: pattern: a function that reads NiCamera.m_kProjection (offset 0xA0..0xD0 = 3 matrices
        # 0xA0 viewMat, 0xE0 projMat, 0x120 viewProjMat) and then calls matrix-mul + stores
        # into a global-indirected pointer. Scan for:
        #   mov rax, [rip+G]
        #   movaps xmm, [r?+0x120] (read NiCam viewProjMat)
        #   movaps [rax + Y], xmm  (write somewhere in singleton)
        # We want to figure out Y.
        log("\n== B: disassembly dump around known render init helper 0x21A0680 (CB_Map_A) ==", fh)
        decomp(ib()+0x21A0680, fh, "CB_Map_A helper", 3000)
        decomp(ib()+0x21A05E0, fh, "CB_Map_B helper", 3000)

        # C: look at BSShaderAccumulator::SetupPrepass or SetCameraData. Slot 22 of vtable
        # 0x290A6B0 is sub_140239490 (nullsub). Non-vtable methods — look at constructor xrefs.
        # BSShaderAccumulator ctor at 0x21CFBF0 (vtable slot 2 assigns itself). Look at the
        # init function that creates accumulator AND populates BSGraphics::State. Actually
        # 0x21CFAE0 is dtor.
        # More promising: look at what reads CB_Map_A's arg 1 (CB descriptor table @ 0x3A0F400).
        log("\n== C: func writing scene matrices into CB. Look for first 0xC0 byte write ==", fh)
        # find fns that write an 0xC0-byte struct to a buffer returned from CB_Map_A
        cbma_ea = ib() + 0x21A0680
        callers = set()
        for x in idautils.XrefsTo(cbma_ea, 0):
            fn = ida_funcs.get_func(x.frm)
            if fn: callers.add(fn.start_ea)
        log(f"  CB_Map_A callers: {len(callers)}", fh)
        # Decompile up to 8, looking for one named like DFPrePassSetupTechnique with viewProj writes
        for fea in list(callers)[:8]:
            decomp(fea, fh, f"CB_Map_A caller", 2500)

        log("\n== DONE ==", fh)
main()
