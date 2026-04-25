"""find_bsgraphics_state.py

Goal: locate BSGraphics::State and BSGraphics::Renderer singleton globals in
Fallout4.exe 1.11.191. CommonLibF4 documents:
  State::GetSingleton()         -> REL::ID(600795)
  Renderer::RendererData::GetSingleton() -> REL::ID(1235449)

No AddressLibrary .bin available, so we anchor on:
  - string 'D3D11CreateDeviceAndSwapChain'  (imports the func; caller is Renderer::Init)
  - string 'CreateDXGIFactory'
  - the 26 BSShaderAccumulator vtable slots 0..25 (RVA 0x239490..0x2395F0) — the
    Set* mutators that take camera data -> caller writes into State singleton.
  - decompile candidates and find 'mov qword [rip+G], rax' / 'lea rcx, [rip+G]' near
    movaps writes to +0xD0, +0x210, +0x160+0xD0 (=0x230).

Output re/bsgraphics_state_report.txt

What to look for in the decomps:
  1. A function that writes 4 __m128 values at +0xD0..+0x100 of a pointer
     (viewProjMat). That pointer is typically State+0x160 (cameraState offset).
  2. A function that reads a singleton via `lea rcx, [rip+STATE]` where STATE
     is a .data slot storing the State* pointer.
"""
import ida_auto, ida_bytes, ida_funcs, ida_hexrays, ida_nalt, ida_name
import ida_segment, ida_ua, ida_search, ida_xref
import idautils, idc

OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\bsgraphics_state_report.txt"

def image_base():
    return ida_nalt.get_imagebase()
def ea2rva(ea):
    return ea - image_base()
def rva2ea(rva):
    return image_base() + rva

def log(msg, fh):
    print(msg)
    fh.write(msg + "\n"); fh.flush()

def find_string(s):
    # walk string table
    hits = []
    for sea in idautils.Strings():
        try:
            if str(sea) == s:
                hits.append(sea.ea)
        except: pass
    return hits

def callers_of_ea(ea, max_callers=20):
    res = []
    for xref in idautils.XrefsTo(ea, 0):
        fn = ida_funcs.get_func(xref.frm)
        if fn:
            res.append(fn.start_ea)
        if len(res) >= max_callers:
            break
    return list(set(res))

def decomp_find_writes(fea, offsets_of_interest):
    """Look in pseudocode text for writes to any of offsets_of_interest."""
    fn = ida_funcs.get_func(fea)
    if not fn: return None
    try:
        cf = ida_hexrays.decompile(fn.start_ea)
        if cf is None: return None
        txt = str(cf)
    except Exception as e:
        return f"<decomp failed: {e}>"
    hits = []
    for off in offsets_of_interest:
        marks = [f"+ {off}", f"+{off}", f"0x{off:X}", f"0x{off:x}"]
        for m in marks:
            if m in txt:
                hits.append((off, m))
                break
    return (txt, hits)

def scan_for_global_store(fea, fh):
    """Scan first ~0x200 bytes of fn for `mov [rip+disp], rax` candidate singleton stores."""
    fn = ida_funcs.get_func(fea)
    if not fn: return []
    stores = []
    ea = fn.start_ea
    end = min(fn.start_ea + 0x1000, fn.end_ea)
    while ea < end:
        ins = ida_ua.insn_t()
        if not ida_ua.decode_insn(ins, ea):
            ea += 1; continue
        mnem = ins.get_canon_mnem()
        if mnem == 'mov' and ins.ops[0].type == 4 and ins.ops[1].type == 1:  # mem, reg
            # ins.ops[0].addr for RIP-relative mem
            tgt = ins.ops[0].addr
            if tgt and ida_segment.getseg(tgt) and ida_segment.getseg(tgt).type in (ida_segment.SEG_DATA, ida_segment.SEG_BSS):
                stores.append((ea, tgt))
        ea += ins.size
    return stores

def main():
    with open(OUT, "w", encoding="utf8") as fh:
        log(f"image base: 0x{image_base():X}", fh)

        # ---------- PART A: D3D11CreateDeviceAndSwapChain anchor ----------
        log("\n== PART A: D3D11 device creator callers ==", fh)
        hits = find_string("D3D11CreateDeviceAndSwapChain")
        log(f"  string hits: {[hex(h) for h in hits]}", fh)
        d3d_callers = []
        for s_ea in hits:
            for x in idautils.XrefsTo(s_ea, 0):
                fn = ida_funcs.get_func(x.frm)
                if fn:
                    d3d_callers.append(fn.start_ea)
        d3d_callers = list(set(d3d_callers))
        log(f"  unique callers: {[hex(ea2rva(c)) for c in d3d_callers]}", fh)

        # ---------- PART B: Decompile each caller, hunt for writes to +0x20..+0x200 globals ----------
        for fea in d3d_callers[:5]:
            log(f"\n--- D3D init fn @ RVA 0x{ea2rva(fea):X} ---", fh)
            try:
                cf = ida_hexrays.decompile(fea)
                if cf:
                    txt = str(cf)
                    log(txt[:9000], fh)
                    if len(txt) > 9000:
                        log(f"  ... ({len(txt)} chars total)", fh)
            except Exception as e:
                log(f"  decomp err: {e}", fh)
            stores = scan_for_global_store(fea, fh)
            log(f"  candidate global stores in fn:", fh)
            for (ea, tgt) in stores[:30]:
                log(f"    @0x{ea2rva(ea):X} -> .data 0x{ea2rva(tgt):X}", fh)

        # ---------- PART C: BSShaderAccumulator::Set* — look for singleton accessor ----------
        log("\n== PART C: BSShaderAccumulator vtbl-24/25 SetCamera-like ==", fh)
        # From prior report, vtable 0x290A6B0, slots 22-25 are small <0x20 byte fns at 0x239490..0x2394C0
        # Likely: one of them sets cameraState on BSGraphics::State.
        for slot_rva in (0x239490, 0x2394A0, 0x2394B0, 0x2394C0, 0x2394D0, 0x239560, 0x239570):
            fea = rva2ea(slot_rva)
            log(f"\n-- slot RVA 0x{slot_rva:X} --", fh)
            try:
                cf = ida_hexrays.decompile(fea)
                if cf:
                    log(str(cf)[:1500], fh)
            except Exception as e:
                log(f"  decomp err: {e}", fh)

        # ---------- PART D: direct scan — find any function that writes movaps to +0xD0,+0xE0,+0xF0,+0x100 sequentially ----------
        log("\n== PART D: pattern scan for viewProjMat writer ==", fh)
        # Pattern: movaps xmm?, xmm?; movaps [r?+D0h], xmm?; (+E0, +F0, +100)
        # Hard to scan exhaustively. Instead, search for immediate 0xD0 + 0xE0 + 0xF0 + 0x100 in same func,
        # iterating all functions with size 0x80..0x400 that reference a global pointer.
        text_seg = ida_segment.get_segm_by_name('.text')
        if not text_seg:
            log("  no .text seg?", fh); return
        count = 0
        candidates = []
        for fnea in idautils.Functions(text_seg.start_ea, text_seg.end_ea):
            fn = ida_funcs.get_func(fnea)
            if not fn: continue
            size = fn.end_ea - fn.start_ea
            if size < 0x60 or size > 0x600: continue
            # scan instructions for displacement values 0xD0,0xE0,0xF0,0x100 in memory operands
            seen = set()
            ea = fn.start_ea
            while ea < fn.end_ea:
                ins = ida_ua.insn_t()
                if not ida_ua.decode_insn(ins, ea):
                    ea += 1; continue
                if ins.get_canon_mnem() in ('movaps','movups','movdqu','movdqa'):
                    for op in ins.ops:
                        if op.type == 4:  # memory w/ displacement
                            d = op.addr
                            # displacements are stored differently for reg+disp - use op.addr? use op.value?
                            pass
                        if op.type == 3:  # [reg+disp]
                            # disp in op.addr
                            d = op.addr
                            if d in (0xD0, 0xE0, 0xF0, 0x100):
                                seen.add(d)
                ea += ins.size
            if seen == {0xD0, 0xE0, 0xF0, 0x100}:
                candidates.append(fnea)
                if len(candidates) > 40: break
        log(f"  viewProjMat writer candidates: {[hex(ea2rva(c)) for c in candidates]}", fh)

        log("\n== DONE ==", fh)

main()
