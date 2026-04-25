"""find_bsgraphics_state5.py — decompile promising candidates"""
import ida_hexrays, ida_funcs, ida_nalt, ida_name, ida_bytes, ida_segment, idautils, idc, ida_ua
OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\bsgraphics_state_report5.txt"
def ib(): return ida_nalt.get_imagebase()
def rva(ea): return ea - ib()
def log(m, fh): print(m); fh.write(m+"\n"); fh.flush()

def decomp(fea, fh, label, maxc=7000):
    fn = ida_funcs.get_func(fea)
    if not fn: log(f"  no fn at 0x{fea:X}", fh); return
    try:
        cf = ida_hexrays.decompile(fn.start_ea)
        if not cf: log(f"  decomp=None {label}", fh); return
        txt = str(cf)
        log(f"\n======== {label} @ RVA 0x{rva(fn.start_ea):X} ========", fh)
        log(txt[:maxc] + ("\n...[truncated]" if len(txt) > maxc else ""), fh)
    except Exception as e:
        log(f"  err: {e}", fh)

def callers(fea, maxn=20):
    res = set()
    for x in idautils.XrefsTo(fea, 0):
        fn = ida_funcs.get_func(x.frm)
        if fn: res.add(fn.start_ea)
        if len(res) >= maxn: break
    return list(res)

def data_xrefs(gea, maxn=30):
    res = []
    for x in idautils.XrefsTo(gea, 0):
        fn = ida_funcs.get_func(x.frm)
        res.append((x.frm, fn.start_ea if fn else None))
        if len(res) >= maxn: break
    return res

def main():
    with open(OUT, 'w', encoding='utf8') as fh:
        log(f"image base 0x{ib():X}", fh)
        # Top candidates from v4
        cands = [
            (0x265C70, "NiCam120->glb+D0 via 0x30dc000"),
            (0xD61AB0, "NiCam120->glb+D0 via 0x30dbd58/0x32d2228"),
            (0xD61EF0, "NiCam120->glb+D0 via 0x30dbd58/0x3e5c658/0x32d2228"),
            (0x19E1D30, "writer+C0-110 via 0x2f32158"),
            (0x1336B10, "NiCam120->glb+D0 via 0x2f32158"),
            (0x13AE5B0, "NiCam120->glb+D0 via 0x333f5c8/0x3318ac8"),
            (0x1406310, "NiCam120->glb+D0 via 0x3318ac8"),
        ]
        for (rva_v, lbl) in cands:
            decomp(ib()+rva_v, fh, lbl, maxc=5000)

        # Data xrefs for the promising globals (all functions that READ/WRITE these pointers)
        log("\n== DATA XREFS ==", fh)
        for g_rva in (0x32d2228, 0x30dbd58, 0x30dc000, 0x2f32158, 0x3318ac8, 0x3e5c658, 0x333f5c8):
            log(f"\n-- global RVA 0x{g_rva:X} --", fh)
            refs = data_xrefs(ib()+g_rva)
            log(f"  xref count: {len(refs)}", fh)
            fnset = set()
            for (site, fn) in refs:
                if fn: fnset.add(fn)
            for f in list(fnset)[:20]:
                log(f"    fn RVA 0x{rva(f):X}", fh)

        # If 0x32d2228 is related to PlayerCharacter singleton (0x32D2260 is player), it may not be BSGraphics.
        # But 0x30dbd58 / 0x30dc000 / 0x2f32158 are new — likely renderer globals.
        # Decompile a short function that reads 0x30dbd58 ONLY (singleton accessor ~GetSingleton pattern)
        log("\n== B: find short accessor fn for each global ==", fh)
        for g_rva in (0x30dbd58, 0x30dc000, 0x2f32158, 0x3318ac8):
            gea = ib() + g_rva
            # find callers where fn size is tiny (20-60 bytes) — that's a GetSingleton
            fns_to_try = set()
            for x in idautils.XrefsTo(gea, 0):
                fn = ida_funcs.get_func(x.frm)
                if fn and (fn.end_ea - fn.start_ea) <= 0x60:
                    fns_to_try.add(fn.start_ea)
            for fea in list(fns_to_try)[:3]:
                decomp(fea, fh, f"tiny-reader of 0x{g_rva:X}", maxc=600)

        log("\n== DONE ==", fh)
main()
