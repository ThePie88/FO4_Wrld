"""
decomp_stradaB_texture2.py

Focused follow-up: decomp sub_14217A910 (texture loader), its siblings in the
0x2179xxx cluster, plus the BSShaderTextureSet vtable & ITextureDB vtable.

Prior finding: sub_14217A910(path, flag, flag) is used in sub_1406B60C0 and
sub_1406C1C90 with "Textures\\Sky\\MoonShadow.dds" — BUT in both call sites
the return value is IGNORED. So it might be a *preload/release* hint, not
a loader. Let me confirm by decomping it deeply.

Also: decomp sub_14167BF00 (string-load helper that takes a path string and
stores it somewhere) to see if that's a simpler string copy.

Targets:
  sub_14217A910  @ 0x217A910   "real" texture helper
  sub_14217AC60  @ 0x217AC60   (same group, touches default tex)
  sub_14217B3C0  @ 0x217B3C0   (same group)
  sub_142162990  @ 0x2162990   (reads qword_1434391A0, near 9D0)
  sub_1421629D0  @ 0x21629D0   (another qword_1434391A0 reader)
  sub_1421674E0  @ 0x21674E0   (another one)
  sub_14216F1D0  @ 0x216F1D0   (another BSEffectShader variant?)

  + vtable dumps:
    BSShaderTextureSet vtable @ RVA 0x24A7030
    BGSTextureSet vtable      @ RVA 0x24A71A0
    QueuedHandles@BSTextureDB @ RVA 0x2694590
    ITextureDB                @ RVA 0x2694458
    NiTextureDBForwarded      @ RVA 0x2694668

  + look for xrefs to ITextureDB vtable to find the singleton
  + look for xrefs to NiTextureDBForwarded vtable to find its ctor,
    decompile that ctor to find the path-based API.
"""
import ida_auto
import ida_funcs
import ida_nalt
import ida_hexrays
import ida_pro
import ida_bytes
import ida_segment
import ida_name
import idautils
import idc

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\stradaB_texture_raw2.txt"


def log(fh, msg):
    print(msg)
    fh.write(msg + "\n")
    fh.flush()


def rva(ea):
    return ea - ida_nalt.get_imagebase()


def decomp_full(ea, fh, label="", max_lines=400):
    log(fh, f"\n-- decomp {label} @ 0x{ea:X} (RVA 0x{rva(ea):X}) --")
    fn = ida_funcs.get_func(ea)
    if not fn:
        log(fh, "  [!] NO FUNC")
        return None
    log(fh, f"  size=0x{fn.end_ea - fn.start_ea:X}")
    try:
        cf = ida_hexrays.decompile(ea)
        if cf:
            t = str(cf)
            lines = t.split("\n")
            if len(lines) > max_lines:
                log(fh, "\n".join(lines[:max_lines]))
                log(fh, f"  ... (truncated, total={len(lines)} lines)")
            else:
                log(fh, t)
            return t
    except Exception as e:
        log(fh, f"  [!] decompile failed: {e}")
    return None


def xrefs_to_addr(fh, ea, label, limit=40):
    log(fh, f"\n==== xrefs to {label} @ 0x{ea:X} (RVA 0x{rva(ea):X}) ====")
    results = []
    for xref in idautils.XrefsTo(ea, 0):
        fn = ida_funcs.get_func(xref.frm)
        fname = ida_funcs.get_func_name(xref.frm) or "?"
        fn_start = fn.start_ea if fn else 0
        fn_rva = rva(fn_start) if fn_start else 0
        log(fh, f"  xref from 0x{xref.frm:X} in {fname} (func @ 0x{fn_start:X} RVA 0x{fn_rva:X}) type={xref.type}")
        results.append((xref.frm, fn_start))
        if len(results) >= limit:
            break
    return results


def dump_vtable(fh, vt_ea, label, entries=60):
    log(fh, f"\n-- vtable dump {label} @ 0x{vt_ea:X} (RVA 0x{rva(vt_ea):X}) --")
    for i in range(entries):
        q = ida_bytes.get_qword(vt_ea + 8 * i)
        if q == 0 or not ida_funcs.get_func(q):
            log(fh, f"  [{i:3d}] 0x{q:X}  (not-a-func)")
            if q == 0:
                break
            continue
        fname = ida_funcs.get_func_name(q) or "?"
        log(fh, f"  [{i:3d}] 0x{q:X}  RVA=0x{rva(q):X}  {fname}")


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    log(fh, "==== Strada B — Texture API dossier pass 2 ====")
    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()
    IMG = ida_nalt.get_imagebase()
    log(fh, f"image base = 0x{IMG:X}")

    # === PART A — deep decomp the 0x2179xxx cluster ===
    log(fh, "\n=========================================")
    log(fh, "  PART A — sub_14217A910 and siblings")
    log(fh, "=========================================")
    FUNCS = [
        (0x14217A910, "sub_14217A910 (suspected texture preload/stream API)"),
        (0x14217AC60, "sub_14217AC60 (same cluster)"),
        (0x14217B3C0, "sub_14217B3C0 (same cluster)"),
        (0x1421792E0, "sub_1421792E0 (loads TestMeatcapGore01_{d,n,h}.dds)"),
        (0x142179140, "sub_142179140 (SSN writer — seen before)"),
        (0x142179350, "sub_142179350 (poss. related)"),
        (0x14216F1D0, "sub_14216F1D0 (reads default tex, near effect ctor)"),
        (0x1421629D0, "sub_1421629D0 (reads default tex)"),
        (0x142162990, "sub_142162990 (the slot at shader+88 ctor?)"),
        (0x1421674E0, "sub_1421674E0 (reads default tex)"),
        (0x142163B00, "sub_142163B00 (reads default tex)"),
        (0x1421F9F00, "sub_1421F9F00 (called by effect init — writes a1[11] result)"),
        (0x1421FA3B0, "sub_1421FA3B0 (called by effect init — dtor of the slot)"),
        (0x14167BF00, "sub_14167BF00 (path-string internal)"),
        (0x14167BDC0, "sub_14167BDC0 (BSFixedString::Create)"),
        (0x14167BEF0, "sub_14167BEF0 (BSFixedString::Release)"),
    ]
    for ea, lbl in FUNCS:
        decomp_full(ea, fh, lbl, max_lines=300)

    # === PART B — vtable dumps ===
    log(fh, "\n=========================================")
    log(fh, "  PART B — key class vtables")
    log(fh, "=========================================")
    VTS = [
        (IMG + 0x24A7030, "BSShaderTextureSet vtable"),
        (IMG + 0x24A71A0, "BGSTextureSet vtable"),
        (IMG + 0x2694458, "ITextureDB vtable"),
        (IMG + 0x2694590, "QueuedHandles@BSTextureDB vtable"),
        (IMG + 0x2694668, "NiTextureDBForwarded vtable"),
        (IMG + 0x2694710, "BSQueuedResourceCollection<EntryDB<BSMaterialDB>,1>"),
        (IMG + 0x2465758, "BSQueuedResourceCollection<EntryDB<BSModelDB>>"),
    ]
    for vt, lbl in VTS:
        dump_vtable(fh, vt, lbl, entries=32)

    # === PART C — xrefs to ITextureDB vtable (should reveal the singleton) ===
    log(fh, "\n=========================================")
    log(fh, "  PART C — ITextureDB vt xrefs + NiTextureDBForwarded xrefs")
    log(fh, "=========================================")
    xrefs_to_addr(fh, IMG + 0x2694458, "ITextureDB vtable", limit=30)
    xrefs_to_addr(fh, IMG + 0x2694668, "NiTextureDBForwarded vtable", limit=30)
    xrefs_to_addr(fh, IMG + 0x26944B8, "BSQueuedResourceCollection<EntryDB<BSTextureDB>,1>", limit=20)
    xrefs_to_addr(fh, IMG + 0x2694590, "QueuedHandles@BSTextureDB", limit=30)

    # === PART D — xrefs to BSShaderTextureSet vtable ===
    log(fh, "\n=========================================")
    log(fh, "  PART D — BSShaderTextureSet vt xrefs")
    log(fh, "=========================================")
    xs = xrefs_to_addr(fh, IMG + 0x24A7030, "BSShaderTextureSet vtable", limit=20)
    seen = set()
    for (_, fn_ea) in xs[:10]:
        if fn_ea and fn_ea not in seen:
            seen.add(fn_ea)
            decomp_full(fn_ea, fh, f"BSShaderTextureSet-xref-func", max_lines=200)

    # === PART E — qword_1431E5320 (global texture manager?) ===
    # From sub_142161B10: result = sub_1421F9F00(qword_1431E5320, a2, v8, v9)
    # — that looks like a global singleton being passed to a texture-related fn.
    log(fh, "\n=========================================")
    log(fh, "  PART E — qword_1431E5320 (candidate texture manager singleton)")
    log(fh, "=========================================")
    MAN = IMG + 0x31E5320
    xrefs_to_addr(fh, MAN, "qword_1431E5320", limit=40)
    # Decomp the first function that reads it (excluding the ones we already have).
    # Also decomp sub_1421F9F00 & sub_1421FA3B0 (the ones that consume the singleton).
    decomp_full(IMG + 0x21F9F00, fh, "sub_1421F9F00 (consumes singleton)", max_lines=300)
    decomp_full(IMG + 0x21FA3B0, fh, "sub_1421FA3B0 (consumes singleton)", max_lines=300)

    # === PART F — sub_14216F1D0 (likely the real "BSEffectShader with texture path" ctor) ===
    log(fh, "\n=========================================")
    log(fh, "  PART F — more BSEffectShader ctor variants")
    log(fh, "=========================================")
    for ea, lbl in [
        (0x14216F1D0, "sub_14216F1D0 (2nd BSEffect variant)"),
        (0x142163B00, "sub_142163B00 (shader helper)"),
        (0x142164410, "sub_142164410 (shader helper)"),
        (0x1421718E0, "sub_1421718E0 (dtor variant of BSLSP?)"),
    ]:
        decomp_full(IMG + (ea - 0x140000000), fh, lbl, max_lines=300)

    # === PART G — the BSShaderTextureSet ctor ===
    # Based on prior xref list, one function will be the ctor (stores the vtable
    # pointer). Look for that.
    log(fh, "\n=========================================")
    log(fh, "  PART G — BSShaderTextureSet layout probe")
    log(fh, "=========================================")
    # Check the vtable entries, usually [0]=rtti, [1]=dtor, etc.
    # After we have them, the ctor of BSShaderTextureSet must appear via xref
    # to the vtable address.
    # That list is already shown in PART D.

    # === PART H — Dump strings for "new", "one_wan" etc (the Moon texture code) ===
    # The Moon ctor (sub_1406B5950) concatenates paths like
    # "Data/Textures/Sky/%s_%s.dds" and stores the result into a struct — no
    # immediate texture load. That means the path is stored and the texture is
    # loaded LAZILY by whoever reads the struct. So the loader is somewhere
    # deeper. Decomp sub_1401F81D0 (the string-formatter into a member).
    log(fh, "\n=========================================")
    log(fh, "  PART H — path-string storage helpers")
    log(fh, "=========================================")
    for ea, lbl in [
        (0x1401F81D0, "sub_1401F81D0 (path-format-into-struct)"),
        (0x1401E61D0, "sub_1401E61D0 (path-assign-into-struct)"),
        (0x140206600, "sub_140206600 (path-concat)"),
        (0x14217A910, "sub_14217A910 (deep re-decomp for final verdict)"),
    ]:
        decomp_full(IMG + (ea - 0x140000000), fh, lbl, max_lines=300)

    # === PART I — Cross-ref sub_14217A910 again, see all call sites ===
    log(fh, "\n=========================================")
    log(fh, "  PART I — sub_14217A910 all xrefs")
    log(fh, "=========================================")
    xrefs_to_addr(fh, IMG + 0x217A910, "sub_14217A910", limit=60)

    # === PART J — The FX/test Meatcap path consumer decomp ===
    # It's a big function, but the key is the loader call near TestMeatcapGore paths.
    # Let's also look at sub_14217A910 through the *callee chain* to find the
    # real BA2-stream opener.
    log(fh, "\n=========================================")
    log(fh, "  PART J — sub_14217A910 callees (first 3 layers)")
    log(fh, "=========================================")
    # Read ALL call instructions inside sub_14217A910 and resolve targets.
    fn = ida_funcs.get_func(IMG + 0x217A910)
    if fn:
        targets = set()
        cur = fn.start_ea
        while cur < fn.end_ea:
            dis = (idc.generate_disasm_line(cur, 0) or "").strip()
            if dis.lower().startswith("call "):
                # Check the ref target
                for xref in idautils.XrefsFrom(cur, 0):
                    if xref.type in (ida_bytes.fl_CN, ida_bytes.fl_CF) or xref.type == 16 or xref.type == 17:
                        targets.add(xref.to)
            cur = idc.next_head(cur, fn.end_ea)
            if cur == idc.BADADDR:
                break
        log(fh, f"  {len(targets)} call targets in sub_14217A910")
        for t in sorted(targets):
            fname = ida_funcs.get_func_name(t) or "?"
            log(fh, f"  call -> 0x{t:X} RVA=0x{rva(t):X} {fname}")

    log(fh, "\n==== END pass 2 ====")
    fh.close()
    ida_pro.qexit(0)


main()
