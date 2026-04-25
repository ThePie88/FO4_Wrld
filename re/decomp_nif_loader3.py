"""
decomp_nif_loader3.py — nail down the public API.

Pass 2 confirmed: sub_1417B3480 is a generic "parse-NIF-stream -> build
BSFadeNode" function that:
  - takes (a1, a2, a3, a4, a5) where a1/a2 look like path/stream args,
    a3 is an option struct, a4 is BYREF output NiAVObject**.
  - reads &qword_14355EB60 (the BSFixedString "fallback path" slot).
  - allocates 0x1C0 (BSFadeNode) or 0x140 (NiNode) via sub_1416579C0.
  - wraps via sub_142174E60 (BSFadeNode::AssignSource).
  - calls BSStream vtable to parse the NIF file.

Callers of interest from pass 2:
  - sub_14026E1C0 (possibly load-from-file wrapper)
  - sub_14033EC90 / sub_14033F200 / sub_14033F870
  - sub_140482C50 / sub_14048D280 / sub_14048E4C0 / sub_1404901C0

Let's decompile those + the direct wrappers to find:
  (a) a public, simple entry (const char* path, NiAVObject** out).
  (b) whether it's blocking, and what pre-conditions exist.
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

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\stradaB_nif_loader_raw3.txt"


def log(fh, msg):
    print(msg)
    fh.write(msg + "\n")
    fh.flush()


def rva(ea):
    return ea - ida_nalt.get_imagebase()


def decomp_full(ea, fh, label="", max_lines=500):
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


def xrefs_to_addr(fh, ea, label, limit=60):
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


def list_names_matching(patterns, fh, label="", limit=200):
    log(fh, f"\n==== Names matching {patterns} ({label}) ====")
    hits = []
    for (ea, n) in idautils.Names():
        ln = n.lower()
        if any(p.lower() in ln for p in patterns):
            hits.append((ea, n))
    for (ea, n) in hits[:limit]:
        log(fh, f"  0x{ea:X}  RVA=0x{rva(ea):X}  {n}")
    return hits


def find_string_contains(frag):
    hits = []
    for s in idautils.Strings():
        try:
            v = str(s)
        except:
            continue
        if frag in v:
            hits.append((s.ea, v))
    return hits


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    log(fh, "==== NIF loader — deep-dive pass 3 (public entry) ====")
    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()
    IMG = ida_nalt.get_imagebase()
    log(fh, f"image base = 0x{IMG:X}")

    callers = [
        (0x14026E1C0, "caller_sub_14026E1C0"),
        (0x14033EC90, "caller_sub_14033EC90"),
        (0x14033F200, "caller_sub_14033F200"),
        (0x14033F870, "caller_sub_14033F870"),
        (0x140482C50, "caller_sub_140482C50"),
        (0x14048D280, "caller_sub_14048D280"),
        (0x14048E4C0, "caller_sub_14048E4C0"),
        (0x1404901C0, "caller_sub_1404901C0"),
    ]
    for ea, lbl in callers:
        decomp_full(ea, fh, lbl, max_lines=250)

    # sub_1417B4430 writes QueuedHandles@BSModelDB vtable — probably ctor.
    # sub_1417B39D0 writes BSModelProcessor vtable — probably ctor.
    # Between them: the BSModelDB singleton init.
    log(fh, "\n\n=========================================")
    log(fh, "  BSModelDB ctors (vtable writers)")
    log(fh, "=========================================")
    decomp_full(0x1417B4430, fh, "sub_1417B4430_QueuedHandles_ctor", max_lines=150)
    decomp_full(0x1417B39D0, fh, "sub_1417B39D0_BSModelProcessor_ctor", max_lines=150)

    # sub_1417B39F0 is called by sub_1402FC0E0 (which also calls AssignSource)
    decomp_full(0x1417B39F0, fh, "sub_1417B39F0_somewhere", max_lines=150)

    # sub_1417B40F0 is called in sub_140458740 — probably "file exists?"
    decomp_full(0x1417B40F0, fh, "sub_1417B40F0_file_exists_check", max_lines=150)

    # sub_14040CF10 — allocator for 448 bytes in sub_140458740 path.
    decomp_full(0x14040CF10, fh, "sub_14040CF10_alloc_448", max_lines=150)

    # sub_1402C9BA0 — called a lot with (a4, path?) pattern.
    decomp_full(0x1402C9BA0, fh, "sub_1402C9BA0", max_lines=150)

    # sub_1416A7EF0 — first thing called in sub_1417B3A10
    decomp_full(0x1416A7EF0, fh, "sub_1416A7EF0_in_load_kick", max_lines=150)
    # sub_1416A8130 — last call in sub_1417B3A10; carries the actual load
    decomp_full(0x1416A8130, fh, "sub_1416A8130_final_load_call", max_lines=200)

    # IEntryDB "Load by path" method via vtable[?] - peek at BSResource IEntryDB
    # vtable. The func at 0x1416A5C20 (writes IEntryDB vtable) is the ctor.
    log(fh, "\n\n=========================================")
    log(fh, "  IEntryDB vtable [search for Demand/QueueRequest]")
    log(fh, "=========================================")
    decomp_full(0x1416A5C20, fh, "sub_1416A5C20_IEntryDB_ctor", max_lines=150)

    # The IEntryDB::vtable is at 0x14267B860. Dump the pointer contents
    # (first 8 slots, 8 bytes each)
    log(fh, "\n-- IEntryDB vtable dump (first 32 slots) --")
    for i in range(32):
        ea = 0x14267B860 + 8 * i
        v = idc.get_qword(ea)
        n = ida_funcs.get_func_name(v) or "?"
        log(fh, f"  vt[{i:2d}] @ 0x{ea:X}  -> 0x{v:X}  (RVA 0x{v - IMG:X})  {n}")

    # BSResourceNiBinaryStream vtable 0x14267C320 (from pass 1)
    log(fh, "\n\n=========================================")
    log(fh, "  BSResourceNiBinaryStream vtable dump")
    log(fh, "=========================================")
    for i in range(16):
        ea = 0x14267C320 + 8 * i
        v = idc.get_qword(ea)
        log(fh, f"  vt[{i:2d}] @ 0x{ea:X}  -> 0x{v:X}  (RVA 0x{v - IMG:X})")

    # NiStream vtable 0x14267F000
    log(fh, "\n\n=========================================")
    log(fh, "  NiStream vtable dump")
    log(fh, "=========================================")
    for i in range(16):
        ea = 0x14267F000 + 8 * i
        v = idc.get_qword(ea)
        log(fh, f"  vt[{i:2d}] @ 0x{ea:X}  -> 0x{v:X}  (RVA 0x{v - IMG:X})")

    # === The biggest caller: sub_140458740 — very long (0x114F) —
    # this looks like TESObjectREFR::Load3D or similar. Decompile more.
    log(fh, "\n\n=========================================")
    log(fh, "  TRY: sub_140458740 callers (is this Load3D?)")
    log(fh, "=========================================")
    xrefs_to_addr(fh, 0x140458740, "sub_140458740_big_3d_loader", limit=30)

    # === sub_14026E1C0 — likely a simple "load model by path" public entry
    # because it has few args and calls sub_1417B3480 directly.
    # Let's find who calls it.
    log(fh, "\n\n=========================================")
    log(fh, "  xrefs to sub_14026E1C0")
    log(fh, "=========================================")
    xrefs_to_addr(fh, 0x14026E1C0, "sub_14026E1C0", limit=30)

    # === sub_14033EC90
    log(fh, "\n\n=========================================")
    log(fh, "  xrefs to sub_14033EC90")
    log(fh, "=========================================")
    xrefs_to_addr(fh, 0x14033EC90, "sub_14033EC90", limit=30)

    # Identify TESObjectREFR::Load3D by searching the vtable region for a
    # method that calls sub_140458740 or sub_1417B3480
    # The TESObjectREFR TD @ 0x142F90680 in pass 1; the COL chain leads to
    # vtable. We search for xrefs from the Load3D-style bridge.

    # === Very often these loaders take:
    #   a1 = TESForm* / TESObjectREFR*
    #   a2 = Actor* or parent scene
    #   a3 = TESModel* (not path)
    #   a4 = NiAVObject** out
    #   a5 = some "preload" bool
    # Check sub_14033EC90 signature in detail.
    decomp_full(0x14033EC90, fh, "sub_14033EC90_full", max_lines=350)

    # === sub_1402C9BA0 signature: "TES model swap"? decomp it
    decomp_full(0x1402C9BA0, fh, "sub_1402C9BA0_full", max_lines=300)

    # === sub_14026E1C0 signature:
    decomp_full(0x14026E1C0, fh, "sub_14026E1C0_full", max_lines=300)

    # Check if there's a named BSFadeNode subclass BSLeafAnimNode
    log(fh, "\n\n=========================================")
    log(fh, "  BSLeafAnimNode / BSDismemberSkinInstance related")
    log(fh, "=========================================")
    list_names_matching(["BSLeafAnim", "BSDismember", "BSLODTriShape",
                         "BSSkyShape", "BSWaterShape"],
                        fh, label="nif-node-subclasses", limit=40)

    # === Important: find the function that wraps the path -> NiNode output.
    # Look at sub_1417B3480 parameters more carefully via disasm of callers.
    log(fh, "\n\n=========================================")
    log(fh, "  sub_1417B3480 raw disasm (first 50 instr)")
    log(fh, "=========================================")
    cur = 0x1417B3480
    fn = ida_funcs.get_func(cur)
    if fn:
        end = min(fn.end_ea, cur + 512)
        i = 0
        while cur < end and i < 50:
            dis = idc.generate_disasm_line(cur, 0) or "?"
            log(fh, f"  0x{cur:X}  {dis}")
            cur = idc.next_head(cur, end)
            i += 1

    log(fh, "\n==== END deep-dive 3 ====")
    fh.close()
    ida_pro.qexit(0)


main()
