"""
decomp_nif_loader2.py — deep-dive on the candidate NIF loader API.

From pass 1 we identified:
 - sub_1401880B0: writes "Meshes\\Marker_Error.NIF" to qword_14355EB60 via
   BSFixedString, then calls sub_1422B70BC(sub_1424198C0).
 - sub_1406E6060: builds "%s/Morphs/%s.nif" and calls sub_1406E7130.
 - sub_1402FBDF0: TESModelDB::TESProcessor alloc + store path + call sub_1417B3A10.
 - sub_1402DFA40: huge (0x3528) func loading many markers.
 - sub_1416DEAF0: checks "Gamebryo File Format, Version 20.2.0.7" magic (NiStream::Load)

Decompile these + their chain, + their callers to find the ultimate public API.
Also find BSModelDB singleton globals and its vtable.
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

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\stradaB_nif_loader_raw2.txt"


def log(fh, msg):
    print(msg)
    fh.write(msg + "\n")
    fh.flush()


def rva(ea):
    return ea - ida_nalt.get_imagebase()


def decomp_full(ea, fh, label="", max_lines=600):
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


def find_string_equals(exact):
    for s in idautils.Strings():
        try:
            v = str(s)
        except:
            continue
        if v == exact:
            return s.ea
    return 0


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


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    log(fh, "==== NIF loader — deep-dive pass 2 ====")
    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()
    IMG = ida_nalt.get_imagebase()
    log(fh, f"image base = 0x{IMG:X}")

    # --- Targets from pass 1 ---
    # Public-ish NIF loader candidates:
    # sub_1422B70BC(callbackFn) — invoked after BSFixedString path is in qword_14355EB60.
    # sub_1417B3A10 — terminal load kick (used by sub_1402FBDF0).
    # sub_1417B3480 — calls AssignSource (xref from step 6).
    # sub_142177E60 — calls AssignSource.
    # sub_1406E7130 — called by sub_1406E6060 with the constructed "%s/Morphs/%s.nif" path.
    # sub_1416DEAF0 — references "Gamebryo File Format" magic (NiStream entry).

    tgts = [
        (0x1422B70BC, "sub_1422B70BC_nif_entry_wrapper"),
        (0x1417B3A10, "sub_1417B3A10_load_kick"),
        (0x1417B3480, "sub_1417B3480_calls_AssignSource"),
        (0x142177E60, "sub_142177E60_calls_AssignSource"),
        (0x1406E7130, "sub_1406E7130_morph_loader"),
        (0x1416DEAF0, "sub_1416DEAF0_NiStream_magic_check"),
        (0x1401880B0, "sub_1401880B0_marker_err_entrance_full"),
        (0x1402FBDF0, "sub_1402FBDF0_tesmodeldb_alloc_use"),
        (0x142174E60, "sub_142174E60_BSFadeNode_AssignSource_again"),
        (0x1424198C0, "sub_1424198C0_callback_fn_for_marker_err"),
        # xref targets from AssignSource caller list
        (0x1402FC0E0, "sub_1402FC0E0_marker_err_usage"),
        (0x140458740, "sub_140458740_AssignSrc_call"),
    ]
    for ea, lbl in tgts:
        decomp_full(ea, fh, lbl, max_lines=400)

    # Now who calls sub_1422B70BC?
    log(fh, "\n\n=====================================")
    log(fh, " xrefs to sub_1422B70BC (potential public NIF-load API)")
    log(fh, "=====================================")
    xrefs_to_addr(fh, 0x1422B70BC, "sub_1422B70BC", limit=80)

    # Who calls sub_1417B3A10?
    log(fh, "\n\n=====================================")
    log(fh, " xrefs to sub_1417B3A10")
    log(fh, "=====================================")
    xrefs_to_addr(fh, 0x1417B3A10, "sub_1417B3A10", limit=80)

    # Who calls sub_1417B3480?
    log(fh, "\n\n=====================================")
    log(fh, " xrefs to sub_1417B3480")
    log(fh, "=====================================")
    xrefs_to_addr(fh, 0x1417B3480, "sub_1417B3480", limit=40)

    # Examine sub_1416DEAF0 depth and its callers
    log(fh, "\n\n=====================================")
    log(fh, " xrefs to sub_1416DEAF0 (NiStream)")
    log(fh, "=====================================")
    xrefs_to_addr(fh, 0x1416DEAF0, "sub_1416DEAF0", limit=40)

    # Find BSModelDB singleton globals by looking for the QueuedHandles vtable write
    log(fh, "\n\n=====================================")
    log(fh, " Search: BSModelDB QueuedHandles vtable xrefs")
    log(fh, "=====================================")
    # 0x142465830 = ??_7QueuedHandles@BSModelDB@@6B@ per pass1
    xrefs_to_addr(fh, 0x142465830, "QueuedHandles_BSModelDB_vtable", limit=30)

    # And BSModelProcessor vtable writes
    log(fh, "\n\n=====================================")
    log(fh, " Search: BSModelProcessor vtable xrefs")
    log(fh, "=====================================")
    xrefs_to_addr(fh, 0x14246D700, "BSModelProcessor_BSModelDB_vtable", limit=30)

    # TESQueuedHandles vtable (TES-flavored model DB) — used by TESModelDB path
    log(fh, "\n\n=====================================")
    log(fh, " Search: TESQueuedHandles vtable xrefs (TESModelDB path)")
    log(fh, "=====================================")
    xrefs_to_addr(fh, 0x142465E58, "TESQueuedHandles_TESModelDB_vtable", limit=30)

    # BSFadeNode vtable xrefs → ctor/alloc sites (the final wrapping step)
    log(fh, "\n\n=====================================")
    log(fh, " BSFadeNode vtable writes (identifies alloc+wrap sites)")
    log(fh, "=====================================")
    xrefs_to_addr(fh, 0x1428FA3E8, "BSFadeNode_vtable", limit=40)

    # === Callers of sub_1422B70BC — trace 3-4 levels up to find the public top-level API
    log(fh, "\n\n=====================================")
    log(fh, " Direct callers of sub_1422B70BC — decompile top 4")
    log(fh, "=====================================")
    callers = []
    for xref in idautils.XrefsTo(0x1422B70BC, 0):
        fn = ida_funcs.get_func(xref.frm)
        if fn:
            callers.append(fn.start_ea)
    seen = set()
    for c in callers[:6]:
        if c not in seen:
            seen.add(c)
            decomp_full(c, fh, f"caller-of-sub_1422B70BC", max_lines=250)

    # === Same for sub_1417B3A10 callers
    log(fh, "\n\n=====================================")
    log(fh, " Direct callers of sub_1417B3A10 — decompile top 6")
    log(fh, "=====================================")
    callers2 = []
    for xref in idautils.XrefsTo(0x1417B3A10, 0):
        fn = ida_funcs.get_func(xref.frm)
        if fn:
            callers2.append(fn.start_ea)
    seen2 = set()
    for c in callers2[:8]:
        if c not in seen2:
            seen2.add(c)
            decomp_full(c, fh, f"caller-of-sub_1417B3A10", max_lines=180)

    # === Find TESModel::SetModel (consumes a path and stashes it) and related calls
    log(fh, "\n\n=====================================")
    log(fh, " TESModel-related functions (by name prefix)")
    log(fh, "=====================================")
    list_names_matching(
        ["TESModel::", "BGSModelMaterialSwap::", "TESObjectREFR::Load3D",
         "TESObjectREFR::Reset3D", "TESObjectREFR::Set3D",
         "BGSLoadForm", "Actor::Load3D"],
        fh, label="TES_Model_names", limit=60,
    )

    # === search for "%s_1LayerTorso" / male body hint / CharacterAssets
    log(fh, "\n\n=====================================")
    log(fh, " CharacterAssets + MaleBody candidate paths")
    log(fh, "=====================================")
    for frag in ["CharacterAssets", "MaleBody", "FemaleBody",
                 "BaseHumanMale", "Actors\\Character"]:
        hits = find_string_contains(frag)
        log(fh, f"\n  frag='{frag}' => {len(hits)} string hits")
        for (sea, v) in hits[:25]:
            log(fh, f"    0x{sea:X}  RVA=0x{rva(sea):X}  '{v}'")

    # === Look for qword_14355EB60 — the BSFixedString slot written by sub_1401880B0
    log(fh, "\n\n=====================================")
    log(fh, " qword_14355EB60 (model-err BSFixedString slot) xrefs")
    log(fh, "=====================================")
    xrefs_to_addr(fh, 0x14355EB60, "qword_14355EB60", limit=25)

    # === Hunt: the actual BSResource::EntryDB<BSModelDB>::Demand signature
    # IEntryDB<BSResource> has a vtable; search names too
    log(fh, "\n\n=====================================")
    log(fh, " IEntryDB vtable + Demand-like members")
    log(fh, "=====================================")
    # IEntryDB vtable @ 0x14267B860 per pass1
    xrefs_to_addr(fh, 0x14267B860, "IEntryDB_BSResource_vtable", limit=25)

    # Very likely: the public loader is the method at some vtable slot of
    # the BSModelDB global singleton. Let's find the global that holds it.
    # In the texture-API case the singleton was at qword_1430DD7F8. Try
    # nearby globals in .data:
    # Pattern: a qword whose value is the EntryDB<BSModelDB> vtable + X.

    # === sub_1402DFA40 size=0x3528 is huge (MarkerX loader). Truncate heavily.
    # Skip (too big).

    # === Directly examine sub_1402C72C0 (our glob-mode "\*.NIF" scan) and
    # sub_141686C50 which it tail-calls — this is a directory-scan helper,
    # NOT a loader. Confirm and mark as irrelevant.
    log(fh, "\n\n=====================================")
    log(fh, " sub_141686C50 (called by glob helper)")
    log(fh, "=====================================")
    decomp_full(0x141686C50, fh, "sub_141686C50_glob_helper", max_lines=200)

    # === "Data\\Meshes\\" and "Data\\Actors\\" xrefs, for context
    log(fh, "\n\n=====================================")
    log(fh, " 'Data\\\\Meshes\\\\' and similar path prefixes")
    log(fh, "=====================================")
    for frag in ["Data\\Meshes", "Data\\Actors", "Meshes\\Actors",
                 "Actors\\Character", "Meshes\\Characters"]:
        hits = find_string_contains(frag)
        for (sea, v) in hits[:5]:
            log(fh, f"  0x{sea:X} RVA=0x{rva(sea):X} '{v}'")

    log(fh, "\n==== END deep-dive 2 ====")
    fh.close()
    ida_pro.qexit(0)


main()
