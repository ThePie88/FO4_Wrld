"""
decomp_nif_loader.py

Find the Fallout 4 engine-internal NIF loader API — the function the engine
calls to turn a path like "Meshes\\Actors\\Character\\CharacterAssets\\MaleBody.nif"
into a render-ready scene-graph root (BSFadeNode / NiAVObject).

Strategy:
 1) Locate the BSModelDB RTTI strings, walk to its TypeDescriptor then to
    vtables / ctors / member functions.
 2) Search for "BSModelDB::Demand" / "::Load" style symbols by name.
 3) Find xrefs to hardcoded .nif paths that end in literal ".nif" and trace
    back to a loader function.
 4) Find xrefs to the NIF magic ("Gamebryo File Format") and the NiStream
    parser entry point.
 5) Decompile the top 2-3 candidate loader functions fully.
 6) Also dump BSFadeNode ctor and child-set helpers for cleanup sequence.
 7) Find the NiRefObject::DecRef pattern for teardown.
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

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\stradaB_nif_loader_raw.txt"


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


def disasm_block(ea, fh, label="", insn_count=80):
    log(fh, f"\n-- disasm {label} @ 0x{ea:X} (RVA 0x{rva(ea):X}) --")
    fn = ida_funcs.get_func(ea)
    if not fn:
        log(fh, "  [!] NO FUNC (addr may be data/vtable)")
        # Just disasm the requested count anyway
        cur = ea
        end = ea + insn_count * 16
        i = 0
        while cur < end and i < insn_count:
            dis = idc.generate_disasm_line(cur, 0) or "?"
            log(fh, f"  0x{cur:X}  {dis}")
            cur = idc.next_head(cur, end)
            i += 1
            if cur == idc.BADADDR:
                break
        return
    cur = ea
    end = min(fn.end_ea, ea + insn_count * 16)
    i = 0
    while cur < end and i < insn_count:
        dis = idc.generate_disasm_line(cur, 0) or "?"
        log(fh, f"  0x{cur:X}  {dis}")
        cur = idc.next_head(cur, end)
        i += 1
        if cur == idc.BADADDR:
            break


def find_strings_containing(substrs, fh, label="", limit=200):
    log(fh, f"\n==== Searching .rdata for substrings: {substrs} ({label}) ====")
    found = []
    for s in idautils.Strings():
        try:
            v = str(s)
        except:
            continue
        if any(sub.lower() in v.lower() for sub in substrs):
            ea = s.ea
            found.append((ea, v))
            log(fh, f"  0x{ea:X}  RVA=0x{rva(ea):X}  '{v}'")
            if len(found) >= limit:
                log(fh, f"  ... (limit {limit} reached)")
                break
    return found


def find_string_equals(exact, fh):
    """Find string by EXACT match."""
    for s in idautils.Strings():
        try:
            v = str(s)
        except:
            continue
        if v == exact:
            return s.ea
    return 0


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


def sym(name):
    ea = ida_name.get_name_ea(idc.BADADDR, name)
    return ea if ea != idc.BADADDR else 0


def list_names_matching(patterns, fh, label="", limit=120):
    log(fh, f"\n==== Names matching {patterns} ({label}) ====")
    hits = []
    for (ea, n) in idautils.Names():
        ln = n.lower()
        if any(p.lower() in ln for p in patterns):
            hits.append((ea, n))
    for (ea, n) in hits[:limit]:
        log(fh, f"  0x{ea:X}  RVA=0x{rva(ea):X}  {n}")
    return hits


def find_rtti_typedescriptor(mangled_name, fh):
    """Given a mangled RTTI string like '.?AVBSModelDB@@', return the TypeDescriptor
    address (which is the string's address - 0x10 typically on MSVC x64).
    Actually: the `.?AV...` string is at an offset inside the TypeDescriptor; we
    search for references to the string directly."""
    log(fh, f"\n==== RTTI lookup: {mangled_name} ====")
    str_ea = find_string_equals(mangled_name, fh)
    if not str_ea:
        log(fh, "  not found as exact string")
        # try as substring
        matches = [ea for ea, v in [(s.ea, str(s)) for s in idautils.Strings()]
                   if mangled_name in v]
        if matches:
            log(fh, f"  partial matches: {[hex(m) for m in matches[:5]]}")
            str_ea = matches[0]
        else:
            return 0, []
    log(fh, f"  string @ 0x{str_ea:X} (RVA 0x{rva(str_ea):X})")
    # TypeDescriptor header is at str_ea - 0x10 on x64 (vtable + spare + name)
    td = str_ea - 0x10
    log(fh, f"  TypeDescriptor (guess) @ 0x{td:X}")
    # Find xrefs to TD (those are likely RTTICompleteObjectLocator entries)
    col_refs = list(idautils.XrefsTo(td, 0))
    log(fh, f"  xrefs to TD: {len(col_refs)}")
    for xr in col_refs[:12]:
        log(fh, f"    from 0x{xr.frm:X} type={xr.type}")
    return td, col_refs


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    log(fh, "==== Fallout 4 — NIF loader API dossier (raw) ====")
    ida_auto.auto_wait()
    ida_hexrays.init_hexrays_plugin()
    IMG = ida_nalt.get_imagebase()
    log(fh, f"image base = 0x{IMG:X}")

    # === STEP 1 — RTTI for BSModelDB, NiStream, BSFadeNode, BSResourceNiBinaryStream
    log(fh, "\n\n=========================================")
    log(fh, "  STEP 1 — RTTI TypeDescriptors")
    log(fh, "=========================================")
    rtti_hits = {}
    for mangled in [
        ".?AV?$EntryDB@UDBTraits@BSModelDB@@@BSResource@@",
        ".?AUDBTraits@BSModelDB@@",
        ".?AVBSModelProcessor@BSModelDB@@",
        ".?AVQueuedHandles@BSModelDB@@",
        ".?AVNiStream@@",
        ".?AVBSFadeNode@@",
        ".?AVBSResourceNiBinaryStream@@",
        ".?AVBSFile@@",
    ]:
        td, col = find_rtti_typedescriptor(mangled, fh)
        rtti_hits[mangled] = (td, col)

    # === STEP 2 — Names matching loader-style symbols
    log(fh, "\n\n=========================================")
    log(fh, "  STEP 2 — Names matching loader patterns")
    log(fh, "=========================================")
    name_hits = list_names_matching(
        ["BSModelDB", "ModelDB", "NiStream", "BSFadeNode",
         "BSResourceNiBinaryStream", "BSModelProcessor",
         "QueuedHandles", "LoadResource", "QueueLoad",
         "::Load", "::Demand", "::ResolveLoad", "BSResource::",
         "EntryDB", "DBTraits"],
        fh, label="loader-style-names", limit=200,
    )

    # === STEP 3 — Find the "Gamebryo File Format" magic string
    log(fh, "\n\n=========================================")
    log(fh, "  STEP 3 — NIF magic 'Gamebryo File Format' xrefs")
    log(fh, "=========================================")
    for magic in ["Gamebryo File Format",
                  "NetImmerse File Format",
                  "Gamebryo File Format, Version"]:
        found = find_strings_containing([magic], fh, label=f"magic-{magic[:20]}")
        for (sea, v) in found[:3]:
            xrefs_to_addr(fh, sea, f"'{v}'", limit=8)

    # === STEP 4 — Find NIF path strings that look like engine-consumed
    # We want to find: paths the engine uses literally (not editor-marker).
    # The char body NIFs are probably built up at runtime from format strings,
    # but the ARMO/MODT data points to specific .nif paths.
    log(fh, "\n\n=========================================")
    log(fh, "  STEP 4 — .nif path format strings + xrefs")
    log(fh, "=========================================")
    # "%s\\%s.nif" is a common Creation Engine format
    nif_fmts = find_strings_containing([
        "%s.nif", "%s.NIF",
        "Meshes\\%s", "meshes\\%s",
        ".nif\0",
    ], fh, label="nif-path-format-strings")

    # Dedup function set
    seen_funcs = set()

    # Trace 8 of them
    for (sea, v) in nif_fmts[:12]:
        log(fh, f"\n-- xref analysis for '{v}' @ 0x{sea:X} --")
        xrs = xrefs_to_addr(fh, sea, f"'{v}'", limit=6)
        for (_, fn_ea) in xrs[:2]:
            if fn_ea and fn_ea not in seen_funcs:
                seen_funcs.add(fn_ea)
                decomp_full(fn_ea, fh, f"fmt-consumer '{v[:25]}'", max_lines=200)

    # === STEP 5 — Specific editor-marker NIFs that are definitely loaded by
    # the engine at startup (MarkerX.nif etc). Trace the code that loads them.
    log(fh, "\n\n=========================================")
    log(fh, "  STEP 5 — Marker NIF load sites")
    log(fh, "=========================================")
    for name in ["MarkerX.nif", "EditorMarker.NIF", "MarkerTeleport.nif",
                 "Marker_Error.NIF", "SplineMarker.nif"]:
        sea = find_string_equals(name, fh)
        if not sea:
            # loose search
            for s in idautils.Strings():
                try:
                    v = str(s)
                except:
                    continue
                if name.lower() in v.lower():
                    sea = s.ea
                    break
        if sea:
            log(fh, f"\n  '{name}' @ 0x{sea:X} RVA 0x{rva(sea):X}")
            xrs = xrefs_to_addr(fh, sea, name, limit=8)
            for (xf, fn_ea) in xrs[:2]:
                if fn_ea and fn_ea not in seen_funcs:
                    seen_funcs.add(fn_ea)
                    decomp_full(fn_ea, fh, f"marker-loader-of-{name}", max_lines=250)

    # === STEP 6 — BSFadeNode ctor + AssignSource (we know from M1 dossier)
    log(fh, "\n\n=========================================")
    log(fh, "  STEP 6 — BSFadeNode ctor + AssignSource")
    log(fh, "=========================================")
    BSFADENODE_CTOR = IMG + 0x2174DC0
    BSFADENODE_ASSIGNSRC = IMG + 0x2174E60
    decomp_full(BSFADENODE_CTOR, fh, "BSFadeNode::ctor", max_lines=300)
    decomp_full(BSFADENODE_ASSIGNSRC, fh, "BSFadeNode::AssignSource", max_lines=300)

    # Who calls AssignSource? Those are the NIF loader wrappers most likely.
    xrefs_to_addr(fh, BSFADENODE_ASSIGNSRC, "BSFadeNode::AssignSource", limit=40)

    # === STEP 7 — Full names dump of anything containing "Model" or "Mesh"
    log(fh, "\n\n=========================================")
    log(fh, "  STEP 7 — 'Model' / 'Mesh' symbol sweep")
    log(fh, "=========================================")
    list_names_matching(["Model::", "Mesh::", "LoadMesh", "LoadModel",
                         "GetModel", "FetchModel", "Load3DModel",
                         "NiObject::Load", "BSResource::Load",
                         "Fetch::Async"],
                         fh, label="model-mesh-names", limit=120)

    # === STEP 8 — Attempt to locate a "%s.nif" format string writer
    # and follow into the loader. Also: search for functions that call
    # something AND reference ".nif" as an immediate.
    log(fh, "\n\n=========================================")
    log(fh, "  STEP 8 — functions that build .nif paths and call loaders")
    log(fh, "=========================================")
    # Get ".nif" bytes in .rdata to find cross-refs to any string ending .nif
    # (too many to enumerate; skip and rely on fmts + markers)

    # === STEP 9 — Look for TESNPC::Load3D / TESObjectREFR::Load3D
    log(fh, "\n\n=========================================")
    log(fh, "  STEP 9 — TESObjectREFR::Load3D / Actor::Load3D RTTI")
    log(fh, "=========================================")
    for rtti_sym in [
        ".?AVTESObjectREFR@@",
        ".?AVTESNPC@@",
        ".?AVActor@@",
        ".?AVCharacter@@",
        ".?AVTESObjectARMO@@",
        ".?AVBGSModelMaterialSwap@@",
        ".?AVTESModel@@",
    ]:
        find_rtti_typedescriptor(rtti_sym, fh)

    # === STEP 10 — Check "Failed to initialize terrain effect (Incorrect model name? Use <model>.nif)"
    # That string should be referenced in the NIF load error handler.
    log(fh, "\n\n=========================================")
    log(fh, "  STEP 10 — terrain-effect error string")
    log(fh, "=========================================")
    err_sea = find_string_equals(
        "Failed to initialize terrain effect (Incorrect model name? Use <model>.nif)",
        fh)
    if not err_sea:
        for s in idautils.Strings():
            try:
                v = str(s)
            except:
                continue
            if "terrain effect" in v.lower() and "model name" in v.lower():
                err_sea = s.ea
                break
    if err_sea:
        log(fh, f"\n  error string @ 0x{err_sea:X} RVA 0x{rva(err_sea):X}")
        xrs = xrefs_to_addr(fh, err_sea, "terrain-effect-error", limit=10)
        for (_, fn_ea) in xrs[:3]:
            if fn_ea and fn_ea not in seen_funcs:
                seen_funcs.add(fn_ea)
                decomp_full(fn_ea, fh, "terrain-effect-error-site", max_lines=300)

    # === STEP 11 — Search strings dump for "BSModelDB::Demand" / ::Load etc.
    log(fh, "\n\n=========================================")
    log(fh, "  STEP 11 — debug/log strings for ModelDB")
    log(fh, "=========================================")
    hunt = find_strings_containing(
        ["ModelDB::", "ModelDB ", "model.db",
         "BSModelManager", "NiStream::Load",
         "failed to load model", "could not load model",
         "model load fail"],
        fh, label="modeldb-debug-strings", limit=50,
    )
    for (sea, v) in hunt[:10]:
        xrefs_to_addr(fh, sea, f"'{v}'", limit=6)

    # === STEP 12 — "*.NIF" / ".NIF" / "nif" as extension strings
    log(fh, "\n\n=========================================")
    log(fh, "  STEP 12 — extension literal scan")
    log(fh, "=========================================")
    ext_hits = find_strings_containing(["\\*.NIF", "\\*.nif"], fh, label="nif-glob")
    for (sea, v) in ext_hits[:8]:
        xrs = xrefs_to_addr(fh, sea, v, limit=6)
        for (_, fn_ea) in xrs[:2]:
            if fn_ea and fn_ea not in seen_funcs:
                seen_funcs.add(fn_ea)
                decomp_full(fn_ea, fh, f"nif-glob-consumer", max_lines=200)

    log(fh, "\n==== END NIF loader dossier ====")
    fh.close()
    ida_pro.qexit(0)


main()
