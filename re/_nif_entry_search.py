"""Deep search for NIF load entry point.
Goals:
  1. Disasm prolog sub_1417B3E90 (50 insns).
  2. Real asm at all xref call sites of sub_1417B3E90.
  3. sub_1401880B0 (Marker_Error) — investigate.
  4. xrefs to NIF path strings in .rdata.
  5. BSModelDB::EntryDB RTTI follow -> Demand method.
  6. sub_140458740 (Actor::Load3D) skim.
  7. sub_14033EF00 -> understand second arg type.
"""
import idc
import idaapi
import idautils
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_name
import ida_ua
import ida_xref
import ida_search
import ida_segment
import ida_typeinf

ida_hexrays.init_hexrays_plugin()

OUT_LOG = r"C:\Users\filip\Desktop\FalloutWorld\re\_nif_entry_search.log"
OUT_DUMP = r"C:\Users\filip\Desktop\FalloutWorld\re\_nif_entry_search.dump.log"

LOG = open(OUT_LOG, "w", encoding="utf-8")
DUMP = open(OUT_DUMP, "w", encoding="utf-8")

def log(s=""):
    print(s, flush=True)
    LOG.write(s + "\n")

def dump(s=""):
    DUMP.write(s + "\n")

def disasm_range(start, end, fh):
    """Dump disasm between ea=start..end inclusive."""
    ea = start
    while ea < end:
        line = idc.generate_disasm_line(ea, 0) or ""
        bytes_hex = ""
        sz = idc.get_item_size(ea)
        raw = ida_bytes.get_bytes(ea, sz) or b""
        bytes_hex = raw.hex()
        fh.write(f"  0x{ea:X}  {bytes_hex:<20} {line}\n")
        ea = idc.next_head(ea, end + 0x200)

def disasm_n(ea, n, fh):
    """Disasm n instructions starting at ea."""
    cur = ea
    for _ in range(n):
        line = idc.generate_disasm_line(cur, 0) or ""
        sz = idc.get_item_size(cur)
        raw = ida_bytes.get_bytes(cur, sz) or b""
        bytes_hex = raw.hex()
        fh.write(f"  0x{cur:X}  {bytes_hex:<20} {line}\n")
        nxt = idc.next_head(cur)
        if nxt == idc.BADADDR:
            break
        cur = nxt

def disasm_window(ea, before=20, after=15, fh=None):
    """Disasm a window centered around ea."""
    cur = ea
    for _ in range(before):
        prev = idc.prev_head(cur)
        if prev == idc.BADADDR:
            break
        cur = prev
    start = cur
    total = before + after + 1
    cur = start
    for _ in range(total):
        line = idc.generate_disasm_line(cur, 0) or ""
        sz = idc.get_item_size(cur)
        raw = ida_bytes.get_bytes(cur, sz) or b""
        bytes_hex = raw.hex()
        mark = "  <--" if cur == ea else ""
        fh.write(f"  0x{cur:X}  {bytes_hex:<20} {line}{mark}\n")
        nxt = idc.next_head(cur)
        if nxt == idc.BADADDR:
            break
        cur = nxt

def safe_decompile(ea):
    try:
        c = ida_hexrays.decompile(ea)
        if c:
            return str(c)
    except Exception as e:
        return f"<decompile failed: {e}>"
    return "<decompile empty>"

# ============================================================
# 1. Prolog sub_1417B3E90 (50 insns)
# ============================================================
log("\n==========================================================")
log("== 1. PROLOG sub_1417B3E90 (first 60 insns)")
log("==========================================================")
EA = 0x1417B3E90
log(f"Function name: {idc.get_func_name(EA)}")
log(f"Size: 0x{idc.get_func_attr(EA, idc.FUNCATTR_END) - EA:X}")
dump(f"\n====== PROLOG sub_1417B3E90 @ 0x{EA:X} ======")
disasm_n(EA, 80, DUMP)

# Also extract: the FIRST memory read from rcx, rdx, r8
log("\n-- scanning for first rcx/rdx/r8 deref --")
cur = EA
for _ in range(80):
    mnem = idc.print_insn_mnem(cur)
    op0 = idc.print_operand(cur, 0)
    op1 = idc.print_operand(cur, 1)
    line = idc.generate_disasm_line(cur, 0)
    if any(t in (op0 + " " + op1).lower() for t in ["[rcx","[rdx","[r8","[r9"]):
        log(f"  deref @ 0x{cur:X}: {line}")
    cur = idc.next_head(cur)
    if cur == idc.BADADDR:
        break

# ============================================================
# 2. All xrefs to sub_1417B3E90 — dump real asm
# ============================================================
log("\n==========================================================")
log("== 2. XREFS TO sub_1417B3E90 — REAL ASM AT CALL SITES")
log("==========================================================")
dump(f"\n====== XREFS TO sub_1417B3E90 ======")
for x in idautils.XrefsTo(EA):
    log(f"\n-- xref from 0x{x.frm:X} (type={x.type}) in {idc.get_func_name(x.frm)} --")
    dump(f"\n-- xref from 0x{x.frm:X} in {idc.get_func_name(x.frm)} --")
    disasm_window(x.frm, before=30, after=6, fh=DUMP)

# ============================================================
# 3. sub_1401880B0 investigation (Marker_Error caller)
# ============================================================
log("\n==========================================================")
log("== 3. sub_1401880B0 Marker_Error caller — decomp + disasm")
log("==========================================================")
EA2 = 0x1401880B0
log(f"Function: {idc.get_func_name(EA2)}")
sz2 = idc.get_func_attr(EA2, idc.FUNCATTR_END) - EA2
log(f"Size: 0x{sz2:X}")
dump(f"\n====== sub_1401880B0 @ 0x{EA2:X} ======")
disasm_n(EA2, 60, DUMP)
log("\n-- decomp sub_1401880B0 --")
log(safe_decompile(EA2)[:4000])

# xrefs TO this function (who calls Marker_Error?)
log("\n-- xrefs to sub_1401880B0 --")
cnt = 0
for x in idautils.XrefsTo(EA2):
    log(f"  xref from 0x{x.frm:X} in {idc.get_func_name(x.frm)} type={x.type}")
    cnt += 1
    if cnt > 8:
        break

# ============================================================
# 4. NIF path strings in .rdata
# ============================================================
log("\n==========================================================")
log("== 4. NIF PATH STRINGS IN .rdata — xref who uses them")
log("==========================================================")

# Known addresses from dossier:
known_addrs = {
    0x1424B0638: "Data\\Meshes\\TestSave.nif",
    0x1424CEDC8: "Meshes\\Actors\\Character\\FaceGenData...",
    0x142519110: "%s\\Actors\\Character\\CameraShake.nif",
}

# Also scan .rdata strings list for any ending in .nif
log("\n-- scan .rdata strings for '.nif' endings (first 40) --")
seen = 0
for s_ea, s_val in idautils.Strings():
    sv = str(s_val)
    if sv.lower().endswith(".nif") and seen < 60:
        xrefs = [hex(x.frm) for x in idautils.XrefsTo(s_ea)][:5]
        log(f"  0x{s_ea:X}: {sv!r:70s} xrefs: {xrefs}")
        seen += 1

# Deep-dive on the known strings
for addr, name in known_addrs.items():
    log(f"\n-- xrefs to '{name}' @ 0x{addr:X} --")
    s = idc.get_strlit_contents(addr, -1, ida_bytes.STRTYPE_C)
    if s:
        log(f"    string: {s.decode('latin-1')!r}")
    for x in idautils.XrefsTo(addr):
        func = idc.get_func_name(x.frm)
        log(f"    xref from 0x{x.frm:X} in {func}")

# ============================================================
# 5. RTTI: BSModelDB::EntryDB -> Demand method
# ============================================================
log("\n==========================================================")
log("== 5. BSModelDB::EntryDB RTTI @ 0x309C680 -> class methods")
log("==========================================================")
RTTI_EA = 0x143097000  # hmm dossier said 0x309C680 which is RVA
# Actually RVA 0x309C680 -> VA 0x143097...no: IMG 0x140000000 + 0x309C680 = 0x14309C680
RTTI_VA = 0x14309C680
s = idc.get_strlit_contents(RTTI_VA, -1, ida_bytes.STRTYPE_C) or b""
log(f"  @ 0x{RTTI_VA:X}: {s.decode('latin-1')!r}")
# xrefs to RTTI string
log("\n-- xrefs to EntryDB<BSModelDB> RTTI string --")
for x in idautils.XrefsTo(RTTI_VA):
    log(f"    xref from 0x{x.frm:X}  {idc.get_func_name(x.frm)}")

# Find the vtable for BSModelDB::EntryDB (class is .?AV?$EntryDB...)
# Scan .rdata for pointers that are close to the RTTI addr. Typical MSVC RTTI descriptor chain.
# Also search for strings containing "Demand"
log("\n-- search strings for 'Demand' (first 10) --")
text_seg = ida_segment.get_segm_by_name(".rdata")
if text_seg:
    cnt = 0
    for s_ea, s_val in idautils.Strings():
        sv = str(s_val)
        if "Demand" in sv and cnt < 15:
            log(f"  0x{s_ea:X}: {sv!r}")
            cnt += 1

# ============================================================
# 6. sub_140458740 (Actor::Load3D) skim
# ============================================================
log("\n==========================================================")
log("== 6. sub_140458740 Actor::Load3D-like — first 60 insns")
log("==========================================================")
EA3 = 0x140458740
log(f"Size: 0x{idc.get_func_attr(EA3, idc.FUNCATTR_END) - EA3:X}")
dump(f"\n====== sub_140458740 @ 0x{EA3:X} first 80 insns ======")
disasm_n(EA3, 100, DUMP)

# Find which NIF load function Actor::Load3D uses
log("\n-- scan body for calls to loader functions --")
fn_end = idc.get_func_attr(EA3, idc.FUNCATTR_END)
cur = EA3
while cur < fn_end:
    mnem = idc.print_insn_mnem(cur)
    if mnem == "call":
        tgt = idc.get_operand_value(cur, 0)
        name = idc.get_func_name(tgt) or f"sub_{tgt:X}"
        # interesting targets
        if any(t in name for t in ["17B3", "26E1C", "33EC", "33EF", "33D1", "16A6", "Load3D", "Demand"]):
            log(f"  call @ 0x{cur:X} -> {name} (0x{tgt:X})")
    cur = idc.next_head(cur, fn_end)
    if cur == idc.BADADDR:
        break

# ============================================================
# 7. sub_14033EF00 — understand what arg2 (BSResource::EntryDB::Entry*) is
# ============================================================
log("\n==========================================================")
log("== 7. sub_14033EF00 decomp + signature")
log("==========================================================")
EA4 = 0x14033EF00
log(safe_decompile(EA4)[:3000])

# ============================================================
# 8. sub_1416A6D00 and sub_1416A6930 — cache layer
# ============================================================
log("\n==========================================================")
log("== 8. sub_1416A6D00 ResolveFromCache decomp (first 3000 chars)")
log("==========================================================")
log(safe_decompile(0x1416A6D00)[:3000])

log("\n==========================================================")
log("== 9. sub_1416A6930 cache variant")
log("==========================================================")
log(safe_decompile(0x1416A6930)[:2500])

# ============================================================
# 10. qword_14355EB60 fallback-path BSFixedString - what's there at runtime?
# ============================================================
log("\n==========================================================")
log("== 10. qword_14355EB60 data + writer")
log("==========================================================")
# find writes to this addr
VAR = 0x14355EB60
log(f"-- xrefs to qword_14355EB60 --")
cnt = 0
for x in idautils.XrefsTo(VAR):
    log(f"  xref from 0x{x.frm:X} in {idc.get_func_name(x.frm)} type={x.type}")
    cnt += 1
    if cnt > 10:
        break

# ============================================================
# 11. Look for a function that takes ONLY a path string
# ============================================================
log("\n==========================================================")
log("== 11. Search for single-arg or two-arg NIF path functions")
log("==========================================================")
# Strategy: functions called at vanilla sub_1401880B0 Marker_Error site
# Deep-dive: what does Marker_Error init call? Let's look for LOAD_XREF to "Meshes\\Marker_Error.NIF"
s_markerr = 0
for s_ea, s_val in idautils.Strings():
    sv = str(s_val)
    if "Marker_Error" in sv:
        log(f"  string @ 0x{s_ea:X}: {sv!r}")
        s_markerr = s_ea
        break

if s_markerr:
    log(f"\n-- xrefs to Marker_Error string --")
    for x in idautils.XrefsTo(s_markerr):
        func = idc.get_func_name(x.frm)
        log(f"  xref from 0x{x.frm:X} in {func}")

# ============================================================
# 12. Dump sub_14033D1E0 (REFR::Load3D)
# ============================================================
log("\n==========================================================")
log("== 12. sub_14033D1E0 REFR::Load3D first 3500 chars")
log("==========================================================")
log(safe_decompile(0x14033D1E0)[:3500])

LOG.close()
DUMP.close()
print("DONE")
idc.qexit(0)
