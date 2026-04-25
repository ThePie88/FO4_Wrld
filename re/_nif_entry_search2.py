"""Part 2: skipped sections — without idautils.Strings()."""
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

ida_hexrays.init_hexrays_plugin()

OUT_LOG = r"C:\Users\filip\Desktop\FalloutWorld\re\_nif_entry_search.log"
OUT_DUMP = r"C:\Users\filip\Desktop\FalloutWorld\re\_nif_entry_search.dump.log"

LOG = open(OUT_LOG, "a", encoding="utf-8")
DUMP = open(OUT_DUMP, "a", encoding="utf-8")

def log(s=""):
    print(s, flush=True)
    LOG.write(s + "\n")

def dump(s=""):
    DUMP.write(s + "\n")

def disasm_n(ea, n, fh):
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

def safe_decompile(ea):
    try:
        c = ida_hexrays.decompile(ea)
        if c:
            return str(c)
    except Exception as e:
        return f"<decompile failed: {e}>"
    return "<decompile empty>"

# ============================================================
# 4b. NIF path strings via direct EA lookup (no idautils.Strings)
# ============================================================
log("\n==========================================================")
log("== 4b. NIF PATH STRINGS — known + 'TestSave' search")
log("==========================================================")

known = [0x1424B0638, 0x1424CEDC8, 0x142519110]
# Find "TestSave.nif" via idc.find_binary
rdata = ida_segment.get_segm_by_name(".rdata")
target = b"TestSave.nif"
if rdata:
    try:
        size = min(rdata.end_ea - rdata.start_ea, 8 * 1024 * 1024)
        chunk = ida_bytes.get_bytes(rdata.start_ea, size) or b""
        pos = chunk.find(target)
        if pos >= 0:
            start = pos
            while start > 0 and chunk[start - 1] != 0:
                start -= 1
            cur = rdata.start_ea + start
            known.append(cur)
            log(f"  scan-hit TestSave: 0x{cur:X}")
    except Exception as e:
        log(f"  scan failed: {e}")

for addr in set(known):
    s = idc.get_strlit_contents(addr, -1, 0)
    ss = repr(s) if s else "<?>"
    log(f"\n-- addr 0x{addr:X}  str: {ss}")
    for x in idautils.XrefsTo(addr):
        func = idc.get_func_name(x.frm)
        log(f"    xref from 0x{x.frm:X} in {func} type={x.type}")

# ============================================================
# 5b. RTTI BSModelDB::EntryDB -> look for Demand/classdump
# ============================================================
log("\n==========================================================")
log("== 5b. BSModelDB::EntryDB RTTI @ 0x14309C680 -> class methods")
log("==========================================================")

RTTI_VA = 0x14309C680
s = idc.get_strlit_contents(RTTI_VA, -1, 0) or b""
sr = repr(s)
log(f"  RTTI string @ 0x{RTTI_VA:X}: {sr}")

log("\n-- xrefs to EntryDB<BSModelDB> RTTI string --")
for x in idautils.XrefsTo(RTTI_VA):
    log(f"    xref from 0x{x.frm:X} func={idc.get_func_name(x.frm)}")

# Search text segment for "Demand" strings via raw read
log("\n-- search .rdata for 'Demand' strings (raw scan) --")
rdata = ida_segment.get_segm_by_name(".rdata")
if rdata:
    target = b"Demand"
    # Read entire .rdata in one chunk (limit 8MB)
    size = min(rdata.end_ea - rdata.start_ea, 8 * 1024 * 1024)
    chunk = ida_bytes.get_bytes(rdata.start_ea, size) or b""
    idx = 0
    cnt = 0
    while cnt < 20:
        pos = chunk.find(target, idx)
        if pos < 0:
            break
        abs_addr = rdata.start_ea + pos
        # walk back to cstr start
        start = pos
        while start > 0 and chunk[start - 1] != 0:
            start -= 1
        cstr_addr = rdata.start_ea + start
        # extract cstr
        end = start
        while end < len(chunk) and chunk[end] != 0:
            end += 1
        s = chunk[start:end]
        if b"Demand" in s:
            xs = [hex(x.frm) for x in idautils.XrefsTo(cstr_addr)][:5]
            sr = repr(s)
            log(f"  0x{cstr_addr:X}: {sr}  xrefs: {xs}")
            cnt += 1
        idx = pos + 6

# ============================================================
# 6b. sub_140458740 Actor::Load3D — scan body for NIF load calls
# ============================================================
log("\n==========================================================")
log("== 6b. sub_140458740 body call-scan")
log("==========================================================")
EA3 = 0x140458740
fn_end = idc.get_func_attr(EA3, idc.FUNCATTR_END)
log(f"function range 0x{EA3:X} .. 0x{fn_end:X}  size=0x{fn_end-EA3:X}")
cur = EA3
calls_interest = []
while cur < fn_end and cur != idc.BADADDR:
    mnem = idc.print_insn_mnem(cur)
    if mnem == "call":
        tgt = idc.get_operand_value(cur, 0)
        name = idc.get_func_name(tgt) or f"sub_{tgt:X}"
        if any(t in name for t in ["17B3", "26E1C", "33EC", "33EF", "33D1", "16A6", "Load3D", "Demand", "Demand"]):
            log(f"  call @ 0x{cur:X} -> {name} (0x{tgt:X})")
            calls_interest.append((cur, tgt, name))
    cur = idc.next_head(cur, fn_end)

# ============================================================
# 7. sub_14033EF00 decomp
# ============================================================
log("\n==========================================================")
log("== 7. sub_14033EF00 decomp")
log("==========================================================")
log(safe_decompile(0x14033EF00)[:3500])

# ============================================================
# 8. sub_1416A6D00 decomp
# ============================================================
log("\n==========================================================")
log("== 8. sub_1416A6D00 decomp")
log("==========================================================")
log(safe_decompile(0x1416A6D00)[:3500])

# ============================================================
# 9. sub_1416A6930 decomp
# ============================================================
log("\n==========================================================")
log("== 9. sub_1416A6930 decomp")
log("==========================================================")
log(safe_decompile(0x1416A6930)[:2500])

# ============================================================
# 10. qword_14355EB60 fallback-path xrefs
# ============================================================
log("\n==========================================================")
log("== 10. qword_14355EB60 xrefs")
log("==========================================================")
VAR = 0x14355EB60
for x in idautils.XrefsTo(VAR):
    log(f"  xref from 0x{x.frm:X} in {idc.get_func_name(x.frm)} type={x.type}")

# ============================================================
# 11. sub_14033D1E0 decomp
# ============================================================
log("\n==========================================================")
log("== 11. sub_14033D1E0 REFR::Load3D decomp")
log("==========================================================")
log(safe_decompile(0x14033D1E0)[:4000])

# ============================================================
# 12. sub_1417B3480 prolog — see what a3 deref pattern does
# ============================================================
log("\n==========================================================")
log("== 12. sub_1417B3480 prolog (80 insns)")
log("==========================================================")
dump(f"\n====== sub_1417B3480 PROLOG @ 0x1417B3480 ======")
disasm_n(0x1417B3480, 90, DUMP)

# Also decomp — use hex-rays on the full function
log("\n-- sub_1417B3480 decomp (first 5000 chars) --")
log(safe_decompile(0x1417B3480)[:5000])

# ============================================================
# 13. Dump sub_14033EC90 prolog to understand a3 + a5 deref chain
# ============================================================
log("\n==========================================================")
log("== 13. sub_14033EC90 prolog (50 insns)")
log("==========================================================")
dump(f"\n====== sub_14033EC90 PROLOG @ 0x14033EC90 ======")
disasm_n(0x14033EC90, 60, DUMP)

# ============================================================
# 14. Look at caller_of_ec90_a @ 0x1407758D0 — does it pass 0 or non-0 for a3/a5?
# ============================================================
log("\n==========================================================")
log("== 14. caller 0x1407758D0 — how it calls sub_14033EC90 + sub_1417B3E90")
log("==========================================================")
dump(f"\n====== caller 0x1407758D0 ======")
disasm_n(0x1407758D0, 200, DUMP)

# ============================================================
# 15. Scan disasm near each call site: what's in the 16-byte struct?
# ============================================================
log("\n==========================================================")
log("== 15. Caller-struct layout scan (the a3 pointer target)")
log("==========================================================")

call_sites = [
    (0x1402AE058, 0x1402ADF80, "sub_1402ADF80"),
    (0x1402D69BF, 0x1402D6910, "sub_1402D6910"),
    (0x1403D36A7, 0x1403D3480, "sub_1403D3480"),
    (0x1403F736F, 0x1403F7320, "sub_1403F7320"),
    (0x1403FA4CF, 0x1403FA450, "sub_1403FA450"),
    (0x14042D58F, 0x14042D520, "sub_14042D520"),
    (0x14042F975, 0x14042F8D0, "sub_14042F8D0"),
    (0x140434E1F, 0x140434DA0, "sub_140434DA0"),
]

for site, fn, fn_name in call_sites:
    log(f"\n-- at 0x{site:X} in {fn_name} --")
    dump(f"\n-- call site 0x{site:X} in {fn_name} — 40 insns before --")
    # walk back 40 instructions
    cur = site
    for _ in range(40):
        prev = idc.prev_head(cur)
        if prev == idc.BADADDR:
            break
        cur = prev
    start = cur
    # scan for stores that match lea r8, [rsp+X] and stores to [rsp+X+0..8]
    cur = start
    for _ in range(42):
        line = idc.generate_disasm_line(cur, 0) or ""
        dump(f"  0x{cur:X}  {line}")
        cur = idc.next_head(cur)
        if cur == idc.BADADDR:
            break

LOG.close()
DUMP.close()
print("DONE2")
idc.qexit(0)
