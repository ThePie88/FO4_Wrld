"""
M7.b Pass 7 — Confirm details:
  - sub_14050D990 fallback (Get3DOriginal / GetTemplate3D)
  - NiAVObject vt[48] = sub_1416C8310 — likely UpdateDownwardPass
  - vt[49] vt[50] (size 237 each) — likely UpdateNode / UpdateBound (writers)
  - sub_140D5BBB0 vt[139] — accesses +0xB78 too?
  - cross-check Actor offset 0xB78 in any other Actor::Setup3D path

Output: re/_player_copy_m7_7_raw.log
"""
import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name

LOG_PATH = r"C:\Users\filip\Desktop\FalloutWorld\re\_player_copy_m7_7_raw.log"
out_lines = []

def log(s): out_lines.append(s if isinstance(s, str) else str(s))
def hexs(x):
    try: return "0x%X" % x
    except: return str(x)

def decomp(ea, label=""):
    try:
        cfunc = ida_hexrays.decompile(ea)
        if cfunc:
            log("\n========== %s @ %s ==========" % (label, hexs(ea)))
            log(str(cfunc))
            return cfunc
    except Exception as e:
        log("decomp err %s: %s" % (hexs(ea), e))
    return None

log("=" * 80)
log(" M7.b PASS 7 — confirm details")
log("=" * 80)

# 1) sub_14050D990 fallback for Get3D
decomp(0x14050D990, "sub_14050D990 fallback in Get3D")

# 2) The size-3 fns — NiAVObject UpdateDownwardPass / UpdateUpwardPass
# vt[48] sub_1416C8310 size 136 — UpdateDownwardPass
# vt[47] sub_1416C8230 size 206 — could be UpdateNode / UpdateWorldData
decomp(0x1416C8310, "NiAVObject vt[48] sub_1416C8310")
decomp(0x1416C8230, "NiAVObject vt[47] sub_1416C8230")
decomp(0x1416C83A0, "NiAVObject vt[49] sub_1416C83A0")
decomp(0x1416C84A0, "NiAVObject vt[50] sub_1416C84A0")
decomp(0x1416C81A0, "NiAVObject vt[45] sub_1416C81A0")

# 3) Confirm vt[139] reads 0xB78 too
decomp(0x140D5BBB0, "PC vt[139] sub_140D5BBB0 (re-decomp for verification)")

# 4) Search for any small fn that returns *(this+0xB78) for cross-check
# 0xB78 = 2936 — find candidates
log("\n--- Search small fns returning [this+0xB78] ---")
SCAN_LO, SCAN_HI = 0x140000000, 0x142000000
count = 0
for fn_ea in idautils.Functions(SCAN_LO, SCAN_HI):
    f = ida_funcs.get_func(fn_ea)
    if not f: continue
    sz = f.end_ea - f.start_ea
    if sz < 4 or sz > 80:
        continue
    head = ida_bytes.get_bytes(fn_ea, min(sz, 32))
    if not head: continue
    # Look for: 48 8B 81 78 0B 00 00 = mov rax, [rcx+0xB78]
    if b"\x48\x8B\x81\x78\x0B\x00\x00" in head or b"\x48\x8B\x89\x78\x0B\x00\x00" in head:
        count += 1
        n = ida_name.get_ea_name(fn_ea) or ""
        log("  fn %s sz=%d %s bytes=%s" % (hexs(fn_ea), sz, n, head[:24].hex()))
        if count > 20:
            break

# 5) Find writers to +0xB78 — what code SETS the loaded3D pointer?
# byte sequence: 48 89 81 78 0B 00 00 = mov [rcx+0xB78], rax
log("\n--- Search for writers to [this+0xB78] ---")
count = 0
for fn_ea in idautils.Functions(SCAN_LO, SCAN_HI):
    f = ida_funcs.get_func(fn_ea)
    if not f: continue
    sz = f.end_ea - f.start_ea
    if sz < 4 or sz > 5000:
        continue
    head = ida_bytes.get_bytes(fn_ea, min(sz, 4096))
    if not head: continue
    if b"\x89\x81\x78\x0B\x00\x00" in head or b"\x89\xB1\x78\x0B\x00\x00" in head:
        count += 1
        n = ida_name.get_ea_name(fn_ea) or ""
        log("  fn %s sz=%d %s" % (hexs(fn_ea), sz, n))
        if count > 30:
            break

# Save report
with open(LOG_PATH, "w", encoding="utf-8") as fp:
    fp.write("\n".join(out_lines))
print("WROTE", LOG_PATH, "lines=%d" % len(out_lines))
idaapi.qexit(0)
