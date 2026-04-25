"""
M7.b Pass 6 — DEFINITIVE: PC vt[140] = Get3D / loaded3D accessor.

The Papyrus Is3DLoaded native lambda (sub_141157DA0) is:
   return *a3 && (vt[1120 / 8 = 140])(*a3) != 0
So PC vt[140] = sub_140D5BB30 returns the loaded BSFadeNode pointer.

Decompile:
  - sub_140D5BB30  (PC vt[140] size 53)
  - related: vt[156] sub_140CB2E60, vt[157] sub_140CB2E70 (size 36)
  - vt[155] sub_140D7E0B0 (size 28)

Output: re/_player_copy_m7_6_raw.log
"""
import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name

LOG_PATH = r"C:\Users\filip\Desktop\FalloutWorld\re\_player_copy_m7_6_raw.log"
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
log(" M7.b PASS 6 — DEFINITIVE Get3D vt[140] decomp")
log("=" * 80)

# 1) Reference.Is3DLoaded native lambda
decomp(0x141157DA0, "Reference.Is3DLoaded native lambda")

# 2) PC vt[140] = Get3D
decomp(0x140D5BB30, "PC vt[140] = Get3D")

# 3) Adjacent vt slots that are likely related
for slot, ea in [(155, 0x140D7E0B0), (156, 0x140CB2E60), (157, 0x140CB2E70),
                 (139, 0x140D5BBB0), (138, 0x140D77630), (137, 0x14050D6F0),
                 (136, 0x140D5BBD0), (141, 0x14050D9D0), (142, 0x140D8A3A0),
                 (143, 0x140D622C0), (144, 0x140510010)]:
    decomp(ea, "PC vt[%d]" % slot)

# 4) Disassemble PC vt[140] for byte-level confirmation
log("\n--- PC vt[140] = sub_140D5BB30 disasm ---")
ea = 0x140D5BB30
end = 0x140D5BB30 + 60
while ea < end:
    mn = idc.print_insn_mnem(ea)
    if not mn:
        break
    op0 = idc.print_operand(ea, 0)
    op1 = idc.print_operand(ea, 1)
    log("  %s  %-6s %s, %s" % (hexs(ea), mn, op0, op1))
    nxt = idc.next_head(ea, end)
    if nxt == idaapi.BADADDR:
        break
    ea = nxt

# 5) Check Actor vtable @ 0x142513078 vt[140] — confirm same offset
log("\n--- Actor vtable @ 0x142513078 vt[140] ---")
ACTOR_VT = 0x142513078
fn = ida_bytes.get_qword(ACTOR_VT + 140 * 8)
log("  Actor vt[140] = %s" % hexs(fn))
if fn and fn != idaapi.BADADDR:
    decomp(fn, "Actor vt[140]")

# 6) TESObjectREFR vtable — find it
log("\n--- TESObjectREFR vtable lookup ---")
for sn in idautils.Names():
    ea, name = sn
    if name and "TESObjectREFR" in name and "vftable" in name:
        log("  %s @ %s" % (name, hexs(ea)))

# Try a few candidate REFR vtable addrs (likely 0x14250...)
# Check ?_7TESObjectREFR@@6B@ in IDA names
for sn in idautils.Names():
    ea, name = sn
    if name and "_7TESObjectREFR" in name:
        log("  REFR vt: %s @ %s" % (name, hexs(ea)))
        # Read its slot 140
        fn = ida_bytes.get_qword(ea + 140 * 8)
        log("    REFR vt[140] = %s" % hexs(fn))
        if fn and fn != idaapi.BADADDR:
            decomp(fn, "REFR vt[140] (from %s)" % name)
        break

# 7) Compare: NiAVObject and NiNode local-transform offsets
# Specifically, decompile UpdateNode (vt slot for NiAVObject ::Update)
# and what writes to +0x70 / +0xA0 (world transforms)
log("\n--- NiAVObject UpdateNodeUpward / Update — what writes world transforms ---")
# From NiAVObject vtable, scan for UpdateNode-style fns
NIAVOBJ_VT = 0x14267D0C0
for slot in range(40, 75):
    fn = ida_bytes.get_qword(NIAVOBJ_VT + slot * 8)
    if not fn or fn == idaapi.BADADDR:
        continue
    f = ida_funcs.get_func(fn)
    sz = (f.end_ea - f.start_ea) if f else 0
    n = ida_name.get_ea_name(fn) or ""
    log("  NiAVObject vt[%2d] = %s sz=%d %s" % (slot, hexs(fn), sz, n))

# Save report
with open(LOG_PATH, "w", encoding="utf-8") as fp:
    fp.write("\n".join(out_lines))
print("WROTE", LOG_PATH, "lines=%d" % len(out_lines))
idaapi.qexit(0)
