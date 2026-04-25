"""
M7.b Pass 4 — Lock down the Get3D / loaded3D offset CONCLUSIVELY.

Approach:
  1. Find caller of sub_140C87EA0 — Actor::Setup3D-like — and observe what
     it passes as 'a4' (the BSFadeNode** out-param).
  2. Find Papyrus Reference.Is3DLoaded (refr-bound) actual native, decompile,
     and observe what offset it reads.
  3. Decompile sub_141162D02 area context for Is3DLoaded ref.
  4. Decompile vt[16] sub_1404F56C0 - candidate Setup3D
  5. Search for "Setup3D" / "AttachTo3D" / "QShouldDeferUpdate" string xrefs.

Output: re/_player_copy_m7_4_raw.log
"""
import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name, ida_segment

LOG_PATH = r"C:\Users\filip\Desktop\FalloutWorld\re\_player_copy_m7_4_raw.log"
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

def xrefs_to(ea, max_=40):
    out = []
    for r in idautils.XrefsTo(ea):
        out.append((r.frm, r.iscode, r.type))
        if len(out) >= max_:
            break
    return out

def func_containing(ea):
    f = ida_funcs.get_func(ea)
    return f.start_ea if f else None

log("=" * 80)
log(" M7.b PASS 4 — Get3D offset, conclusive")
log("=" * 80)

# 1) Callers of sub_140C87EA0 — should pass 3D out-pointer offset
log("\n--- Callers of sub_140C87EA0 (Actor-Setup3D-helper-via-NIF-loader) ---")
for fr, _, _ in xrefs_to(0x140C87EA0, 20):
    f = func_containing(fr)
    n = ida_name.get_ea_name(f) if f else "?"
    log("  xref from %s (in fn %s, %s)" % (hexs(fr), hexs(f) if f else "?", n))
    if f:
        decomp(f, "caller of sub_140C87EA0 @ %s" % hexs(f))

# 2) Decompile vt[16] sub_1404F56C0 — Setup3D candidate
log("\n--- PC vt[16] sub_1404F56C0 ---")
decomp(0x1404F56C0, "PC vt[16] sub_1404F56C0")

# 3) Look for "loadedReference" or "kInitFlags" strings
for s in ["LoadGame", "Setup3D", "InitItem", "Init3D"]:
    pass  # noisy

# 4) Find the engine console command "GetCurrent3D" if it exists
log("\n--- Search for Papyrus 'Reference.Is3DLoaded' implementation ---")
# 'Is3DLoaded' string is at 0x1425CDEA8 — find its registrar (NativeFunction0
# wired to a binder fn). Need the fn that READS the flag.
# Use the xref I already have: sub_141162D02 in fn 0x14115EFB0 registers it.
# Find the lambda/binder that gets attached.

# The natives in FO4 register via NativeFunction0<Reference, bool>::ctor(name,
# class, fn_ptr). The fn_ptr lambda is a small wrapper. Look at the 8 bytes
# AFTER the name string ref in the registrar — typically: offset to lambda fn.

# A reliable shortcut — search for functions xref'd from 0x14115EFB0 that
# are SHORT (5-30 bytes) — those are the Is3DLoaded native lambda.
log("\n--- Small functions called by 0x14115EFB0 (likely include the lambda) ---")
fn = ida_funcs.get_func(0x14115EFB0)
if fn:
    items = []
    ea = fn.start_ea
    while ea < fn.end_ea:
        ins = idc.print_insn_mnem(ea)
        if ins == "lea" or ins == "call":
            op0 = idc.print_operand(ea, 0)
            op1 = idc.print_operand(ea, 1)
            tgt = idc.get_operand_value(ea, 1) if ins == "lea" else idc.get_operand_value(ea, 0)
            if tgt and tgt != idaapi.BADADDR:
                target_fn = ida_funcs.get_func(tgt)
                if target_fn:
                    sz = target_fn.end_ea - target_fn.start_ea
                    if 5 <= sz <= 100:
                        items.append((ea, ins, hexs(tgt), sz))
        ea = idc.next_head(ea, fn.end_ea)
    seen = set()
    for ins_ea, ins, t, sz in items:
        if t in seen: continue
        seen.add(t)
        log("  %s: %s -> %s sz=%d" % (hexs(ins_ea), ins, t, sz))

# 5) THE direct path. Decompile a couple of smallest "lea fn" target candidates
# from inside 0x14115EFB0
log("\n--- Decomp candidate small lambda fns ---")
# Will be filled by caller seeing the items above. Fall back: scan the .text
# range adjacent to 0x14115EFB0 for short fns (likely native lambdas).
for off in range(0, 0x6000, 0x10):
    ea = 0x14115E000 + off
    if not ida_funcs.get_func(ea):
        continue
    f = ida_funcs.get_func(ea)
    sz = f.end_ea - f.start_ea
    if not (5 <= sz <= 60):
        continue
    head = ida_bytes.get_bytes(ea, min(sz, 32))
    if head and head[0:3] == b"\x48\x8B\x41" and b"\xC3" in head[:24]:
        log("  cand %s sz=%d bytes=%s" % (hexs(ea), sz, head[:24].hex()))

# 6) Try Papyrus 'GetHeadingAngle' or 'PlayIdle' which read 3D — find their
# binders. Most direct: 'PlayIdle' definitely reads 3D.

# 7) The DIRECT method: Decompile sub_140C87EA0's caller's CALLER if present.
# Actually let's find what writes to the +0x148 / +0x1F0 / +0x80 offset.
# Search for "mov [rcx+0x80], rax" or similar in apply_mats caller fns.

# 8) Decompile sub_140C5DAA0 (vt[184] of PC: small fn 34 bytes) — could be Has3D
log("\n--- vt[184] sub_140C5DAA0 ---")
decomp(0x140C5DAA0, "PC vt[184] candidate Has3D")

# 9) Decompile vt[105] sub_140C82EA0 (writes structure to a2)
log("\n--- vt[105] sub_140C82EA0 ---")
decomp(0x140C82EA0, "PC vt[105]")

# 10) Decompile vt[14] sub_140311570 — the "GetType" or similar
log("\n--- vt[14] sub_140311570 ---")
decomp(0x140311570, "PC vt[14]")

# 11) Look for sub_140404950 — called from sub_140C87EA0 to wrap form
# Decomp it so we know what type it returns

# 12) The DEFINITIVE: there should be an Actor::QHasCurrentProcess /
# Actor::GetCurrentProcess type fn. Actor in FO4 has loadedData at
# (per CommonLibF4 0.9.0 src):
#    TESObjectREFR layout:
#       +0x68  loadedData     (REFR3D loaded data pointer)
#       +0x70  parentCell     (already verified +0xB8)
# Wait — parentCell is verified +0xB8. So +0x68 is NOT loadedData.
#
# We KNOW from FW codebase memory that:
#    REFR+0xB8 = parentCell
#    REFR+0xC0..0xC8 = AngleX/Y/Z
#    REFR+0xD0..0xD8 = X/Y/Z
#    REFR+0xE0 = baseForm
#    REFR+0xF8/0xFC = scale
#    REFR+0x100 = ExtraDataList
#
# So loadedData is somewhere AFTER 0x100. Likely at 0x108, 0x148, 0x1F0.
#
# Let's decompile sub_140C30D80 (Actor) or the Actor::GetCurrentProcess
# accessor. Search for the Actor RTTI vtable @ the dossier's 0x142513078.

# Decompile some Actor-class small accessor candidates (from earlier scan)
# — these look at REFR/Actor offsets
log("\n--- Decomp short actor-range fns from earlier scan ---")
for ea in [0x14130DA60, 0x141297720, 0x141441850]:
    decomp(ea, "actor small accessor @ %s" % hexs(ea))

# 13) Search for engine CTOR of REFR3DLoadedData / TESObjectREFR3D —
#    or strings. Names containing Loaded:
log("\n--- Names containing Loaded3D / 3DLoaded / loadedRef ---")
for sn in idautils.Names():
    ea, name = sn
    if name and any(s in name for s in [
        "3DLoaded", "loaded3D", "Loaded3D", "REFR3D",
        "REFR_3D", "Setup3D", "Get3D",
    ]):
        log("  %s @ %s" % (name, hexs(ea)))

# 14) Find the 'Loaded3D' string xrefs — search broader xrefs
log("\n--- 'Loaded3D' string @ 0x1424B6F13 — wider xref search ---")
# Try drefs (data refs) from anywhere
for r in idautils.DataRefsTo(0x1424B6F13):
    f = func_containing(r)
    n = ida_name.get_ea_name(f) if f else "?"
    log("  dref from %s in fn %s %s" % (hexs(r), hexs(f) if f else "?", n))

# Save report
with open(LOG_PATH, "w", encoding="utf-8") as fp:
    fp.write("\n".join(out_lines))
print("WROTE", LOG_PATH, "lines=%d" % len(out_lines))
idaapi.qexit(0)
