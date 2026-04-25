"""
M7.b Pass 5 — Direct: find the lambda registered for Reference.Is3DLoaded
              and chase REFR's loaded3D offset.

The strategy: Papyrus 'Is3DLoaded' string @ 0x1425CDEA8.
Find the registrar (NativeFunction0<Reference,bool>::ctor) callsite and
look at the lambda function ptr it stores. Decompile that lambda — it
ought to read Get3D from the actor and return whether it's non-null.

Also: PRINT THE STRINGS adjacent to "Is3DLoaded" — Papyrus class binder
namespaces are typically "ObjectReference", "Reference", or "Actor".

Output: re/_player_copy_m7_5_raw.log
"""
import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, ida_name, ida_segment

LOG_PATH = r"C:\Users\filip\Desktop\FalloutWorld\re\_player_copy_m7_5_raw.log"
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
log(" M7.b PASS 5 — Reference.Is3DLoaded lambda hunt")
log("=" * 80)

# 1) The xref to "Is3DLoaded" string @ 0x1425CDEA8 was at 0x141162D02 inside
#    fn 0x14115EFB0 (the registrar). Look at the IDA region around that
#    site for the LEA of the lambda fn pointer (within +0x40 of the string ref).
log("\n--- Look at code around 0x141162D02 (Is3DLoaded string xref site) ---")
ea = 0x141162D00 - 0x40
end = 0x141162D00 + 0x100
while ea < end:
    mn = idc.print_insn_mnem(ea)
    if mn:
        op0 = idc.print_operand(ea, 0)
        op1 = idc.print_operand(ea, 1)
        # 'lea r9/rax, fn_ptr' is what we want
        log("  %s  %s  %s, %s" % (hexs(ea), mn, op0, op1))
    nxt = idc.next_head(ea, end)
    if nxt == idaapi.BADADDR:
        break
    ea = nxt

# 2) The Papyrus binder code typically looks like:
#    lea  rax, [Is3DLoaded_lambda]    ; v[10] = lambda
#    mov  [r12+0x50], rax             ; or [v[10]] = lambda
# Capture the immediately-after lea targets and decompile them.

# 3) Decompile sub_141158620 (sz=24) — found from inner scan, common-shape
log("\n--- Decomp candidate near-region small lambdas ---")
for ea in [0x141158620, 0x141158620, 0x141157640, 0x141157EE0,
           0x141157F30, 0x141157FA0, 0x141157FD0, 0x141158070,
           0x141158090, 0x141157DD0, 0x141157DA0]:
    decomp(ea, "lambda candidate @ %s" % hexs(ea))

# 4) Look around the Is3DLoaded string @ 0x1425CDEA8 — strings nearby may
#    show the binding class (Reference, ObjectReference, Actor). Dump
#    surrounding bytes.
log("\n--- Strings near 'Is3DLoaded' @ 0x1425CDEA8 ---")
for delta in range(-0x80, 0x80, 1):
    a = 0x1425CDEA8 + delta
    s = idc.get_strlit_contents(a, -1, idaapi.STRTYPE_C)
    if s:
        try:
            t = s.decode("utf-8", errors="ignore")
            log("  %s: %r" % (hexs(a), t))
        except:
            pass

# 5) DIRECT — find the lambda by looking at native registrar pattern:
#    In FO4 1.11 the pattern is:
#     v6[10] = lambda_fn_ptr;  -- assigning the function pointer to v[10]
#    where v6 is BSScript::NativeFunction1<TESObjectREFR,bool>'s `this`.
#    The decompiled register approach works only if Hex-Rays renders it.
# Find ALL "mov [reg+0x50], r9/rax" patterns near the string xref.

# Let me decompile the entire fn and search the text for "Is3DLoaded".
log("\n--- Full decomp of sub_14115EFB0 — search for Is3DLoaded callsite & nearby lambda assignment ---")
cfunc = ida_hexrays.decompile(0x14115EFB0)
if cfunc:
    code = str(cfunc).split("\n")
    for i, ln in enumerate(code):
        if "Is3DLoaded" in ln:
            log("LINE %d: %s" % (i, ln))
            for j in range(max(0, i-15), min(len(code), i+15)):
                log("  %d: %s" % (j, code[j]))
            log("  ... ...")

# 6) Check the BIGGEST fn xref'd by registrar — sub_14116C7D0 (sz=99)
#    "lea -> 0x14116C7D0 sz=99" — that could be NativeFunction0::ctor
log("\n--- sub_14116C7D0 (likely native fn ctor template) ---")
decomp(0x14116C7D0, "sub_14116C7D0 NativeFunction0 ctor template")

# Save report
with open(LOG_PATH, "w", encoding="utf-8") as fp:
    fp.write("\n".join(out_lines))
print("WROTE", LOG_PATH, "lines=%d" % len(out_lines))
idaapi.qexit(0)
