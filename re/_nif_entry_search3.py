"""Part 3: check simpler wrappers + Actor::Load3D."""
import idc
import idautils
import ida_hexrays
import ida_bytes
import ida_funcs

ida_hexrays.init_hexrays_plugin()

LOG = open(r"C:\Users\filip\Desktop\FalloutWorld\re\_nif_entry_search.log", "a", encoding="utf-8")
DUMP = open(r"C:\Users\filip\Desktop\FalloutWorld\re\_nif_entry_search.dump.log", "a", encoding="utf-8")

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

def decomp(ea):
    try:
        c = ida_hexrays.decompile(ea)
        if c:
            return str(c)
    except Exception as e:
        return f"<fail: {e}>"
    return "<empty>"

# Smallest / simplest wrappers:
# sub_14042D520 — preload? sub_14042D600 — same?
# sub_1406EA280 — another wrapper
# sub_1402D6910 — another
# sub_140434DA0 — another
# sub_1404580C0 — Actor::Load3D entry
# sub_14076C050 — BSTempEffectDebris (likely just takes path + transform)

targets = {
    0x14042D520: "wrapper_14042D520",
    0x14042D600: "wrapper_14042D600",
    0x1406EA280: "wrapper_1406EA280",
    0x14076C050: "wrapper_14076C050_BSTempEffectDebris",
    0x140434DA0: "wrapper_140434DA0",
    0x1402D6910: "wrapper_1402D6910",
    0x1403F7320: "wrapper_1403F7320",
    0x1403FA450: "wrapper_1403FA450",
    0x1404580C0: "wrapper_1404580C0_ActorLoad3D_leaf",
}

log("\n==========================================================")
log("== 16. Wrapper decomps (simplest entries)")
log("==========================================================")
for ea, name in targets.items():
    log(f"\n-- {name} @ 0x{ea:X} --")
    fn_end = idc.get_func_attr(ea, idc.FUNCATTR_END)
    log(f"   size=0x{fn_end-ea:X}")
    d = decomp(ea)
    log(d[:3500])

# Actor::Load3D at sub_140458740
log("\n==========================================================")
log("== 17. sub_140458740 Actor::Load3D-like decomp (large)")
log("==========================================================")
log(decomp(0x140458740)[:6000])

# sub_1404580C0 is a candidate leaf — decomp
log("\n==========================================================")
log("== 18. sub_1404580C0 full decomp (the Actor path wrapper)")
log("==========================================================")
log(decomp(0x1404580C0)[:5000])

# Also let's check how many xrefs to sub_1417B3E90 pass via a REGISTER (r8/rax) rather than stack-lea.
# Specifically: check if there's a xref where r8 is loaded from a global.
# We already saw all vanilla callers lea r8, [rsp+X] — stack-allocated 16-byte structs.
log("\n==========================================================")
log("== 19. Summary: struct layout across vanilla callers")
log("==========================================================")
log("All vanilla sub_1417B3E90 callers pass r8 = lea [rsp+X]")
log("with the following init pattern:")
log("  [X+0..+7] = 0 (QWORD zero via r12/r13/r15/rdi zeroed reg) — in 1 case = 1")
log("  [X+8]     = flag byte (al & mask | or_value)")
log("Common flag patterns observed: 0x2D, 0x2E, 0x2C, 0x28, 0x2A, 0x20, 0x30")
log("All EVEN masks — bit 0 is cleared.")

# Check sub_1417B3480 flag semantics by looking at xrefs to flag bit masks
log("\n-- confirm flag bit 0x10 in sub_1417B3480 = FadeWrap --")
log("(per disasm line 1585 test byte [r15+8], 20h ; 1598 test [r15+8], 2)")
log("(per decomp v10 = (*(v7+8) & 0x20) == 0   --> 0x20 = use dynamic)")
log("(per decomp *(v7+8) & 2  --> 0x02 = d3d lock+bind)")
log("(per decomp *(v7+8) & 0x10 --> 0x10 = FadeWrap)")
log("(per decomp *(v7+8) & 0x08 --> 0x08 = BSModelProcessor post-hook)")

LOG.close()
DUMP.close()
print("DONE3")
idc.qexit(0)
