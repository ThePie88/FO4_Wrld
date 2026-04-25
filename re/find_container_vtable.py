r"""Extract TESObjectREFR virtual methods for container ops.

From the community research (CommonLibF4 conventions, current master tracks NG):
  vt[0x6D] = RemoveItem(RemoveItemData&)
  vt[0x7A] = AddObjectToContainer(TESBoundObject*, sp<ExtraDataList>, int count,
                                   TESObjectREFR* oldContainer, ITEM_REMOVE_REASON)

TESObjectREFR vtable RVA is known to be 0x2564838 (from reference_fo4_offsets.md).

Strategy:
  1. Dump vtable entries [0x68..0x80] (covers both targets + a few neighbors).
  2. Decompile vt[0x6D] and vt[0x7A].
  3. Print neighbor decomps so I can SANITY-CHECK that the indices match
     the expected signatures (RemoveItem takes 1 arg, AddObjectToContainer
     takes 5 post-`this`). If vt[0x7A] looks wrong, the neighboring ones
     help me spot where the real one is.

Reference: reference_fo4_offsets.md: PlayerCharacter vtable RVA 0x2564838,
which is the SAME vtable as TESObjectREFR up to PlayerCharacter's overrides
(single inheritance). The container-op slots are overridden at the REFR level,
so dumping from 0x2564838 reveals either REFR's own method or a higher-level
Actor override — both are valid hook points for player-initiated transfers.
"""
import ida_auto
import ida_funcs
import ida_hexrays
import ida_nalt
import idc
import ida_pro

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\container_vtable_report.txt"

# TESObjectREFR / PlayerCharacter vtable (same prefix due to single inheritance
# from TESObjectREFR -> Actor -> Character -> PlayerCharacter).
VTABLE_RVA = 0x2564838

# Slots to dump. 0x6D = RemoveItem expected, 0x7A = AddObjectToContainer.
# Bracket them with a wide range so I can visually confirm the right index.
SLOT_RANGE = range(0x60, 0x88)

# Slots to deeply decompile
DEEP_SLOTS = [0x6D, 0x7A]


def log(msg, fh):
    print(msg); fh.write(msg + "\n"); fh.flush()


def decompile_safely(ea, max_len=3500):
    fn = ida_funcs.get_func(ea)
    if fn is None:
        return f"<no func at 0x{ea:X}>"
    try:
        cf = ida_hexrays.decompile(fn.start_ea)
        if cf is None:
            return "<decomp failed>"
        src = str(cf)
        return src if len(src) <= max_len else src[:max_len] + "\n...<truncated>"
    except Exception as e:
        return f"<decomp err: {e}>"


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{img:X}", fh)
    log(f"[+] Vtable base: 0x{img + VTABLE_RVA:X} (RVA 0x{VTABLE_RVA:X})\n", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] no hexrays", fh); fh.close(); ida_pro.qexit(2)

    vt_ea = img + VTABLE_RVA
    log("==== Vtable slot listing ====", fh)
    for slot in SLOT_RANGE:
        ea = vt_ea + slot * 8
        ptr = idc.get_qword(ea)
        if ptr == 0 or ptr == idc.BADADDR:
            log(f"  [0x{slot:02X}] = <empty/invalid>", fh); continue
        rva = ptr - img
        marker = "  **" if slot in DEEP_SLOTS else "    "
        log(f"{marker}[0x{slot:02X}] -> 0x{ptr:X} (RVA 0x{rva:X})", fh)

    for slot in DEEP_SLOTS:
        ea = vt_ea + slot * 8
        ptr = idc.get_qword(ea)
        if ptr == 0 or ptr == idc.BADADDR:
            log(f"\n==== vt[0x{slot:02X}] : <empty> ====", fh); continue
        log(f"\n==== vt[0x{slot:02X}] @ RVA 0x{ptr - img:X} ====", fh)
        log(decompile_safely(ptr), fh)

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
