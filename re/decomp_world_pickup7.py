"""Hunt the REAL world-pickup (E-button) entry.

Prior scripts found:
  - sub_140CA7D20 = event-133 handler reached via sub_140C4CE00 main-thread
    pump. Adds item, shows HUD toast "%s %s".
  - sub_140C4C9A0 = event-133 producer wrapper (enqueues case 133).
  - Only code caller of the producer is sub_1410F80A0 (Papyrus EquipItem
    native wrapper). So event 133 is the "equip-time item-add" path.
  - That's NOT what we want.  E-press pickup MUST go elsewhere.

New strategy:
  1. Look at the BGSProcedureActivate vftable @ RVA 0x2505C00 and its
     Execute / Run method — that's the AI behavior "procedure activate"
     which the PlayerCharacter Activate also hits.
  2. Check ActionActivateDoneHandler vftable @ RVA 0x256C2F8 and its
     HandleEvent method.
  3. Look at "PlayerActivatePickRefEvent" — the input event that the
     player activation sink processes. Its BSTEventSink vftable is
     at RVA 0x25291E8.  The 2nd virtual of a BSTEventSink is ProcessEvent.
  4. Check the REFR virtual "Activate" slot — in Skyrim it is slot 0x37,
     but FO4 next-gen may have moved it. Let's scan REFR vtable slots
     0x00..0x50 AND 0x90..0x110 for anything that references AddObject
     workhorse (sub_140502940) or qword_1431E2D50 (player ptr).
  5. From the list of 34 callers of sub_140502940, pick the ones we
     did NOT yet inspect that have plausible "activate"/"take" feel.

Output: re/world_pickup_report7.txt
"""
import ida_auto, ida_funcs, ida_hexrays, ida_nalt, ida_pro
import ida_xref, ida_name, ida_bytes, idautils, idc

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\world_pickup_report7.txt"

REFR_VTABLE_RVA = 0x2564838
T_WORKHORSE = 0x502940

# Interesting vtables from strings scan
VFT_BGSPROCEDUREACTIVATE = 0x2505C00
VFT_BGSPROCACTIVATEEXEC  = 0x2505DA8
VFT_ACTIONACTIVATEDONE   = 0x256C2F8
VFT_PLAYERACTSINK        = 0x25291E8   # BSTEventSink<PlayerActivatePickRefEvent>
VFT_MULTISINK            = 0x252B1A8
VFT_ACTIVATEHANDLER      = 0x2569CA8


def log(msg, fh):
    print(msg); fh.write(msg + "\n"); fh.flush()


def section(title, fh):
    log("\n" + "=" * 78, fh)
    log(f"== {title}", fh)
    log("=" * 78, fh)


def get_name(ea):
    n = ida_name.get_ea_name(ea)
    return n if n else f"sub_{ea:X}"


def decomp(ea, max_len=3500):
    fn = ida_funcs.get_func(ea)
    if fn is None:
        return f"<no func at 0x{ea:X}>"
    try:
        cf = ida_hexrays.decompile(fn.start_ea)
        if cf is None:
            return "<decomp failed>"
        s = str(cf)
        return s if len(s) <= max_len else s[:max_len] + "\n...<truncated>"
    except Exception as e:
        return f"<decomp err: {e}>"


def dump_vtable_slots(name, vftable_rva, n_slots, fh, img):
    section(f"Vtable {name} @ RVA=0x{vftable_rva:X} first {n_slots} slots", fh)
    base = img + vftable_rva
    for i in range(n_slots):
        slot = base + i * 8
        tgt = ida_bytes.get_qword(slot)
        if tgt == 0 or tgt == 0xFFFFFFFFFFFFFFFF:
            log(f"  slot[{i}] @ 0x{slot:X} -> <empty>", fh)
            continue
        rva = tgt - img
        log(f"  slot[{i}] @ 0x{slot:X} -> {get_name(tgt)}  RVA=0x{rva:X}", fh)


def dump_vtable_slot_decomp(name, vftable_rva, slot_index, fh, img):
    slot = img + vftable_rva + slot_index * 8
    tgt = ida_bytes.get_qword(slot)
    section(f"Vtable {name} slot[{slot_index}] -> {get_name(tgt)}  RVA=0x{tgt-img:X}", fh)
    log(decomp(tgt, 3500), fh)


def scan_refr_vtable_for_workhorse(img, fh):
    """Scan REFR vtable slots 0..0x120 and check if the target decomp calls
    sub_140502940 (AddObject workhorse)."""
    section("Scan REFR vtable (full) for slots whose decomp references sub_140502940 OR qword_1431E2D50", fh)
    wh_ea = img + T_WORKHORSE
    player_ptr2 = img + 0x31E2D50
    player_ptr1 = img + 0x32D2260
    base = img + REFR_VTABLE_RVA
    for i in range(0, 0x120):
        slot = base + i * 8
        tgt = ida_bytes.get_qword(slot)
        if tgt == 0 or tgt == 0xFFFFFFFFFFFFFFFF:
            continue
        d = decomp(tgt, 6000)
        if not isinstance(d, str):
            continue
        hits = []
        if f"sub_{wh_ea:X}" in d or "sub_140502940" in d:
            hits.append("workhorse")
        if "qword_1431E2D50" in d or f"{player_ptr2:X}" in d:
            hits.append("playerPtr2@1431E2D50")
        if "qword_1432D2260" in d or f"{player_ptr1:X}" in d:
            hits.append("playerPtr1@1432D2260")
        if "PickUp" in d or "Pickup" in d or "pickup" in d:
            hits.append("PickUp-string")
        if hits:
            log(f"\n  slot[0x{i:X}] -> {get_name(tgt)}  RVA=0x{tgt-img:X}  HITS: {','.join(hits)}", fh)
            log(f"  --- decomp first 2500 chars ---", fh)
            log(d[:2500], fh)


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{img:X}", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] no hexrays plugin available", fh)
        fh.close(); ida_pro.qexit(2)

    # Scan full REFR vtable for activate/pickup-smelling slots
    scan_refr_vtable_for_workhorse(img, fh)

    # Show BGSProcedureActivate vtable first 20 slots
    dump_vtable_slots("BGSProcedureActivate", VFT_BGSPROCEDUREACTIVATE, 20, fh, img)
    dump_vtable_slots("BGSProcedureActivateExecState", VFT_BGSPROCACTIVATEEXEC, 20, fh, img)
    dump_vtable_slots("ActionActivateDoneHandler", VFT_ACTIONACTIVATEDONE, 15, fh, img)
    dump_vtable_slots("BSTEventSink<PlayerActivatePickRefEvent>", VFT_PLAYERACTSINK, 5, fh, img)
    dump_vtable_slots("BSTEventSink<MultiActivateUseRolloverEvent>", VFT_MULTISINK, 5, fh, img)
    dump_vtable_slots("ActivateHandler", VFT_ACTIVATEHANDLER, 10, fh, img)

    # Decomp the BGSProcedureActivate Execute/Run
    # In Skyrim IProcedure pattern: slot[1]=Run, slot[0]=dtor
    dump_vtable_slot_decomp("BGSProcedureActivate", VFT_BGSPROCEDUREACTIVATE, 1, fh, img)
    dump_vtable_slot_decomp("BGSProcedureActivate", VFT_BGSPROCEDUREACTIVATE, 2, fh, img)
    dump_vtable_slot_decomp("BGSProcedureActivate", VFT_BGSPROCEDUREACTIVATE, 3, fh, img)
    # ExecState Run is typically slot[2] or [3]
    dump_vtable_slot_decomp("BGSProcedureActivateExecState", VFT_BGSPROCACTIVATEEXEC, 1, fh, img)
    dump_vtable_slot_decomp("BGSProcedureActivateExecState", VFT_BGSPROCACTIVATEEXEC, 2, fh, img)
    dump_vtable_slot_decomp("BGSProcedureActivateExecState", VFT_BGSPROCACTIVATEEXEC, 3, fh, img)
    # Event sink ProcessEvent is usually slot[1]
    dump_vtable_slot_decomp("BSTEventSink<PlayerActivatePickRefEvent>", VFT_PLAYERACTSINK, 1, fh, img)

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
