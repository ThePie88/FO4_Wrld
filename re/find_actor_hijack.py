"""
Locate Papyrus natives and helper functions relevant to actor hijacking:
 - PlaceAtMe / PlaceActorAtMe / PlaceLeveledActorAtMe (spawn actors at will)
 - MoveTo / SetPosition (teleport across cells)
 - SetRace / SetOutfit / SetCombatStyle (appearance / equipment / AI swap)
 - StopCombat / StopCombatAlarmOnActor / EvaluatePackage / SetAlly / IsHostile / SetIgnoreFriendlyHits
 - ToggleCombatAI / ToggleAI console commands

Emit to actor_hijack_raw.txt, one block per string anchor. Try to resolve
the native function pointer by searching for a nearby 'lea rax, sub_XXX'
after the xref (Papyrus registrar pattern).
"""
import ida_auto
import ida_funcs
import ida_hexrays
import ida_nalt
import idc
import idautils
import ida_pro

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\actor_hijack_raw.txt"

TARGETS = [
    # Spawn
    "PlaceAtMe",
    "PlaceActorAtMe",
    "PlaceLeveledActorAtMe",
    # Teleport
    "MoveTo",
    "SetPosition",
    # Appearance / equipment
    "SetRace",
    "SetOutfit",
    "SetCombatStyle",
    # AI / combat
    "StopCombat",
    "StopCombatAlarmOnActor",
    "EvaluatePackage",
    "SetAlly",
    "IgnoreFriendlyHits",
    "SetIgnoreFriendlyHits",
    "IsHostileToActor",
    "IsInCombat",
    "GetCurrentAIPackage",
    # Ref lifecycle
    "Disable",
    "Enable",
    "Delete",
    "MarkForDelete",
    # Console
    "ToggleCombatAI",
    "ToggleAI",
]


def log(msg, fh):
    print(msg)
    fh.write(msg + "\n")
    fh.flush()


def find_native_after_xref(xref_ea, fh, prefix="    "):
    """After a Papyrus registrar xref, look 1..40 insns forward for 'lea rax, sub_XXX'
    which is the native function pointer.
    Returns (native_ea, lea_site) or (None, None)."""
    cur = xref_ea
    for _ in range(40):
        cur = idc.next_head(cur)
        if cur == idc.BADADDR:
            break
        mnem = idc.print_insn_mnem(cur)
        if mnem == "lea":
            op1 = idc.print_operand(cur, 1)
            if op1.startswith("sub_"):
                native_ea = idc.get_operand_value(cur, 1)
                return native_ea, cur
        # Don't wander too far; ret usually ends the arg setup block
        if mnem == "ret":
            break
    return None, None


def decompile_short(ea, fh, max_lines=60, prefix="    "):
    try:
        fn = ida_funcs.get_func(ea)
        if not fn:
            return
        cf = ida_hexrays.decompile(fn.start_ea)
        if not cf:
            return
        src = str(cf)
        nlines = src.count("\n")
        if nlines <= max_lines:
            log(prefix + "--- decompile ({} lines) ---".format(nlines), fh)
            log(src, fh)
            log(prefix + "---", fh)
        else:
            log(prefix + "[decomp too long: {} lines, skipping]".format(nlines), fh)
    except Exception as e:
        log(prefix + "decompile error: " + str(e), fh)


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log("[+] Image base: 0x{:X}".format(img), fh)

    if not ida_hexrays.init_hexrays_plugin():
        log("[-] Hex-Rays unavailable", fh)
        fh.close()
        ida_pro.qexit(2)
        return

    log("[*] Enumerating strings...", fh)
    strs = list(idautils.Strings())
    log("[+] Total strings: {}".format(len(strs)), fh)

    # Gather exact-string hits
    hits = {t: [] for t in TARGETS}
    for s in strs:
        try:
            txt = str(s)
        except Exception:
            continue
        if txt in hits:
            hits[txt].append(s.ea)

    for t in TARGETS:
        ea_list = hits[t]
        log("\n==== {!r}: {} string hit(s) ====".format(t, len(ea_list)), fh)
        for sea in ea_list:
            log("  string @ 0x{:X} (RVA 0x{:X})".format(sea, sea - img), fh)
            xrefs = list(idautils.XrefsTo(sea, 0))
            log("    xrefs: {}".format(len(xrefs)), fh)
            for x in xrefs[:8]:
                fn = ida_funcs.get_func(x.frm)
                fn_ea = fn.start_ea if fn else 0
                log("    xref 0x{:X} (RVA 0x{:X}) in func RVA 0x{:X}".format(
                    x.frm, x.frm - img, (fn_ea - img) if fn_ea else 0), fh)
                native_ea, lea_site = find_native_after_xref(x.frm, fh)
                if native_ea:
                    log("      → native sub_{:X} @ 0x{:X} (RVA 0x{:X})  (lea @ 0x{:X})".format(
                        native_ea, native_ea, native_ea - img, lea_site), fh)
                    decompile_short(native_ea, fh)

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
