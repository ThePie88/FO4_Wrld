"""
Cerca stringhe per rotazione e animation state, decompila natives/handler.
"""
import ida_auto
import ida_funcs
import ida_hexrays
import ida_nalt
import idc
import idautils
import ida_pro

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\rotation_anim_report.txt"

def log(msg, fh):
    print(msg)
    fh.write(msg + "\n")
    fh.flush()

def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{img:X}", fh)

    if not ida_hexrays.init_hexrays_plugin():
        log("[-] Hex-Rays unavailable", fh)
        fh.close()
        ida_pro.qexit(2)

    # Lista di strings anchor
    targets = {
        # Rotation
        "GetAngleX":     "Papyrus Actor.GetAngleX",
        "GetAngleY":     "Papyrus Actor.GetAngleY",
        "GetAngleZ":     "Papyrus Actor.GetAngleZ",
        "SetAngle":      "Papyrus SetAngle",
        "GetAngle":      "Console GetAngle",
        # Animation
        "GetAnimationVariableBool": "Papyrus GetAnimationVariableBool",
        "IsRunning":     "Papyrus IsRunning",
        "IsSprinting":   "Papyrus IsSprinting",
        "IsSneaking":    "Papyrus IsSneaking",
        "IsWalking":     "Papyrus IsWalking",
        "IsInCombat":    "Papyrus IsInCombat",
        "GetMovementDirection": "Papyrus GetMovementDirection",
        "IsWeaponDrawn": "Papyrus IsWeaponDrawn",
    }

    log("[*] Enumerating strings...", fh)
    strs = list(idautils.Strings())
    log(f"[+] Total strings: {len(strs)}", fh)

    found = {}
    for s in strs:
        try:
            txt = str(s)
        except Exception:
            continue
        if txt in targets:
            found.setdefault(txt, []).append(s.ea)

    # Per ogni string trovata, lista xref e se è chiamato Papyrus register pattern (lea rdx, string),
    # cerca l'istruzione "lea rax, sub_XXXXXX" 4-20 byte dopo — è il function pointer nativo
    for needle, label in targets.items():
        hits = found.get(needle, [])
        log(f"\n[+] {label!r}: {len(hits)} hits", fh)
        for h in hits:
            log(f"    string at 0x{h:X} (RVA 0x{h - img:X})", fh)
            xrefs = list(idautils.XrefsTo(h, 0))
            for x in xrefs[:5]:
                log(f"    xref from 0x{x.frm:X} (RVA 0x{x.frm - img:X})", fh)
                # Cerca "lea rax, sub_XXX" entro 30 istruzioni dopo (NativeFunction0 setup)
                cur = x.frm
                for _ in range(20):
                    cur = idc.next_head(cur)
                    if cur == idc.BADADDR:
                        break
                    mnem = idc.print_insn_mnem(cur)
                    if mnem == "lea":
                        op1 = idc.print_operand(cur, 1)
                        # sub_ references → candidate native
                        if op1.startswith("sub_"):
                            target_ea = idc.get_operand_value(cur, 1)
                            log(f"      → candidate native: {op1} @ 0x{target_ea:X} (from 0x{cur:X})", fh)
                            # Decompila
                            try:
                                fn = ida_funcs.get_func(target_ea)
                                if fn:
                                    cf = ida_hexrays.decompile(fn.start_ea)
                                    if cf:
                                        src = str(cf)
                                        # Log solo se la funzione è corta (true native spesso < 20 righe)
                                        nlines = src.count("\n")
                                        if nlines < 40:
                                            log(f"      --- Decompiled (short, {nlines} lines) ---", fh)
                                            log(src, fh)
                                            log(f"      --- end ---", fh)
                                        else:
                                            log(f"      [ decompiled but too long ({nlines} lines), skipping print ]", fh)
                            except Exception as e:
                                log(f"      decompile error: {e}", fh)
                            break

    log("\n==== Report complete ====", fh)
    fh.close()
    ida_pro.qexit(0)

main()
