"""Hunt the "world-item E-pickup" engine entry (stimpak-on-table, ammo-on-floor,
weapon-leaning-wall -> press E -> goes to player inventory).

Already ruled out:
  - vt[0x7A] AddObjectToContainer (sub_140C7A500) : does NOT fire for
    world-item pickup.  Fires only for container<->player transfers
    (chest, corpse, ContainerMenu).

Working hypothesis: world pickup routes through TESObjectREFR::Activate
(a different vtable slot than 0x7A) OR a dedicated PlayerCharacter
pickup method, OR a non-vt[0x7A] caller of sub_140502940 (AddObject
workhorse).

This script:
  1. Dumps REFR vtable @ RVA 0x2564838 slots 0x50..0x90 with
     first 2500 chars of Hex-Rays decomp each, so we can see which
     slot touches inventory-add logic.
  2. Lists ALL xrefs TO sub_140502940 (AddObject workhorse).  For
     each unique caller, dumps first 2500 chars of decomp.  The
     caller that is NOT vt[0x7A] (sub_140C7A500) and is NOT a
     ContainerMenu path is the world-pickup candidate.
  3. Searches IDB names for "pickup", "pick_up", "activate",
     "pickupobject" case-insensitive.
  4. Searches for string literals inside decomp for "PickUpObject",
     "PickUp", "PutInContainer", "Activate".

Output: re/world_pickup_report.txt
"""
import re
import ida_auto, ida_funcs, ida_hexrays, ida_nalt, ida_pro
import ida_xref, ida_name, ida_bytes, idautils, idc

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\world_pickup_report.txt"

# --- targets ---------------------------------------------------------------
REFR_VTABLE_RVA      = 0x2564838   # TESObjectREFR vtable start
VT_SLOT_FIRST        = 0x50
VT_SLOT_LAST         = 0x90        # inclusive
T_ADDOBJ_WORKHORSE   = 0x0502940   # sub_140502940
T_VT7A_KNOWN         = 0x0C7A500   # sub_140C7A500 = vt[0x7A] AddObjectToContainer (already known)

NAME_SEARCH_PATTERNS = [
    r"pick\s*up",
    r"pickup",
    r"pick_up",
    r"activate",
    r"pickupobject",
    r"steal",
    r"grab",
    r"lootref",
    r"loot_ref",
    r"loot",
]

UI_HINT_STRINGS = [
    "PickUpObject", "PickUp", "Pickup", "PutInContainer",
    "Activate", "Activator", "Steal", "LootRef",
    "Inventory", "AddObject", "Container",
    "ContainerMenu", "Trigger", "Player", "PlayerCharacter",
]

def log(msg, fh):
    print(msg); fh.write(msg + "\n"); fh.flush()


def section(title, fh):
    log("\n" + "=" * 78, fh)
    log(f"== {title}", fh)
    log("=" * 78, fh)


def get_name(ea):
    n = ida_name.get_ea_name(ea)
    return n if n else f"sub_{ea:X}"


def decomp(ea, max_len=2500):
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


def list_xrefs_to(ea):
    """Return list of (caller_fn_start, caller_name, xref_ea)."""
    out = []
    seen = set()
    for xref in idautils.XrefsTo(ea, 0):
        fn = ida_funcs.get_func(xref.frm)
        if fn is None:
            out.append((None, "<no func>", xref.frm))
            continue
        key = fn.start_ea
        if key in seen:
            continue
        seen.add(key)
        out.append((fn.start_ea, get_name(fn.start_ea), xref.frm))
    return out


def scan_ui_hints(decomp_text):
    hits = [s for s in UI_HINT_STRINGS if s.lower() in decomp_text.lower()]
    return hits


def is_vftable_caller(name):
    return "vftable" in name.lower() or "::`vftable'" in name


def dump_vtable_slots(fh, img):
    section(f"(1) REFR vtable RVA=0x{REFR_VTABLE_RVA:X} slots 0x{VT_SLOT_FIRST:X}..0x{VT_SLOT_LAST:X}", fh)
    vt_ea = img + REFR_VTABLE_RVA
    for slot in range(VT_SLOT_FIRST, VT_SLOT_LAST + 1):
        slot_ea = vt_ea + slot * 8
        target = ida_bytes.get_qword(slot_ea)
        if target == 0 or target == 0xFFFFFFFFFFFFFFFF:
            log(f"\n-- slot[0x{slot:X}] @ 0x{slot_ea:X} -> 0x{target:X}  <empty>", fh)
            continue
        rva = target - img
        tname = get_name(target)
        flag = " <== KNOWN vt[0x7A] AddObjectToContainer" if slot == 0x7A else ""
        log(f"\n-- slot[0x{slot:X}] @ 0x{slot_ea:X} -> {tname}  RVA=0x{rva:X}{flag}", fh)
        d = decomp(target, 2500)
        hints = scan_ui_hints(d)
        if hints:
            log(f"   UI-hint strings: {', '.join(hints)}", fh)
        else:
            log(f"   UI-hint strings: <none>", fh)
        log("--- decomp (first 2500 chars) ---", fh)
        log(d, fh)


def dump_xrefs_to_workhorse(fh, img):
    ea = img + T_ADDOBJ_WORKHORSE
    section(f"(2) XREFS TO sub_140502940 (AddObject workhorse) @ 0x{ea:X}", fh)
    xrefs = list_xrefs_to(ea)
    log(f"Found {len(xrefs)} unique caller function(s).", fh)
    vt7a_ea = img + T_VT7A_KNOWN
    for (cea, cname, from_ea) in xrefs:
        if cea is None:
            log(f"\n-- raw xref from 0x{from_ea:X} (no enclosing func)", fh)
            continue
        rva = cea - img
        vflag = " [VTABLE SLOT]" if is_vftable_caller(cname) else ""
        known_flag = ""
        if cea == vt7a_ea:
            known_flag = " <== KNOWN vt[0x7A] AddObjectToContainer (skip)"
        log(f"\n-- caller {cname}  RVA=0x{rva:X}  (xref site 0x{from_ea:X}){vflag}{known_flag}", fh)
        d = decomp(cea, 2500)
        ui_hits = scan_ui_hints(d)
        if ui_hits:
            log(f"   UI-hint strings: {', '.join(ui_hits)}", fh)
        else:
            log(f"   UI-hint strings: <none>", fh)
        log("--- decomp (first 2500 chars) ---", fh)
        log(d, fh)


def scan_name_table(fh, img):
    section("(3) Symbol search: pickup/pick_up/activate/pickupobject/steal/grab/loot", fh)
    patterns = [re.compile(p, re.IGNORECASE) for p in NAME_SEARCH_PATTERNS]
    hits_by_pat = {p.pattern: [] for p in patterns}
    for ea, name in idautils.Names():
        for p in patterns:
            if p.search(name):
                hits_by_pat[p.pattern].append((ea, name))
    for pat_str, hits in hits_by_pat.items():
        log(f"\n--- pattern /{pat_str}/ : {len(hits)} match(es) ---", fh)
        for ea, name in sorted(hits):
            rva = ea - img
            log(f"  {name} @ 0x{ea:X}  RVA=0x{rva:X}", fh)


def dump_activate_candidates(fh, img):
    """Find any name matching 'activate' that looks like TESObjectREFR member
    or Papyrus/AS3 native -- decomp the function to inspect."""
    section("(4) Activate-like candidates: names matching /activate/i -> decomp first 1500 chars", fh)
    pat = re.compile(r"activate", re.IGNORECASE)
    candidates = []
    for ea, name in idautils.Names():
        if pat.search(name) and ida_funcs.get_func(ea) is not None:
            candidates.append((ea, name))
    log(f"Total activate-named functions: {len(candidates)}", fh)
    # Limit to avoid timeout — take first 40 by EA
    candidates.sort()
    for ea, name in candidates[:40]:
        rva = ea - img
        log(f"\n-- {name}  RVA=0x{rva:X}", fh)
        d = decomp(ea, 1500)
        hints = scan_ui_hints(d)
        log(f"   UI-hints: {', '.join(hints) if hints else '<none>'}", fh)
        log("--- decomp (first 1500 chars) ---", fh)
        log(d, fh)


def meta_summary(fh, img):
    section("(5) Meta: callers of workhorse minus known vt[0x7A]", fh)
    ea = img + T_ADDOBJ_WORKHORSE
    vt7a_ea = img + T_VT7A_KNOWN
    xrefs = list_xrefs_to(ea)
    non_vt7a = []
    for (cea, cname, _fea) in xrefs:
        if cea is None:
            continue
        if cea == vt7a_ea:
            continue
        non_vt7a.append((cea, cname))
    log(f"Non-vt[0x7A] unique callers: {len(non_vt7a)}", fh)
    for cea, cname in sorted(non_vt7a):
        rva = cea - img
        d = decomp(cea, 6000)
        hints = scan_ui_hints(d)
        hstr = ",".join(hints) if hints else "-"
        vflag = " [VTABLE SLOT]" if is_vftable_caller(cname) else ""
        log(f"  RVA=0x{rva:X}  {cname}  UI-hints={hstr}{vflag}", fh)


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{img:X}", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] no hexrays plugin available", fh)
        fh.close(); ida_pro.qexit(2)

    # (1) dump REFR vtable slots 0x50..0x90
    dump_vtable_slots(fh, img)

    # (2) xrefs to AddObject workhorse
    dump_xrefs_to_workhorse(fh, img)

    # (3) name-table search
    scan_name_table(fh, img)

    # (4) activate-like candidate decomps
    dump_activate_candidates(fh, img)

    # (5) meta-summary
    meta_summary(fh, img)

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
