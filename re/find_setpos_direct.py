"""Find a VM-free path to teleport a REFR:
  A. The console command 'setpos' exec handler — direct engine call,
     takes (ref, axis, value) per the vanilla console form.
  B. The SetPositionFunctor::Execute virtual method — processed by the
     deferred-op queue, no Papyrus VM context needed to invoke.
"""
import ida_auto
import ida_funcs
import ida_hexrays
import ida_nalt
import idc
import idautils
import ida_pro

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\setpos_direct_report.txt"


def log(msg, fh):
    print(msg); fh.write(msg + "\n"); fh.flush()


def decompile(rva, img, fh, max_len=3500):
    ea = img + rva
    fn = ida_funcs.get_func(ea)
    if fn is None:
        log(f"  <no func at 0x{ea:X}>", fh); return
    try:
        cf = ida_hexrays.decompile(fn.start_ea)
        if cf is None:
            log("  <decomp failed>", fh); return
        src = str(cf)
        if len(src) > max_len: src = src[:max_len] + "\n...<truncated>"
        log(src, fh)
    except Exception as e:
        log(f"  <decomp err: {e}>", fh)


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{img:X}\n", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] no hexrays", fh); fh.close(); ida_pro.qexit(2)

    strs = list(idautils.Strings())

    # ---- A. Console command 'SetPos' / 'setpos' lookup ----
    # Console commands are registered with their name as a string. The exec
    # function pointer lives in the registration struct a few fields away.
    # Common casing variants.
    log("==== A. Console command 'setpos' ====", fh)
    console_names = ["SetPos", "setpos", "SetPosition", "setposition"]
    for name in console_names:
        hits = [s.ea for s in strs if str(s) == name]
        if not hits: continue
        log(f"  string {name!r}: {len(hits)} hit(s)", fh)
        for h in hits:
            log(f"    @ 0x{h:X} (RVA 0x{h - img:X})", fh)
            xrefs = list(idautils.XrefsTo(h, 0))
            for x in xrefs[:4]:
                fn = ida_funcs.get_func(x.frm)
                fn_label = f"func 0x{fn.start_ea:X}" if fn else "<no func>"
                log(f"      xref 0x{x.frm:X} in {fn_label}", fh)
                # If the xref is in a data section (console table), the
                # entry layout typically has the exec fn pointer some bytes
                # ahead. Dump 40 bytes after the string ref in data.
                # But easier: if no func, treat as data table.
                if fn is None:
                    # Scan forward 0x40 bytes for qwords that look like
                    # function pointers (in .text section).
                    for off in range(0, 0x40, 8):
                        qw = idc.get_qword(x.frm + off)
                        if qw == idc.BADADDR or qw == 0: continue
                        # Check if qw looks like a code pointer
                        if idc.get_segm_name(qw) == ".text":
                            fn2 = ida_funcs.get_func(qw)
                            if fn2 and fn2.start_ea == qw:
                                log(f"        data+0x{off:02X} -> possible fn 0x{qw:X} "
                                    f"(RVA 0x{qw - img:X})", fh)

    # ---- B. SetPositionFunctor vtable / Execute method ----
    # We know from sub_14115D9E0 that a SetPositionFunctor is constructed
    # via a vtable pointer. The vtable is labeled by IDA as something like
    # "??_7?$SetPositionFunctor@..." — search names for it.
    log("\n==== B. SetPositionFunctor vtable lookup ====", fh)
    for name_ea, name in idautils.Names():
        if "SetPositionFunctor" in name and "vftable" in name:
            log(f"  vtable @ 0x{name_ea:X} (RVA 0x{name_ea - img:X})  name={name!r}", fh)
            # Read first 8 qwords — these are virtual method pointers
            for i in range(8):
                ptr = idc.get_qword(name_ea + i * 8)
                if ptr == idc.BADADDR: break
                if ptr == 0:
                    log(f"    vtable[{i}] = 0", fh); break
                if idc.get_segm_name(ptr) != ".text":
                    # Not a code pointer — probably past end of vtable
                    break
                log(f"    vtable[{i}] = 0x{ptr:X} (RVA 0x{ptr - img:X})", fh)
                # Decompile each — first non-dtor is usually Execute/Run
                log(f"      --- decomp ---", fh)
                decompile(ptr - img, img, fh, max_len=1500)
                log(f"      ---", fh)

    # ---- C. Also look for related MoveToBaseFunctor (we saw it in the
    #          SetPosition decomp — might share Execute semantics) ----
    log("\n==== C. MoveToBaseFunctor vtable (related) ====", fh)
    for name_ea, name in idautils.Names():
        if "MoveToBaseFunctor" in name and "vftable" in name:
            log(f"  vtable @ 0x{name_ea:X} (RVA 0x{name_ea - img:X})  name={name!r}", fh)
            for i in range(5):
                ptr = idc.get_qword(name_ea + i * 8)
                if ptr == idc.BADADDR or ptr == 0: break
                if idc.get_segm_name(ptr) != ".text": break
                log(f"    vtable[{i}] = 0x{ptr:X} (RVA 0x{ptr - img:X})", fh)

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
