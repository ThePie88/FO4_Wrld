"""Decomp sub_14031C310 — strong candidate for the PUT path.

Rationale: it's one of only 2 functions (besides vt[0x7A] itself) that
calls sub_1405007B0 (the AddObject inner worker), and it calls it TWICE
(at 0x31C811 + 0x31C898). Two sequential AddObject calls in one function
== "transfer from A to B" pattern.

Also decomp:
  - RemoveItemFunctor::operator() (one of the slots in the vtable at
    0x25C45F8 — try slot [1] which is usually operator() or dtor)
  - AddItemFunctor::operator() (vtable at 0x25C4598)
"""
import ida_auto, ida_funcs, ida_hexrays, ida_nalt, ida_pro, ida_bytes, ida_name

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\put_candidate_report.txt"


def log(msg, fh):
    print(msg); fh.write(msg + "\n"); fh.flush()


def decomp(ea, max_len=15000):
    fn = ida_funcs.get_func(ea)
    if fn is None: return f"<no func at 0x{ea:X}>"
    try:
        cf = ida_hexrays.decompile(fn.start_ea)
        if cf is None: return "<decomp failed>"
        s = str(cf)
        return s if len(s) <= max_len else s[:max_len] + "\n...<truncated>"
    except Exception as e:
        return f"<decomp err: {e}>"


def read_q(ea): return ida_bytes.get_qword(ea)


def get_name(ea):
    n = ida_name.get_ea_name(ea)
    return n if n else f"sub_{ea:X}"


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    ida_auto.auto_wait()
    img = ida_nalt.get_imagebase()
    log(f"[+] Image base: 0x{img:X}\n", fh)
    if not ida_hexrays.init_hexrays_plugin():
        log("[-] no hexrays", fh); fh.close(); ida_pro.qexit(2)

    # T1: sub_14031C310 — the strong PUT candidate
    log("=" * 72, fh)
    log("== sub_14031C310 (calls sub_1405007B0 twice — transfer pattern)", fh)
    log("=" * 72, fh)
    log(decomp(img + 0x31C310, 20000), fh)

    # T2: AddItemFunctor vtable slots
    log("\n" + "=" * 72, fh)
    log("== AddItemFunctor vtable @ RVA 0x25C4598", fh)
    log("=" * 72, fh)
    vt_add = img + 0x25C4598
    for i in range(6):
        slot_ea = vt_add + i * 8
        t = read_q(slot_ea)
        log(f"\n--- slot[{i}] -> 0x{t:X} (RVA 0x{t-img:X})  {get_name(t)} ---", fh)
        log(decomp(t, 8000), fh)

    # T3: RemoveItemFunctor vtable slots
    log("\n" + "=" * 72, fh)
    log("== RemoveItemFunctor vtable @ RVA 0x25C45F8", fh)
    log("=" * 72, fh)
    vt_rem = img + 0x25C45F8
    for i in range(6):
        slot_ea = vt_rem + i * 8
        t = read_q(slot_ea)
        log(f"\n--- slot[{i}] -> 0x{t:X} (RVA 0x{t-img:X})  {get_name(t)} ---", fh)
        log(decomp(t, 8000), fh)

    log("\n==== done ====", fh)
    fh.close()
    ida_pro.qexit(0)


main()
