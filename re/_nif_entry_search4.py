"""Part 4: disasm sub_1404580C0 prolog + check
   if a1/a2 are dereferenced before sub_1417B3E90."""
import idc
import ida_bytes
import ida_hexrays

ida_hexrays.init_hexrays_plugin()

DUMP = open(r"C:\Users\filip\Desktop\FalloutWorld\re\_nif_entry_search.dump.log", "a", encoding="utf-8")
LOG = open(r"C:\Users\filip\Desktop\FalloutWorld\re\_nif_entry_search.log", "a", encoding="utf-8")

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

def log(s=""):
    print(s, flush=True)
    LOG.write(s + "\n")

DUMP.write(f"\n====== sub_1404580C0 PROLOG FULL ======\n")
disasm_n(0x1404580C0, 80, DUMP)

# Also disasm sub_1417B3E90 full body to understand return value usage
DUMP.write(f"\n====== sub_1417B3E90 FULL BODY ======\n")
disasm_n(0x1417B3E90, 180, DUMP)

# Also check: is there a simpler `sub_1417B3D10` (the 5-arg version shown in _check_highlevel)?
# sig from decomp: (char* Source, __int64* a2, __int64 a3) — a3 is opts pointer too
# Decompile it
LOG.write("\n==========================================================\n")
LOG.write("== 20. sub_1417B3D10 decomp (alternative entry)\n")
LOG.write("==========================================================\n")
try:
    c = ida_hexrays.decompile(0x1417B3D10)
    if c:
        LOG.write(str(c)[:3000])
except Exception as e:
    LOG.write(f"fail: {e}\n")

# Caller of 1417B3D10 — see if that's simpler
LOG.write("\n\n-- xrefs to sub_1417B3D10 --\n")
import idautils
for x in idautils.XrefsTo(0x1417B3D10):
    LOG.write(f"  xref 0x{x.frm:X} in {idc.get_func_name(x.frm)} type={x.type}\n")

DUMP.close()
LOG.close()
print("DONE4")
idc.qexit(0)
