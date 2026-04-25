"""Depth RE v12 - Decompile specific suspicious CreateDSS caller functions,
and read raw bytes of suspect desc arrays for DepthStencilState.
"""
import idaapi, idautils, idc, ida_funcs, ida_hexrays, ida_bytes, struct

OUT = r"C:\Users\filip\Desktop\FalloutWorld\re\depth_final_report12.txt"
LOG = []
def W(s): LOG.append(str(s)); print(s)
idaapi.auto_wait()
ida_hexrays.init_hexrays_plugin()
imagebase = idaapi.get_imagebase()
def rva(ea): return ea - imagebase

D3D_CMP = {1:"NEVER",2:"LESS",3:"EQUAL",4:"LESS_EQUAL",5:"GREATER",6:"NOT_EQUAL",7:"GREATER_EQUAL",8:"ALWAYS"}

# Approach 1: Look at `sub_140CFAF50` where two DSS creations happen with descs
# at 0x1430e1990 and 0x1430e1998 — only 8 bytes apart!? That's weird.
# Let me read the bytes around 0x1430e1990 as a continuous array and try to parse.
TARGET_FUNC_EAS = [
    0x140CFAF50,  # has 2 calls
    0x14102C820,  # has 1 call
    0x14184C1E0,
    0x141858200,
    0x141B74270,
    0x141CAD6D0,  # big one with 11 calls
    0x141CAF000, 0x141CAF050, 0x141CAF160, 0x141CAF190, 0x141CAF340,
    0x141992470,
    0x141B872B0,
    0x140CA2F50,
    0x140E0D9C0, 0x140E0DAF0,
]

for fn_ea in TARGET_FUNC_EAS:
    try:
        W(f"\n{'='*72}")
        W(f"Function RVA{rva(fn_ea):#x} ({idc.get_func_name(fn_ea)})")
        W("="*72)
        cf = ida_hexrays.decompile(fn_ea)
        if not cf:
            W("  (decompile failed)")
            continue
        src = str(cf)
        lines = src.split("\n")
        W(f"  total lines: {len(lines)}")
        # Show first 80 lines
        for i, line in enumerate(lines[:80]):
            W(f"    {i:3d}: {line}")
        # Also extract lines mentioning interesting things
        W("\n  lines mentioning DSS-relevant keywords:")
        for i, line in enumerate(lines):
            if any(k in line for k in (
                "CreateDepthStencilState", "CreateTexture2D",
                "ClearDepthStencilView", "OMSetDepthStencilState",
                "OMSetRenderTargets",
                "DepthFunc", "DepthEnable", "DepthWrite",
                "D3D11_DEPTH", "lpVtbl", "DSV",
                "(_QWORD *)(*(_QWORD *)",
            )):
                W(f"    {i:4d}: {line}")
    except Exception as e:
        W(f"decompile exception: {e}")

# Also look at the raw data around 0x1430e1990 and related
W("\n" + "="*72)
W("Raw DSS desc blobs examination")
W("="*72)
BLOBS = [
    (0x1430E1960, 0x1430E1A00, "near 0x1430E1990/1998"),
    (0x14326F2E0, 0x14326F380, "near 0x14326F2F0"),
    (0x14307440, 0x14307500, "near 0x143074440 maybe"),
]
for start, end, label in BLOBS:
    W(f"\n-- {label}: {start:#x}..{end:#x} --")
    ea = start
    while ea < end:
        row = []
        for i in range(8):
            dw = idc.get_wide_dword(ea + i*4) or 0
            row.append(f"{dw:08x}")
        W(f"  {ea:#x}: {' '.join(row)}")
        # Also try to interpret as DSS desc
        de = idc.get_wide_dword(ea) or 0
        dm = idc.get_wide_dword(ea+4) or 0
        df = idc.get_wide_dword(ea+8) or 0
        se = idc.get_wide_dword(ea+12) or 0
        sr = ida_bytes.get_byte(ea+16) or 0
        sw = ida_bytes.get_byte(ea+17) or 0
        if de in (0,1) and dm in (0,1) and df in range(1,9):
            W(f"    ?possible DSS: En={de} Mask={dm} Func={df}({D3D_CMP.get(df,'?')}) StEn={se} SR={sr:#x} SW={sw:#x}")
        ea += 0x20

W("\n[DONE]")
with open(OUT, "w", encoding="utf-8") as f: f.write("\n".join(LOG))
idc.qexit(0)
