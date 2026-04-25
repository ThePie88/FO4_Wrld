"""Find ID3D11DeviceContext::Map / VSSetConstantBuffers / PSSetConstantBuffers
call sites inside Fallout4.exe 1.11.191 — and cluster them by which CB size / name
they write to.

D3D11 COM vtable offsets (x64):
  VSSetConstantBuffers = vt[7]  = 0x38
  PSSetConstantBuffers = vt[16] = 0x80
  GSSetConstantBuffers = vt[22] = 0xB0
  HSSetConstantBuffers = vt[29] = 0xE8
  DSSetConstantBuffers = vt[33] = 0x108
  CSSetConstantBuffers = vt[46] = 0x170
  Map                  = vt[14] = 0x70
  Unmap                = vt[15] = 0x78

Plan:
 1. Find all `call [reg+0x38]` whose reg was loaded from the SAME global pointer
    path that the CB-Map helpers use (0x3E5AE58 / 0x3E5AE70). These are the
    scene-pass VSSetConstantBuffers calls.
 2. Cross-reference each call's register-setup to discover the slot index (rdx)
    and buffer count (r8d) argument values.
 3. Output a list of (function, slot, count, buffer-ptr-origin) tuples.

For FO4NG I expect the engine to call VSSetConstantBuffers once per shader
setup with slots 0..3 in a batched Set call at the start of SetupTechnique.
After confirming that, we can hook the Map helper (simpler) instead of the
vtable thunk.
"""

import idautils
import ida_auto
import ida_funcs
import ida_name
import ida_bytes
import ida_search
import ida_ua
import idc

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\d3d11_cb_sites_report.txt"
IMAGE_BASE = 0x140000000


def log(fh, *a):
    s = " ".join(str(x) for x in a)
    print(s)
    fh.write(s + "\n")


def scan_pattern(pattern, mask=None):
    """Iterate all EAs matching the byte pattern (hex string) in .text."""
    # Use ida_search with proper API
    start = idc.get_segm_by_sel(idc.selector_by_name(".text"))
    # Instead, just brute-force walk every head in .text
    results = []
    end = idc.get_inf_attr(idc.INF_MAX_EA)
    ea = idc.get_inf_attr(idc.INF_MIN_EA)
    while ea != idc.BADADDR and ea < end:
        matched = True
        for i, b in enumerate(pattern):
            if b is None:
                continue
            if ida_bytes.get_byte(ea + i) != b:
                matched = False
                break
        if matched:
            results.append(ea)
        ea += 1
    return results


def find_vtable_calls(fh, vt_off, label, limit=100):
    """Find `call [reg+vt_off]` patterns (short and long forms)."""
    log(fh, f"\n=== {label}: call [reg+{hex(vt_off)}] ===")
    hits = []
    # Short form FF /2 modrm with disp8 (vt_off < 0x80): FF 5X XX
    # ModRM for "call [reg+disp8]": mod=01, reg=010(/2), rm=reg
    # byte0 = FF, byte1 = 01 010 rrr = 0x50 | rrr, byte2 = disp8
    for reg in range(8):
        for rex in [0x48, 0x49, 0x4C, 0x4D, None]:
            if vt_off < 0x80:
                modrm = 0x50 | reg
                pat = []
                if rex is not None:
                    pat.append(rex)
                pat.extend([0xFF, modrm, vt_off])
                for h in scan_pattern(pat):
                    fn = ida_funcs.get_func(h)
                    rv = h - IMAGE_BASE
                    disasm = idc.GetDisasm(h)
                    hits.append((rv, disasm, fn.start_ea - IMAGE_BASE if fn else None))
                    if len(hits) >= limit:
                        break
            else:
                # Long form with disp32: FF 9X XX XX XX XX
                modrm = 0x90 | reg
                pat = []
                if rex is not None:
                    pat.append(rex)
                pat.extend([0xFF, modrm,
                            vt_off & 0xFF,
                            (vt_off >> 8) & 0xFF,
                            (vt_off >> 16) & 0xFF,
                            (vt_off >> 24) & 0xFF])
                for h in scan_pattern(pat):
                    fn = ida_funcs.get_func(h)
                    rv = h - IMAGE_BASE
                    disasm = idc.GetDisasm(h)
                    hits.append((rv, disasm, fn.start_ea - IMAGE_BASE if fn else None))
                    if len(hits) >= limit:
                        break

    # Dedup
    seen = set()
    uniq = []
    for h in hits:
        if h[0] in seen:
            continue
        seen.add(h[0])
        uniq.append(h)
    log(fh, f"  total unique hits: {len(uniq)}  (showing up to {limit})")
    for rv, dis, fn_rv in uniq[:limit]:
        owner = f"in {hex(fn_rv)}" if fn_rv is not None else "(no func)"
        log(fh, f"    {hex(rv):>10s}  {dis:60s}  {owner}")
    return uniq


def xrefs_to_global(fh, rva, label, limit=60):
    log(fh, f"\n=== xrefs TO global @ {hex(rva)} ({label}) ===")
    cnt = 0
    for x in idautils.XrefsTo(IMAGE_BASE + rva):
        fn = ida_funcs.get_func(x.frm)
        log(fh, f"   from {hex(x.frm - IMAGE_BASE):>10s}  "
                f"{idc.GetDisasm(x.frm):60s}  "
                f"func={hex(fn.start_ea - IMAGE_BASE) if fn else '?'}  "
                f"name={ida_funcs.get_func_name(fn.start_ea) if fn else ''}")
        cnt += 1
        if cnt >= limit:
            break


def main():
    ida_auto.auto_wait()
    with open(REPORT, "w", encoding="utf-8") as fh:
        log(fh, "=" * 70)
        log(fh, "FO4 1.11.191 D3D11 CB site enumeration")
        log(fh, "=" * 70)

        # Find all vtable calls for relevant CB-related methods
        find_vtable_calls(fh, 0x38, "VSSetConstantBuffers (vt[7])", 300)
        find_vtable_calls(fh, 0x70, "Map (vt[14])", 300)
        find_vtable_calls(fh, 0x78, "Unmap (vt[15])", 300)
        find_vtable_calls(fh, 0x80, "PSSetConstantBuffers (vt[16])", 300)
        find_vtable_calls(fh, 0xB0, "GSSetConstantBuffers (vt[22])", 100)
        find_vtable_calls(fh, 0x170, "CSSetConstantBuffers (vt[46])", 100)

        # Xrefs to the CB pointer globals we discovered
        xrefs_to_global(fh, 0x3E5AE58, "CB global ptr A (PerTechnique?)", 60)
        xrefs_to_global(fh, 0x3E5AE70, "CB global ptr B (PerMaterial?)", 60)
        xrefs_to_global(fh, 0x3A0F400, "CB descriptor table?", 60)

        log(fh, "\n[done]")


main()
