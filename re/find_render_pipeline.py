"""
find_render_pipeline.py
Locate UI/scene transition in Fallout4.exe (1.11.191 NG).

Strategy:
 1. Find ID3D11DeviceContext::OMSetRenderTargets via the IAT / delay-load (D3D11 is dynamically
    dispatched through the vtable, so we instead count callers of the context vtable slot +0x20).
    We'll take a different tack: find every xref to __imp_D3D11CreateDevice etc. isn't helpful.
    Instead we use string anchors that are CERTAIN:
       - "Scaleform::Render::HAL::BeginFrame"
       - "Scaleform::Render::HAL::BeginScene"
       - "Scaleform::Render::D3D1x::HAL::PushRenderTarget"
       - "DuringMainRenderJobList"
       - "PostMainRenderJobList"
       - "Composite/AlphaRenderJobList"
       - "WaitDFComposite"
       - "DFComposite"
       - "BSShaderAccumulator"
       - "BSBatchRenderer"
       - "ShadowSceneNode"
    These strings are debug/logging identifiers almost always referenced by the function that
    owns them (e.g. vtable EndFrame handler or SetName calls). We follow xrefs to the callers
    to locate the render orchestrator.

 2. For each anchor, list the callers. The render loop is the function with MULTIPLE of those
    anchors in the same call graph root. We walk up the call tree (up to 3 hops) and find the
    common ancestor.

 3. We also enumerate functions that call ID3D11DeviceContext vtable slot 33 (OMSetRenderTargets
    is slot 33 = 0x108 for x64). We can't do that by name (dynamic vtable) but we CAN identify
    a context pointer by finding a singleton load + call [rax+0x108].

 4. Output: for each anchor, string EA / RVA, 1st-level callers with RVA, function size.
"""

import ida_auto
import ida_bytes
import ida_funcs
import ida_nalt
import ida_segment
import ida_xref
import ida_name
import idautils
import idc
import ida_pro

REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\render_pipeline_anchors.txt"

ANCHORS = [
    # Scaleform render HAL — UI pipeline entry points
    "Scaleform::Render::HAL::BeginFrame",
    "Scaleform::Render::HAL::BeginScene",
    "Scaleform::Render::HAL::beginDisplay",
    "Scaleform::Render::D3D1x::HAL::PushRenderTarget",
    "Scaleform::Render::D3D1x::HAL::applyDepthStencilMode",
    # Creation Engine main render loop markers (job list names)
    "DuringMainRenderJobList",
    "PostMainRenderJobList",
    "PostAllRenderJobList",
    "Composite/AlphaRenderJobList",
    "WaitDFComposite",
    # Scene-end / composition markers
    "DFComposite",
    "BSDFComposite",
    "BSShaderAccumulator",
    "BSBatchRenderer",
    "ShadowSceneNode",
    # UI hand-off candidates
    "BSScaleformManager",
    "Scaleform allocator",
    # Profiler tags that bracket frame phases
    "TtpEndFrame",
    "EndFrameRateCapture",
]


def log(fh, msg):
    print(msg)
    fh.write(msg + "\n")
    fh.flush()


def rva(ea):
    return ea - ida_nalt.get_imagebase()


def find_string_ea(needle, strs):
    hits = []
    for s in strs:
        try:
            if str(s) == needle:
                hits.append(s.ea)
        except Exception:
            pass
    return hits


def list_callers(ea, fh, depth=0, max_depth=2, seen=None):
    """Walk up xrefs. `ea` can be a string EA, function EA, or mid-function EA."""
    if seen is None:
        seen = set()
    if depth > max_depth:
        return
    for x in idautils.XrefsTo(ea, 0):
        frm = x.frm
        fn = ida_funcs.get_func(frm)
        if fn is None:
            log(fh, f"    {'  '*depth}xref from 0x{frm:X} (RVA 0x{rva(frm):X}) — NO FUNC")
            continue
        fs = fn.start_ea
        if fs in seen:
            continue
        seen.add(fs)
        name = ida_funcs.get_func_name(fs) or "?"
        size = fn.end_ea - fs
        log(fh, f"    {'  '*depth}CALLER 0x{fs:X} (RVA 0x{rva(fs):X}) size=0x{size:X} name={name} (from 0x{frm:X})")
        # recurse one level up from the function ENTRY
        if depth < max_depth:
            list_callers(fs, fh, depth + 1, max_depth, seen)


def find_context_vtbl_uses(fh, slot_offsets):
    """
    Best-effort: scan text section for 'call [reg+offset]' patterns that likely indicate
    ID3D11DeviceContext vtable slot calls.  slot_offsets are bytes where known slots live:
       OMSetRenderTargets                   = slot 33 => 0x108
       OMSetRenderTargetsAndUnorderedAccessViews = slot 34 => 0x110
       ClearRenderTargetView                = slot 50 => 0x188
       ClearDepthStencilView                = slot 53 => 0x1A0
       Draw                                 = slot 13 => 0x68
       DrawIndexed                          = slot 12 => 0x60
       Map                                  = slot 14 => 0x70
       PSSetShaderResources                 = slot 8  => 0x40
    We scan the .text segment for the encoded displacement.  x64 call [rax+imm32]
    = FF 90 imm32 (if reg=rax).  We simply count occurrences of each displacement
    across the text segment as a heuristic.
    """
    text = ida_segment.get_segm_by_name(".text")
    if text is None:
        log(fh, "[!] .text segment not found")
        return
    log(fh, f"[+] Scanning .text 0x{text.start_ea:X}..0x{text.end_ea:X} for vtable slot calls (heuristic)")

    counts = {name: 0 for name, _ in slot_offsets}
    # We look for 'FF 90 xx xx xx xx' (call [rax+imm32]) and similar for r10,r11,rcx,rdx
    # opcode FF /2 = call r/m64; modrm 90 = rax+disp32, 91=rcx, 92=rdx, 93=rbx, 94=SIB, 95=rbp, 96=rsi, 97=rdi
    # REX.B + FF /2 for r8..r15: prefix 41 FF 90..97
    modrm_candidates = [0x90, 0x91, 0x92, 0x93, 0x95, 0x96, 0x97]
    rex_modrm_candidates = [(0x41, m) for m in modrm_candidates]

    ea = text.start_ea
    end = text.end_ea
    while ea < end - 6:
        b0 = ida_bytes.get_byte(ea)
        # FF /2 with modrm reg/mem = [reg+disp32]
        if b0 == 0xFF:
            b1 = ida_bytes.get_byte(ea + 1)
            if b1 in modrm_candidates:
                disp = ida_bytes.get_dword(ea + 2)
                for name, off in slot_offsets:
                    if disp == off:
                        counts[name] += 1
                ea += 6
                continue
        if b0 == 0x41:
            b1 = ida_bytes.get_byte(ea + 1)
            if b1 == 0xFF:
                b2 = ida_bytes.get_byte(ea + 2)
                if b2 in modrm_candidates:
                    disp = ida_bytes.get_dword(ea + 3)
                    for name, off in slot_offsets:
                        if disp == off:
                            counts[name] += 1
                    ea += 7
                    continue
        ea += 1

    log(fh, "[+] Displacement occurrence counts (context vtable slot heuristic):")
    for name, off in slot_offsets:
        log(fh, f"      {name:60s} disp=0x{off:X}  count={counts[name]}")


def dump_callers_of_disp(fh, disp_target, max_results=50):
    """Scan .text for call [reg+disp_target] and list the owning functions."""
    text = ida_segment.get_segm_by_name(".text")
    if text is None:
        return []
    modrm_candidates = [0x90, 0x91, 0x92, 0x93, 0x95, 0x96, 0x97]
    ea = text.start_ea
    end = text.end_ea
    hits = []
    while ea < end - 6 and len(hits) < max_results:
        b0 = ida_bytes.get_byte(ea)
        if b0 == 0xFF:
            b1 = ida_bytes.get_byte(ea + 1)
            if b1 in modrm_candidates:
                disp = ida_bytes.get_dword(ea + 2)
                if disp == disp_target:
                    fn = ida_funcs.get_func(ea)
                    if fn:
                        hits.append((ea, fn.start_ea, fn.end_ea - fn.start_ea))
                ea += 6
                continue
        if b0 == 0x41:
            b1 = ida_bytes.get_byte(ea + 1)
            if b1 == 0xFF:
                b2 = ida_bytes.get_byte(ea + 2)
                if b2 in modrm_candidates:
                    disp = ida_bytes.get_dword(ea + 3)
                    if disp == disp_target:
                        fn = ida_funcs.get_func(ea)
                        if fn:
                            hits.append((ea, fn.start_ea, fn.end_ea - fn.start_ea))
                    ea += 7
                    continue
        ea += 1

    # Deduplicate by function start
    seen = {}
    for call_ea, fs, sz in hits:
        seen.setdefault(fs, []).append((call_ea, sz))
    return seen


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    log(fh, "==== waiting for auto_wait ====")
    ida_auto.auto_wait()
    log(fh, f"[+] Image base: 0x{ida_nalt.get_imagebase():X}")

    log(fh, "[*] Enumerating strings (slow)...")
    strs = list(idautils.Strings())
    log(fh, f"[+] Total strings: {len(strs)}")

    log(fh, "")
    log(fh, "============================================================")
    log(fh, "  PART 1: STRING ANCHORS AND THEIR CALLERS")
    log(fh, "============================================================")
    for needle in ANCHORS:
        hits = find_string_ea(needle, strs)
        if not hits:
            log(fh, f"[-] MISSING: {needle!r}")
            continue
        for h in hits:
            log(fh, "")
            log(fh, f"[+] {needle!r} @ 0x{h:X} (RVA 0x{rva(h):X})")
            list_callers(h, fh, depth=0, max_depth=2)

    log(fh, "")
    log(fh, "============================================================")
    log(fh, "  PART 2: D3D11 CONTEXT VTABLE SLOT HEURISTIC")
    log(fh, "============================================================")
    slot_offsets = [
        ("DrawIndexed",           0x60),
        ("Draw",                  0x68),
        ("Map",                   0x70),
        ("OMSetRenderTargets",    0x108),
        ("OMSetRTAndUAV",         0x110),
        ("OMSetBlendState",       0x118),
        ("ClearRenderTargetView", 0x188),
        ("ClearUAVuint",          0x190),
        ("ClearUAVfloat",         0x198),
        ("ClearDepthStencilView", 0x1A0),
        ("GenerateMips",          0x1A8),
        ("Present",               0x40),  # only valid on SwapChain vtable - but useful ceiling
    ]
    find_context_vtbl_uses(fh, slot_offsets)

    log(fh, "")
    log(fh, "============================================================")
    log(fh, "  PART 3: FUNCTIONS CONTAINING ClearDepthStencilView (0x1A0)")
    log(fh, "============================================================")
    by_func = dump_callers_of_disp(fh, 0x1A0, max_results=500)
    log(fh, f"[+] {len(by_func)} unique functions call [reg+0x1A0]  (ClearDepthStencilView candidate)")
    # Sort by size descending and list top 30
    ranked = sorted(by_func.items(), key=lambda kv: -max(sz for _, sz in kv[1]))
    for fs, calls in ranked[:30]:
        name = ida_funcs.get_func_name(fs) or "?"
        nc = len(calls)
        fn = ida_funcs.get_func(fs)
        sz = fn.end_ea - fn.start_ea if fn else 0
        log(fh, f"    func 0x{fs:X} (RVA 0x{rva(fs):X}) size=0x{sz:X} clear_calls={nc} name={name}")

    log(fh, "")
    log(fh, "============================================================")
    log(fh, "  PART 4: FUNCTIONS CONTAINING OMSetRenderTargets (0x108)")
    log(fh, "============================================================")
    by_func2 = dump_callers_of_disp(fh, 0x108, max_results=2000)
    log(fh, f"[+] {len(by_func2)} unique functions call [reg+0x108]  (OMSetRenderTargets candidate)")
    ranked2 = sorted(by_func2.items(), key=lambda kv: -len(kv[1]))
    for fs, calls in ranked2[:40]:
        name = ida_funcs.get_func_name(fs) or "?"
        nc = len(calls)
        fn = ida_funcs.get_func(fs)
        sz = fn.end_ea - fn.start_ea if fn else 0
        log(fh, f"    func 0x{fs:X} (RVA 0x{rva(fs):X}) size=0x{sz:X} omset_calls={nc} name={name}")

    log(fh, "")
    log(fh, "==== Report complete ====")
    fh.close()
    ida_pro.qexit(0)


main()
