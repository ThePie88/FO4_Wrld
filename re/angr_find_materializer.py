"""angr-based scan for functions that write the runtime BGSInventoryList
pointer at REFR+0xF8.

Strategy:
  1. Load Fallout4.exe with angr (no auto-symbolize, use CFGFast for
     function boundaries — scales on 55MB binary).
  2. Walk every function, disassemble blocks, look for x86 MOV-like
     instructions that store a register to [reg+0xF8].
     Specifically patterns: `mov [rXX+0F8h], rYY` with XX != 0 (i.e.,
     not writing to a global).
  3. Also separately find callers of each match (who triggers the write).
  4. Cross-reference with known call sites (sub_140502940 calls vtable
     slot 167 = sub_140D57400 which must eventually write +0xF8).

Output: re/angr_materializer_report.txt

Note: angr's capstone-based disasm is used via `proj.factory.block(addr)`.
"""
import sys, time
import angr
import logging

# Silence angr spam
logging.getLogger("angr").setLevel(logging.ERROR)
logging.getLogger("cle").setLevel(logging.ERROR)
logging.getLogger("pyvex").setLevel(logging.ERROR)

BIN = r"C:\Users\filip\Desktop\FalloutWorld\re\Fallout4.exe"
REPORT = r"C:\Users\filip\Desktop\FalloutWorld\re\angr_materializer_report.txt"


def log(fh, msg):
    print(msg, flush=True); fh.write(msg + "\n"); fh.flush()


def main():
    fh = open(REPORT, "w", encoding="utf-8")
    t0 = time.time()
    log(fh, f"[+] Loading {BIN} ...")
    proj = angr.Project(BIN, auto_load_libs=False)
    log(fh, f"    image base: 0x{proj.loader.main_object.mapped_base:X}")
    log(fh, f"    arch: {proj.arch}")
    log(fh, f"    [+] load took {time.time()-t0:.1f}s")

    # CFGFast — skips indirect resolution, enumerates function boundaries.
    # ~30-90s on a 55MB binary.
    t0 = time.time()
    log(fh, "[+] Building CFGFast (function boundaries only)...")
    cfg = proj.analyses.CFGFast(
        show_progressbar=False,
        force_complete_scan=False,
        data_references=False,
        cross_references=False,
    )
    log(fh, f"    functions discovered: {len(cfg.functions)}")
    log(fh, f"    [+] CFGFast took {time.time()-t0:.1f}s")

    # Walk functions, find writes to [+0xF8].
    # We look for capstone disasm text containing "+0xf8]" as a write target.
    t0 = time.time()
    log(fh, "[+] Scanning for writes to [reg+0xF8]...")
    writers: dict[int, list[tuple[int, str]]] = {}  # fn_addr -> [(ea, insn)]
    total_insns = 0

    for fn_addr, fn in cfg.functions.items():
        # Only functions that actually have code blocks
        if fn.is_simprocedure or fn.is_plt:
            continue
        for block in fn.blocks:
            try:
                insns = block.capstone.insns
            except Exception:
                continue
            for insn in insns:
                total_insns += 1
                # Capstone x86 mnemonic + op_str
                mnem = insn.mnemonic
                if mnem not in ("mov", "movq"):
                    continue
                ops = insn.op_str
                # Write to [reg+0xf8]? op0 must be memory write with +0xf8.
                # Forms: "qword ptr [rdi + 0xf8], rax" or similar
                # Check op_str starts with "qword ptr [" or "dword ptr [", then contains "+ 0xf8"
                if "+ 0xf8]" in ops.lower() and "ptr [" in ops.lower():
                    # ensure it's a write (left side is the memory)
                    first_comma = ops.find(",")
                    if first_comma == -1:
                        continue
                    lhs = ops[:first_comma].strip()
                    if "[" in lhs and "+ 0xf8]" in lhs.lower():
                        writers.setdefault(fn_addr, []).append((insn.address, f"{mnem} {ops}"))

    log(fh, f"    scanned {total_insns} instructions in {time.time()-t0:.1f}s")
    log(fh, f"    functions writing [+0xF8]: {len(writers)}")

    # Report
    log(fh, "\n==== writers ====")
    img = proj.loader.main_object.mapped_base
    # Sort by address
    for fn_addr in sorted(writers.keys()):
        fn = cfg.functions[fn_addr]
        fn_name = fn.name or f"sub_{fn_addr:X}"
        rva = fn_addr - img
        log(fh, f"\n  --- {fn_name} (RVA 0x{rva:X}) — {len(writers[fn_addr])} write(s) ---")
        for ea, insn in writers[fn_addr]:
            log(fh, f"    0x{ea:X} (RVA 0x{ea-img:X}): {insn}")

    # Cross-ref: who calls each writer?
    log(fh, "\n==== callers of each writer ====")
    for fn_addr in sorted(writers.keys()):
        fn = cfg.functions[fn_addr]
        callers = list(fn.predecessors)
        rva = fn_addr - img
        log(fh, f"\n  --- callers of fn @ RVA 0x{rva:X} ({len(callers)}) ---")
        for caller in callers[:10]:
            caller_rva = caller.addr - img
            name = caller.name or f"sub_{caller.addr:X}"
            log(fh, f"    {name} (RVA 0x{caller_rva:X})")

    log(fh, "\n==== done ====")
    fh.close()


if __name__ == "__main__":
    main()
