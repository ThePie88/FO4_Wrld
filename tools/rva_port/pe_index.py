"""Index a Fallout4.exe: functions (from .pdata), normalised code hashes, call
and data references, and RTTI vtables. Cached to <exe>.<size>.idx.pickle.

Normalisation: instruction bytes with every RIP-relative displacement and every
relative branch/call immediate zeroed, so a function that only moved (or whose
callees/globals moved) hashes the same in both builds.
"""

from __future__ import annotations

import hashlib
import mmap
import os
import pickle
import struct
from array import array
import sys
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

import capstone
import pefile

IMAGE_BASE = 0x140000000


@dataclass
class Func:
    start: int          # RVA
    end: int            # RVA (exclusive)
    h: bytes = b""      # normalised hash
    n_insn: int = 0
    calls: list = field(default_factory=list)   # [(insn_idx, target_rva)]
    drefs: list = field(default_factory=list)   # [(insn_idx, target_rva)] rip-relative memory operands
    insn_offs: list = field(default_factory=list)  # instruction start offsets (relative)


@dataclass
class Index:
    path: str
    version: str
    sections: list            # [(name, rva, vsize, raw_ptr, raw_size)]
    funcs: list               # [Func] sorted by start
    vtables: dict             # rtti name + "@" + col offset -> vtable rva


# --------------------------------------------------------------------------- PE
def _sections(pe):
    return [(s.Name.rstrip(b"\0").decode(), s.VirtualAddress, s.Misc_VirtualSize,
             s.PointerToRawData, s.SizeOfRawData) for s in pe.sections]


class Image:
    """Random access to an exe by RVA."""

    def __init__(self, path):
        self.path = path
        self.f = open(path, "rb")
        self.mm = mmap.mmap(self.f.fileno(), 0, access=mmap.ACCESS_READ)
        pe = pefile.PE(data=self.mm[:0x1000], fast_load=True)
        hdr_size = pe.OPTIONAL_HEADER.SizeOfHeaders
        pe = pefile.PE(data=self.mm[:max(hdr_size, 0x1000)], fast_load=True)
        self.secs = _sections(pe)

    def section_of(self, rva):
        for s in self.secs:
            if s[1] <= rva < s[1] + max(s[2], s[4]):
                return s
        return None

    def read(self, rva, n):
        s = self.section_of(rva)
        if not s:
            return b""
        off = s[3] + (rva - s[1])
        avail = s[3] + s[4] - off
        if avail <= 0:
            return b"\0" * n  # .bss-like tail
        return bytes(self.mm[off:off + min(n, avail)]).ljust(n, b"\0")

    def u64(self, rva):
        return struct.unpack("<Q", self.read(rva, 8))[0]

    def u32(self, rva):
        return struct.unpack("<I", self.read(rva, 4))[0]

    def i32(self, rva):
        return struct.unpack("<i", self.read(rva, 4))[0]


def file_version(path) -> str:
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
    for fi in getattr(pe, "VS_FIXEDFILEINFO", []) or []:
        ms, ls = fi.FileVersionMS, fi.FileVersionLS
        return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"
    return "?"


def pdata(path):
    pe = pefile.PE(path, fast_load=True)
    d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXCEPTION"]]
    data = pe.get_data(d.VirtualAddress, d.Size)
    out = []
    for i in range(0, len(data) - 11, 12):
        b, e, _u = struct.unpack_from("<III", data, i)
        if b and e > b:
            out.append((b, e))
    out.sort()
    return out


# ----------------------------------------------------------------- disassembly
_md = None


def _disasm_chunk(args):
    path, ranges = args
    global _md
    if _md is None:
        _md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        _md.detail = True
    img = Image(path)
    out = []
    REL = {capstone.x86.X86_GRP_CALL, capstone.x86.X86_GRP_JUMP, capstone.x86.X86_GRP_BRANCH_RELATIVE}
    for start, end in ranges:
        code = img.read(start, end - start)
        norm = bytearray()
        calls, drefs, offs = [], [], []
        idx = 0
        for ins in _md.disasm(code, start):
            b = bytearray(ins.bytes)
            offs.append(ins.address - start)
            # relative branches / calls
            if ins.imm_size and (set(ins.groups) & REL) and ins.imm_offset:
                tgt = None
                for op in ins.operands:
                    if op.type == capstone.x86.X86_OP_IMM:
                        tgt = op.imm
                b[ins.imm_offset:ins.imm_offset + ins.imm_size] = b"\0" * ins.imm_size
                if ins.mnemonic == "call" and tgt is not None:
                    calls.append((idx, tgt))
                elif ins.mnemonic == "jmp" and tgt is not None and not (start <= tgt < end):
                    calls.append((idx, tgt))  # tail call
            # rip-relative memory operands
            for op in ins.operands:
                if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                    tgt = ins.address + ins.size + op.mem.disp
                    if ins.disp_offset and ins.disp_size:
                        b[ins.disp_offset:ins.disp_offset + ins.disp_size] = b"\0" * ins.disp_size
                    if ins.mnemonic == "call" or ins.mnemonic == "jmp":
                        drefs.append((idx, tgt))  # call [rip+x] import / thunk slot
                    else:
                        drefs.append((idx, tgt))
            norm += b
            idx += 1
        f = Func(start, end, hashlib.blake2b(bytes(norm), digest_size=16).digest(), idx, calls, drefs, array('I', offs))
        out.append(f)
    return out


# ------------------------------------------------------------------------ RTTI
def rtti_vtables(img: Image):
    """Map '<mangled type name>@<offset>' -> vtable RVA via complete object locators."""
    rdata = [s for s in img.secs if s[0] == ".rdata"]
    data = [s for s in img.secs if s[0] == ".data"]
    if not rdata:
        return {}
    r = rdata[0]
    blob = img.read(r[1], r[2])
    out = {}
    # COL: sig(u32)=1, offset(u32), cdOffset(u32), pTypeDescriptor(rva u32), pClassHierarchy(rva), pSelf(rva)
    for i in range(0, len(blob) - 24, 4):
        sig, off, _cd, td, _ch, self_rva = struct.unpack_from("<IIIIII", blob, i)
        if sig != 1 or self_rva != r[1] + i:
            continue
        name = img.read(td + 16, 256).split(b"\0", 1)[0]
        if not name.startswith(b".?A"):
            continue
        col_va = IMAGE_BASE + self_rva
        # vtable = the qword after a pointer to this COL, somewhere in .rdata
        needle = struct.pack("<Q", col_va)
        pos = blob.find(needle)
        while pos != -1:
            if pos % 8 == 0:
                out[f"{name.decode(errors='replace')}@{off:x}"] = r[1] + pos + 8
            pos = blob.find(needle, pos + 8)
    return out


# ----------------------------------------------------------------------- build
def build(path: str, jobs: int | None = None) -> Index:
    size = os.path.getsize(path)
    cache = Path(os.environ.get("TEMP", ".")) / f"fo4idx_{size}.pickle"
    for c in (cache,):
        if c.is_file():
            with open(c, "rb") as fh:
                return pickle.load(fh)
    img = Image(path)
    ranges = pdata(path)
    jobs = jobs or max(1, (os.cpu_count() or 2) - 1)
    chunk = max(1, len(ranges) // (jobs * 8))
    parts = [(path, ranges[i:i + chunk]) for i in range(0, len(ranges), chunk)]
    funcs: list[Func] = []
    print(f"[index] {path}: {len(ranges)} functions, {jobs} workers", file=sys.stderr)
    with ProcessPoolExecutor(jobs) as ex:
        for n, res in enumerate(ex.map(_disasm_chunk, parts), 1):
            funcs.extend(res)
            if n % 50 == 0:
                print(f"[index]   {n}/{len(parts)} chunks", file=sys.stderr)
    funcs.sort(key=lambda f: f.start)
    idx = Index(path, file_version(path), img.secs, funcs, rtti_vtables(img))
    for c in (cache,):
        try:
            with open(c, "wb") as fh:
                pickle.dump(idx, fh, protocol=pickle.HIGHEST_PROTOCOL)
            break
        except OSError:
            continue
    return idx


if __name__ == "__main__":
    # Build through the importable module so the cached pickle references
    # pe_index.Index rather than __main__.Index.
    sys.path.insert(0, str(Path(__file__).parent))
    import pe_index as _self
    i = _self.build(sys.argv[1])
    print(i.version, len(i.funcs), "funcs", len(i.vtables), "vtables")
