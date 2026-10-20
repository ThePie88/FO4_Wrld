"""Poor man's profiler for a running Fallout4.exe (vanilla or modded), from
the outside: no DLL, no symbols, nothing written into the game.

Every `--interval` seconds each thread of the process is suspended for a few
microseconds, its RIP and RSP are read (GetThreadContext), 64 qwords of its
stack are scanned for return addresses inside the game module, and the thread
is resumed. RIPs and stack hits are named with the Hex-Rays function index of
the full decomp (D:\\falloutworld_decomp\\out\\05_functions.csv, image base
0x140000000), so a sample reads "sub_140C3AB10+0x8B" instead of a bare
address. Per-thread CPU time (GetThreadTimes) tells a thread that WORKS from
one that WAITS.

The report is a timeline in `--bucket`-second windows: for each window the
main thread's top location, whether the engine is in a loading screen (the
main thread inside sub_140C3AB10, the message pump of the load), and the
busiest threads with their top location; then a per-thread summary over the
whole run. Everything also goes to tools/sampler_reports/<timestamp>.txt.

Why (2026-10-18): leaving an interior takes 80 s in VANILLA on this PC
(RESEARCH_interior_loads.md section 7); the engine's own loading screen loop
runs on the JobListManager serving thread and the teleport job on a worker,
so only an outside sampler can say where those 80 s go.

Usage (the game must be running; press the door after the sampler starts):
    python tools/fo4_thread_sampler.py --seconds 180
    python tools/fo4_thread_sampler.py --pid 1234 --seconds 60 --interval 0.1
    python tools/fo4_thread_sampler.py --self-test        # samples a python sleeper
"""
from __future__ import annotations

import argparse
import bisect
import collections
import csv
import ctypes
import ctypes.wintypes as wt
import datetime as dt
import os
import struct
import subprocess
import sys
import time

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll")

TH32CS_SNAPPROCESS = 0x2
TH32CS_SNAPTHREAD = 0x4
TH32CS_SNAPMODULE = 0x8
TH32CS_SNAPMODULE32 = 0x10
PROCESS_QUERY_INFORMATION = 0x400
PROCESS_VM_READ = 0x10
THREAD_SUSPEND_RESUME = 0x2
THREAD_GET_CONTEXT = 0x8
THREAD_QUERY_INFORMATION = 0x40
CONTEXT_CONTROL = 0x100001
CONTEXT_INTEGER = 0x100002
CONTEXT_SIZE = 0x4D0
OFF_CONTEXTFLAGS = 0x30
OFF_RSP = 0x98
OFF_RIP = 0xF8
IMAGE_BASE = 0x140000000
STACK_QWORDS = 64
ThreadQuerySetWin32StartAddress = 9

FUNCS_CSV = r"D:\falloutworld_decomp\out\05_functions.csv"

# The loader singleton (qword_14355EB28) and what the flush loop sub_1417AF2F0
# polls: pending IO (+5084), a second pending count (+5296), the per-priority
# counters (pointer at +5192, 5 dwords per priority level, 6 levels), the
# lock-free ring (head +4096, dispatch cursor +4224, tail +4352), the serving
# thread's mode (object at qword_1430DBF78[226381], +104: 2 = loading screen).
LOADER_PTR_RVA = 0x355EB28           # qword_14355EB28 - 0x140000000
SERVING_THREAD_PTR_RVA = 0x32962E0   # &qword_1430DBF78[226381] - 0x140000000
# The request ring lives at loader+384 (sub_1417AF200 pushes into v3 = a1+384):
# ring slots +0 (512 qwords), consume index +4096, dispatch cursor +4224,
# commit index +4352, reserve index +4480; the dispatched items: pointer array
# at +4672 (capacity +4692, next unused +4696), next-index array at +4680, six
# priority lists (head/tail dword pairs) at +4608, the spinlock at +4688, the
# pending count at +4700 (= loader+5084). Each item: vtable +0, state byte +13
# (5 done, 6 cancelled, 7 in flight), priority byte +15, refcount +48.
RING_OFF = 384
FRAME_COUNTER_RVAS = {"begin-frame": 0x3D70938, "game-frame": 0xDA180}   # ++unk_143D70938 (sub_141817D10), dword_1430DA180
RTTI_CATALOG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "re", "engine_rtti_catalog.md")
REPORT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sampler_reports")

# The engine landmarks (FO4 1.11.191, see RESEARCH_interior_loads.md).
LANDMARKS = {
    0x140C3AB10: (0xEF, "LOAD PUMP (main loop waits for the teleport job, pumping messages)"),
    0x140BD6F10: (0x385, "JobListManager::ServingThread::Run (mode 2 = loading-screen render loop)"),
    0x140D55E10: (0x136A, "teleport job (PlayerCharacter pending MoveTo)"),
    0x1417AF2F0: (0x2FC, "loader flush (wait for queued loads up to a priority)"),
    0x1417AF000: (0x1F6, "loader post-process (20 ms slices)"),
    0x1417AF200: (0xF0, "loader ring push (waits when the ring is full)"),
    0x1402D3EB0: (0x1D4, "TES::BeginLoad (LoadingMenu show)"),
    0x1402D4090: (0x3FD, "TES::EndLoad (LoadingMenu hide + fade-in)"),
    0x140DAA820: (0x251, "queued references drain step"),
    0x141817F60: (0xC0, "renderer Present (end of frame)"),
    0x140C334B0: (0x1600, "main loop"),
}


class THREADENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD), ("th32ThreadID", wt.DWORD),
                ("th32OwnerProcessID", wt.DWORD), ("tpBasePri", ctypes.c_long),
                ("tpDeltaPri", ctypes.c_long), ("dwFlags", wt.DWORD)]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("th32ModuleID", wt.DWORD), ("th32ProcessID", wt.DWORD),
                ("GlblcntUsage", wt.DWORD), ("ProccntUsage", wt.DWORD),
                ("modBaseAddr", ctypes.c_void_p), ("modBaseSize", wt.DWORD),
                ("hModule", ctypes.c_void_p), ("szModule", ctypes.c_wchar * 256),
                ("szExePath", ctypes.c_wchar * 260)]


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD), ("th32ProcessID", wt.DWORD),
                ("th32DefaultHeapID", ctypes.c_void_p), ("th32ModuleID", wt.DWORD),
                ("cntThreads", wt.DWORD), ("th32ParentProcessID", wt.DWORD),
                ("pcPriClassBase", ctypes.c_long), ("dwFlags", wt.DWORD),
                ("szExeFile", ctypes.c_wchar * 260)]


class FILETIME(ctypes.Structure):
    _fields_ = [("lo", wt.DWORD), ("hi", wt.DWORD)]

    def value(self) -> int:
        return (self.hi << 32) | self.lo


for fn, res, args in (
    (k32.CreateToolhelp32Snapshot, wt.HANDLE, (wt.DWORD, wt.DWORD)),
    (k32.Thread32First, wt.BOOL, (wt.HANDLE, ctypes.POINTER(THREADENTRY32))),
    (k32.Thread32Next, wt.BOOL, (wt.HANDLE, ctypes.POINTER(THREADENTRY32))),
    (k32.Module32FirstW, wt.BOOL, (wt.HANDLE, ctypes.POINTER(MODULEENTRY32W))),
    (k32.Module32NextW, wt.BOOL, (wt.HANDLE, ctypes.POINTER(MODULEENTRY32W))),
    (k32.Process32FirstW, wt.BOOL, (wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W))),
    (k32.Process32NextW, wt.BOOL, (wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W))),
    (k32.OpenProcess, wt.HANDLE, (wt.DWORD, wt.BOOL, wt.DWORD)),
    (k32.OpenThread, wt.HANDLE, (wt.DWORD, wt.BOOL, wt.DWORD)),
    (k32.SuspendThread, wt.DWORD, (wt.HANDLE,)),
    (k32.ResumeThread, wt.DWORD, (wt.HANDLE,)),
    (k32.GetThreadContext, wt.BOOL, (wt.HANDLE, ctypes.c_void_p)),
    (k32.ReadProcessMemory, wt.BOOL, (wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                      ctypes.POINTER(ctypes.c_size_t))),
    (k32.GetThreadTimes, wt.BOOL, (wt.HANDLE, ctypes.POINTER(FILETIME), ctypes.POINTER(FILETIME),
                                   ctypes.POINTER(FILETIME), ctypes.POINTER(FILETIME))),
    (k32.CloseHandle, wt.BOOL, (wt.HANDLE,)),
    (k32.GetExitCodeProcess, wt.BOOL, (wt.HANDLE, ctypes.POINTER(wt.DWORD))),
    (ntdll.NtQueryInformationThread, ctypes.c_long, (wt.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                                     wt.ULONG, ctypes.POINTER(wt.ULONG))),
):
    fn.restype = res
    fn.argtypes = args


# ---------------------------------------------------------------- naming
class FuncIndex:
    def __init__(self, path: str):
        self.starts: list[int] = []
        self.sizes: list[int] = []
        self.names: list[str] = []
        if not os.path.exists(path):
            print(f"[sampler] no function index at {path}: raw RVAs only")
            return
        with open(path, encoding="utf-8", errors="replace", newline="") as f:
            rd = csv.reader(f)
            hdr = next(rd)
            ie, iname, isize = hdr.index("ea"), hdr.index("name"), hdr.index("size")
            rows = []
            for r in rd:
                try:
                    rows.append((int(r[ie], 16), int(r[isize], 0), r[iname]))
                except (ValueError, IndexError):
                    continue
        rows.sort()
        self.starts = [r[0] for r in rows]
        self.sizes = [r[1] for r in rows]
        self.names = [r[2] for r in rows]
        print(f"[sampler] {len(rows)} functions indexed from the decomp")

    def name(self, ea: int) -> str:
        if not self.starts:
            return f"rva_{ea - IMAGE_BASE:X}"
        i = bisect.bisect_right(self.starts, ea) - 1
        if i < 0:
            return f"rva_{ea - IMAGE_BASE:X}"
        s, sz, n = self.starts[i], self.sizes[i], self.names[i]
        if ea < s + max(sz, 1):
            return f"{n}+0x{ea - s:X}"
        return f"{n}+0x{ea - s:X}?"

    def func(self, ea: int) -> str:
        """The function alone (no offset), for aggregation."""
        return self.name(ea).split("+", 1)[0]


def landmark(ea: int) -> str | None:
    for start, (size, what) in LANDMARKS.items():
        if start <= ea < start + size:
            return what
    return None


# ---------------------------------------------------------------- process
def find_pid(name: str) -> int | None:
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == wt.HANDLE(-1).value or not snap:
        return None
    pe = PROCESSENTRY32W()
    pe.dwSize = ctypes.sizeof(pe)
    found = None
    try:
        ok = k32.Process32FirstW(snap, ctypes.byref(pe))
        while ok:
            if pe.szExeFile.lower() == name.lower():
                found = pe.th32ProcessID
                break
            ok = k32.Process32NextW(snap, ctypes.byref(pe))
    finally:
        k32.CloseHandle(snap)
    return found


def modules(pid: int) -> list[tuple[int, int, str]]:
    """(base, size, name) of every module; retried, the snapshot is flaky."""
    for _ in range(20):
        snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
        if snap and snap != wt.HANDLE(-1).value:
            me = MODULEENTRY32W()
            me.dwSize = ctypes.sizeof(me)
            out = []
            try:
                ok = k32.Module32FirstW(snap, ctypes.byref(me))
                while ok:
                    out.append((me.modBaseAddr or 0, me.modBaseSize, me.szModule))
                    ok = k32.Module32NextW(snap, ctypes.byref(me))
            finally:
                k32.CloseHandle(snap)
            if out:
                return out
        time.sleep(0.05)
    return []


def threads_of(pid: int) -> list[int]:
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if not snap or snap == wt.HANDLE(-1).value:
        return []
    te = THREADENTRY32()
    te.dwSize = ctypes.sizeof(te)
    out = []
    try:
        ok = k32.Thread32First(snap, ctypes.byref(te))
        while ok:
            if te.th32OwnerProcessID == pid:
                out.append(te.th32ThreadID)
            ok = k32.Thread32Next(snap, ctypes.byref(te))
    finally:
        k32.CloseHandle(snap)
    return out


class Thread:
    def __init__(self, tid: int):
        self.tid = tid
        self.h = k32.OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                                False, tid)
        self.start = 0
        self.created = 0
        self.cpu0 = 0        # user+kernel 100 ns at the first sample
        self.cpu_last = 0
        self.samples = 0
        self.rips = collections.Counter()
        self.hits = collections.Counter()
        self.gone = False
        if self.h:
            addr = ctypes.c_void_p(0)
            ntdll.NtQueryInformationThread(self.h, ThreadQuerySetWin32StartAddress,
                                           ctypes.byref(addr), 8, None)
            self.start = addr.value or 0
            c, e, kt, ut = FILETIME(), FILETIME(), FILETIME(), FILETIME()
            if k32.GetThreadTimes(self.h, ctypes.byref(c), ctypes.byref(e), ctypes.byref(kt),
                                  ctypes.byref(ut)):
                self.created = c.value()
                self.cpu0 = self.cpu_last = kt.value() + ut.value()

    def cpu_now(self) -> int:
        c, e, kt, ut = FILETIME(), FILETIME(), FILETIME(), FILETIME()
        if self.h and k32.GetThreadTimes(self.h, ctypes.byref(c), ctypes.byref(e), ctypes.byref(kt),
                                         ctypes.byref(ut)):
            if e.value():
                self.gone = True
            return kt.value() + ut.value()
        return self.cpu_last

    def close(self):
        if self.h:
            k32.CloseHandle(self.h)
            self.h = None


class Sampler:
    def __init__(self, pid: int, funcs: FuncIndex):
        self.pid = pid
        self.funcs = funcs
        self.hproc = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not self.hproc:
            raise SystemExit(f"OpenProcess({pid}) failed, gle={ctypes.get_last_error()}")
        self.mods = modules(pid)
        self.game = None
        for base, size, name in self.mods:
            if name.lower().endswith(".exe"):
                self.game = (base, size, name)
                break
        if not self.game:
            raise SystemExit("main module not found")
        self.threads: dict[int, Thread] = {}
        self.ctx_raw = ctypes.create_string_buffer(CONTEXT_SIZE + 16)
        addr = ctypes.addressof(self.ctx_raw)
        self.ctx = (addr + 15) & ~15
        self.stack_buf = ctypes.create_string_buffer(STACK_QWORDS * 8)
        self.refresh_threads()

    def refresh_threads(self):
        for tid in threads_of(self.pid):
            if tid not in self.threads:
                self.threads[tid] = Thread(tid)

    def module_of(self, addr: int) -> str:
        for base, size, name in self.mods:
            if base <= addr < base + size:
                return name
        return "?"

    def where(self, addr: int) -> str:
        """A readable location: decomp name inside the game, module+offset elsewhere."""
        base, size, name = self.game
        if base <= addr < base + size:
            return self.funcs.name(IMAGE_BASE + (addr - base))
        m = self.module_of(addr)
        if m == "?":
            return f"0x{addr:X}"
        for b, s, n in self.mods:
            if n == m:
                return f"{m}+0x{addr - b:X}"
        return m

    def sample_thread(self, t: Thread) -> tuple[int, list[int]] | None:
        if not t.h:
            return None
        if k32.SuspendThread(t.h) == 0xFFFFFFFF:
            return None
        try:
            ctypes.c_uint32.from_address(self.ctx + OFF_CONTEXTFLAGS).value = CONTEXT_CONTROL | CONTEXT_INTEGER
            if not k32.GetThreadContext(t.h, self.ctx):
                return None
            rip = ctypes.c_uint64.from_address(self.ctx + OFF_RIP).value
            rsp = ctypes.c_uint64.from_address(self.ctx + OFF_RSP).value
            n = ctypes.c_size_t(0)
            hits: list[int] = []
            if rsp and k32.ReadProcessMemory(self.hproc, rsp, self.stack_buf, STACK_QWORDS * 8, ctypes.byref(n)):
                base, size, _ = self.game
                for q in struct.unpack_from(f"<{n.value // 8}Q", self.stack_buf.raw):
                    if base <= q < base + size:
                        hits.append(q)
            return rip, hits
        finally:
            k32.ResumeThread(t.h)

    def read_u64(self, addr: int) -> int | None:
        buf = ctypes.create_string_buffer(8)
        n = ctypes.c_size_t(0)
        if addr and k32.ReadProcessMemory(self.hproc, addr, buf, 8, ctypes.byref(n)) and n.value == 8:
            return struct.unpack("<Q", buf.raw)[0]
        return None

    def read_u32s(self, addr: int, count: int) -> list[int] | None:
        buf = ctypes.create_string_buffer(4 * count)
        n = ctypes.c_size_t(0)
        if addr and k32.ReadProcessMemory(self.hproc, addr, buf, 4 * count, ctypes.byref(n)) and n.value == 4 * count:
            return list(struct.unpack(f"<{count}I", buf.raw))
        return None

    def loader_state(self) -> str:
        """One line with the loader's counters, '' when unreadable."""
        base = self.game[0]
        obj = self.read_u64(base + LOADER_PTR_RVA)
        if not obj:
            return ""
        ring = obj + RING_OFF
        v = self.read_u32s(ring + 4096, 1)
        head = v[0] if v else -1
        v = self.read_u32s(ring + 4224, 1)
        disp = v[0] if v else -1
        v = self.read_u32s(ring + 4352, 1)
        tail = v[0] if v else -1
        v = self.read_u32s(ring + 4480, 1)
        reserve = v[0] if v else -1
        lists = self.read_u32s(ring + 4608, 12)
        heads = [lists[2 * i] for i in range(6)] if lists else []
        v = self.read_u32s(obj + 5084, 1)
        pend_io = v[0] if v else -1
        v = self.read_u32s(obj + 5296, 1)
        pend2 = v[0] if v else -1
        v = self.read_u32s(obj + 5284, 1)
        state = v[0] if v else -1
        prio = self.read_u64(obj + 5192)
        counts = self.read_u32s(prio, 30) if prio else None
        per_level = [sum(counts[5 * i:5 * i + 5]) for i in range(6)] if counts else []
        st = self.read_u64(base + SERVING_THREAD_PTR_RVA)
        mode = -1
        if st:
            v = self.read_u32s(st + 104, 1)
            mode = v[0] if v else -1
        return (f"loader: ring consume {head} disp {disp} commit {tail} reserve {reserve} (unconsumed {tail - head if tail >= 0 and head >= 0 else '?'}), "
                f"list heads {heads}, pending {pend_io}, pending2 {pend2}, state {state}, per-priority {per_level}, "
                f"serving-thread mode {mode}, frames: {self.frame_counters()}")

    _rtti: dict[int, str] | None = None

    def rtti(self) -> dict[int, str]:
        if Sampler._rtti is None:
            m: dict[int, str] = {}
            try:
                import re as _re
                rx = _re.compile(r"\| `([^`]+)` \| `0x([0-9A-Fa-f]+)` \|")
                with open(RTTI_CATALOG, encoding="utf-8", errors="replace") as f:
                    for ln in f:
                        mm = rx.search(ln)
                        if mm:
                            m.setdefault(int(mm.group(2), 16), mm.group(1))
            except OSError:
                pass
            Sampler._rtti = m
            print(f"[sampler] {len(m)} vtables known from the RTTI catalog")
        return Sampler._rtti

    def read_bytes(self, addr: int, n: int) -> bytes | None:
        buf = ctypes.create_string_buffer(n)
        got = ctypes.c_size_t(0)
        if addr and k32.ReadProcessMemory(self.hproc, addr, buf, n, ctypes.byref(got)) and got.value == n:
            return buf.raw
        return None

    def sniff_string(self, addr: int) -> str | None:
        """ASCII or UTF-16 text at addr (a BSFixedString's data pointer, a path)."""
        raw = self.read_bytes(addr, 160)
        if not raw:
            return None
        if raw[0] and raw[1] == 0 and raw[2] and raw[3] == 0:
            s = raw.decode("utf-16-le", errors="replace").split("\0", 1)[0]
        else:
            s = raw.split(b"\0", 1)[0].decode("ascii", errors="replace")
        if len(s) < 5 or not all(32 <= ord(c) < 127 for c in s):
            return None
        return s

    def describe_item(self, p: int) -> tuple[str, int, int, str]:
        """(class, state, priority, text) of a loader request object."""
        raw = self.read_bytes(p, 256)
        if not raw:
            return ("unreadable", -1, -1, "")
        vt = struct.unpack_from("<Q", raw, 0)[0]
        base, size, _ = self.game
        cls = "?"
        if base <= vt < base + size:
            cls = self.rtti().get(vt - base, f"vtable_rva_{vt - base:X}")
        state, prio = raw[13], raw[15]
        texts = []
        for off in range(8, 256, 8):
            q = struct.unpack_from("<Q", raw, off)[0]
            if 0x10000 <= q < 0x7FFFFFFFFFFF:
                s = self.sniff_string(q)
                if s and s not in texts:
                    texts.append(s)
        # inline text (a path stored in the object itself)
        inline = raw[16:].split(b"\0", 1)[0]
        if 5 <= len(inline) < 200 and all(32 <= c < 127 for c in inline):
            texts.append(inline.decode("ascii"))
        return (cls, state, prio, " | ".join(texts[:3]))

    def loader_items(self, limit: int = 4096) -> list[str]:
        """What is queued in the loader right now, as 'class state prio text' lines."""
        base = self.game[0]
        obj = self.read_u64(base + LOADER_PTR_RVA)
        if not obj:
            return []
        ring = obj + RING_OFF
        ptrs: set[int] = set()
        slots = self.read_bytes(ring, 512 * 8)
        if slots:
            ptrs.update(q for q in struct.unpack(f"<512Q", slots) if q)
        arr = self.read_u64(ring + 4672)
        cap = self.read_u32s(ring + 4692, 1)
        if arr and cap and 0 < cap[0] <= limit:
            raw = self.read_bytes(arr, cap[0] * 8)
            if raw:
                ptrs.update(q for q in struct.unpack(f"<{cap[0]}Q", raw) if q)
        out = []
        for p in list(ptrs)[:limit]:
            cls, st, pr, txt = self.describe_item(p)
            out.append(f"{cls} st={st} pr={pr} {txt}")
        return out

    def frame_counters(self) -> str:
        base = self.game[0]
        parts = []
        for name, rva in FRAME_COUNTER_RVAS.items():
            v = self.read_u32s(base + rva, 1)
            parts.append(f"{name} {v[0] if v else '?'}")
        return ", ".join(parts)

    def alive(self) -> bool:
        code = wt.DWORD(0)
        return bool(k32.GetExitCodeProcess(self.hproc, ctypes.byref(code))) and code.value == 259


def run(pid: int, seconds: float, interval: float, bucket: float, funcs: FuncIndex, out_path: str, items_on: bool = True):
    s = Sampler(pid, funcs)
    base, size, name = s.game
    print(f"[sampler] pid {pid} {name} base 0x{base:X} size 0x{size:X}, {len(s.threads)} threads, "
          f"{seconds:.0f} s at {interval*1000:.0f} ms, {bucket:.0f} s buckets")
    main_tid = min(s.threads.values(), key=lambda t: t.created or 2**63).tid if s.threads else 0
    t0 = time.time()
    last_refresh = t0
    # per bucket: tid -> (samples, Counter(rip loc), Counter(stack func), cpu_delta_100ns)
    buckets: list[dict[int, dict]] = []
    loader_lines: list[str] = []
    item_lines: list[tuple[int, int, list]] = []
    cur: dict[int, dict] = {}
    cur_start = t0
    cpu_at_bucket: dict[int, int] = {tid: t.cpu0 for tid, t in s.threads.items()}
    nsamp = 0
    try:
        while time.time() - t0 < seconds:
            now = time.time()
            if now - last_refresh > 2.0:
                s.refresh_threads()
                last_refresh = now
            if now - cur_start >= bucket:
                # close the bucket with the cpu deltas
                for tid, t in s.threads.items():
                    c = t.cpu_now()
                    d = cur.setdefault(tid, {"n": 0, "rip": collections.Counter(), "stk": collections.Counter(), "cpu": 0})
                    d["cpu"] = c - cpu_at_bucket.get(tid, c)
                    cpu_at_bucket[tid] = c
                buckets.append(cur)
                loader_lines.append(s.loader_state())
                if items_on:
                    try:
                        obj = s.read_u64(s.game[0] + LOADER_PTR_RVA)
                        pend = s.read_u32s(obj + 5084, 1) if obj else None
                        if pend and pend[0] > 0:
                            its = s.loader_items()
                            cnt = collections.Counter(its)
                            item_lines.append((len(buckets) - 1, len(its), cnt.most_common(12)))
                    except Exception as ex:   # never let the dump kill the run
                        item_lines.append((len(buckets) - 1, -1, [(f"dump failed: {ex}", 1)]))
                cur = {}
                cur_start = now
            for tid, t in list(s.threads.items()):
                if t.gone:
                    continue
                r = s.sample_thread(t)
                if r is None:
                    continue
                rip, hits = r
                d = cur.setdefault(tid, {"n": 0, "rip": collections.Counter(), "stk": collections.Counter(), "cpu": 0})
                d["n"] += 1
                d["rip"][rip] += 1
                for h in hits:
                    d["stk"][s.funcs.func(IMAGE_BASE + (h - base))] += 1
                t.samples += 1
                t.rips[rip] += 1
                for h in hits:
                    t.hits[s.funcs.func(IMAGE_BASE + (h - base))] += 1
            nsamp += 1
            if not s.alive():
                print("[sampler] the process exited")
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        print("[sampler] stopped")
    for tid, t in s.threads.items():
        c = t.cpu_now()
        d = cur.setdefault(tid, {"n": 0, "rip": collections.Counter(), "stk": collections.Counter(), "cpu": 0})
        d["cpu"] = c - cpu_at_bucket.get(tid, c)
    buckets.append(cur)
    loader_lines.append(s.loader_state())

    lines: list[str] = []
    P = lines.append
    P(f"# fo4 thread sampler  pid {pid} {name}  {dt.datetime.now():%Y-%m-%d %H:%M:%S}  "
      f"{nsamp} rounds, {len(s.threads)} threads, bucket {bucket:.0f} s")
    P("")
    P("## timeline")
    for i, b in enumerate(buckets):
        t_from = i * bucket
        main = b.get(main_tid)
        tag = ""
        main_loc = "-"
        if main and main["n"]:
            rip, _ = main["rip"].most_common(1)[0]
            main_loc = s.where(rip)
            in_pump = sum(c for r, c in main["rip"].items() if landmark_hit(s, r, 0x140C3AB10)) + \
                      main["stk"].get("sub_140C3AB10", 0)
            if in_pump:
                tag = "  [LOADING: main thread in the load pump]"
        busy = sorted(((d["cpu"] / 1e4, tid) for tid, d in b.items() if d["cpu"] > 0), reverse=True)[:4]
        busy_s = ", ".join(f"tid {tid} {ms:.0f} ms -> {top_loc(s, b[tid])}" for ms, tid in busy)
        P(f"[{t_from:5.0f}-{t_from + bucket:5.0f} s] main: {main_loc}{tag}")
        if busy_s:
            P(f"              busy: {busy_s}")
        if i < len(loader_lines) and loader_lines[i]:
            P(f"              {loader_lines[i]}")
    if item_lines:
        P("")
        P("## queued loader items (per bucket, while requests were pending)")
        for bi, n, top in item_lines:
            P(f"[{bi * bucket:5.0f} s] {n} item(s):")
            for txt, c in top:
                P(f"      x{c}  {txt}")
    P("")
    P("## threads (whole run)")
    for tid, t in sorted(s.threads.items(), key=lambda kv: -(kv[1].cpu_last - kv[1].cpu0)):
        cpu_ms = (t.cpu_now() - t.cpu0) / 1e4
        role = []
        if tid == main_tid:
            role.append("MAIN")
        if t.start:
            role.append(f"start {s.where(t.start)}")
        P(f"- tid {tid} {' '.join(role)}: cpu {cpu_ms:.0f} ms, {t.samples} samples")
        heavy = cpu_ms > 0.2 * max(seconds, 1) * 1000 * 0.25   # more than 5% of a core over the run
        for rip, c in t.rips.most_common(30 if heavy else 5):
            lm = landmark(IMAGE_BASE + (rip - base)) if base <= rip < base + size else None
            P(f"    rip {100 * c / max(t.samples, 1):5.1f}%  {s.where(rip)}" + (f"   <- {lm}" if lm else ""))
        for fn, c in t.hits.most_common(20 if heavy else 6):
            ea = funcs_ea(s.funcs, fn)
            lm = landmark(ea) if ea else None
            P(f"    stk {100 * c / max(t.samples, 1):5.1f}%  {fn}" + (f"   <- {lm}" if lm else ""))
    text = "\n".join(lines) + "\n"
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    print(text)
    print(f"[sampler] report: {out_path}")
    for t in s.threads.values():
        t.close()
    k32.CloseHandle(s.hproc)


def landmark_hit(s: Sampler, rip: int, start: int) -> bool:
    base, size, _ = s.game
    if not (base <= rip < base + size):
        return False
    ea = IMAGE_BASE + (rip - base)
    sz = LANDMARKS[start][0]
    return start <= ea < start + sz


def top_loc(s: Sampler, d: dict) -> str:
    if not d["n"]:
        return "-"
    rip, _ = d["rip"].most_common(1)[0]
    loc = s.where(rip)
    stk = d["stk"].most_common(1)
    if stk and not loc.startswith("sub_"):
        loc += f" (stack: {stk[0][0]})"
    return loc


def funcs_ea(funcs: FuncIndex, fn: str) -> int | None:
    try:
        i = funcs.names.index(fn)
        return funcs.starts[i]
    except (ValueError, AttributeError):
        return None


def self_test(funcs: FuncIndex):
    child = subprocess.Popen([sys.executable, "-c", "import time\nwhile True: time.sleep(0.01)"])
    try:
        time.sleep(0.5)
        run(child.pid, 2.0, 0.1, 1.0, funcs, os.path.join(REPORT_DIR, "self_test.txt"), items_on=False)
    finally:
        child.kill()


def main():
    if struct.calcsize("P") != 8:
        raise SystemExit("64-bit Python required")
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pid", type=int)
    ap.add_argument("--name", default="Fallout4.exe")
    ap.add_argument("--seconds", type=float, default=180.0)
    ap.add_argument("--interval", type=float, default=0.2)
    ap.add_argument("--bucket", type=float, default=5.0)
    ap.add_argument("--funcs", default=FUNCS_CSV)
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--no-items", action="store_true", help="skip the loader item dump")
    a = ap.parse_args()
    funcs = FuncIndex(a.funcs)
    if a.self_test:
        self_test(funcs)
        return
    pid = a.pid or find_pid(a.name)
    if not pid:
        raise SystemExit(f"{a.name} is not running")
    out = os.path.join(REPORT_DIR, f"sample_{dt.datetime.now():%Y%m%d_%H%M%S}.txt")
    run(pid, a.seconds, a.interval, a.bucket, funcs, out, items_on=not a.no_items)


if __name__ == "__main__":
    main()
