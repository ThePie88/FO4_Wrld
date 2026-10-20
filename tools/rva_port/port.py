"""Translate 1.11.191 RVAs to another Fallout4.exe build by binary matching.

    python tools/rva_port/port.py OLD.exe NEW.exe [--out map.json]

Stages:
  1. functions whose normalised code hash is unique in both builds
  2. call-graph propagation: aligned call sites inside matched functions pair
     their callees (repeated until nothing new)
  3. gap fill: an unmatched function between two matched neighbours that moved
     by the same delta, with the same size, moved by that delta too
  4. data: RIP-relative operands at aligned instructions pair their targets
     (vote); vtables also pair by RTTI name
Then every address found by inventory.py is translated:
  code   -> containing function + aligned instruction offset
  data   -> exact data pair, else nearest paired symbol below with the same delta
             as the nearest above (inside one consistent region)
Each result carries the method and a confidence, and anything unresolved is
listed for manual review.
"""

from __future__ import annotations

import argparse
import bisect
import collections
import difflib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import inventory  # noqa: E402
import pe_index  # noqa: E402


class Side:
    def __init__(self, idx: pe_index.Index):
        self.idx = idx
        self.funcs = idx.funcs
        self.starts = [f.start for f in self.funcs]
        self.by_start = {f.start: f for f in self.funcs}
        self.by_hash = collections.defaultdict(list)
        for f in self.funcs:
            self.by_hash[f.h].append(f)
        self.text = next(s for s in idx.sections if s[0] == ".text")

    def func_at(self, rva):
        i = bisect.bisect_right(self.starts, rva) - 1
        if i >= 0 and self.funcs[i].start <= rva < self.funcs[i].end:
            return self.funcs[i]
        return None

    def section(self, rva):
        for s in self.idx.sections:
            if s[1] <= rva < s[1] + max(s[2], s[4]):
                return s[0]
        return None


class Matcher:
    def __init__(self, old: Side, new: Side, img_old, img_new):
        self.o, self.n = old, new
        self.io, self.inew = img_old, img_new
        self.fmap: dict[int, tuple[int, str]] = {}   # old func start -> (new start, method)
        self.rev: dict[int, int] = {}
        self.dvotes = collections.defaultdict(collections.Counter)
        self.cvotes = collections.defaultdict(collections.Counter)  # leaf callees (no .pdata entry)
        self._aligned_cache: dict[int, list | None] = {}

    def add(self, a, b, how):
        if a in self.fmap or b in self.rev:
            return False
        self.fmap[a] = (b, how)
        self.rev[b] = a
        return True

    # stage 1
    def unique_hashes(self):
        n = 0
        for h, fs in self.o.by_hash.items():
            nf = self.n.by_hash.get(h)
            if len(fs) == 1 and nf and len(nf) == 1:
                n += self.add(fs[0].start, nf[0].start, "hash")
        return n

    # instruction alignment between a matched pair: list of (old_idx, new_idx)
    def aligned(self, fo, fn):
        key = fo.start
        if key in self._aligned_cache:
            return self._aligned_cache[key]
        if fo.h == fn.h:
            pairs = [(i, i) for i in range(fo.n_insn)]
        else:
            to = _tokens(self.io, fo)
            tn = _tokens(self.inew, fn)
            sm = difflib.SequenceMatcher(None, to, tn, autojunk=False)
            pairs = []
            for a, b, size in sm.get_matching_blocks():
                pairs.extend((a + k, b + k) for k in range(size))
        self._aligned_cache[key] = pairs
        return pairs

    # stage 2
    def propagate(self):
        total = 0
        frontier = list(self.fmap.items())
        while frontier:
            new_pairs = []
            for a, (b, _how) in frontier:
                fo, fn = self.o.by_start[a], self.n.by_start[b]
                pairs = dict(self.aligned(fo, fn))
                calls_n = dict(fn.calls)
                for i, tgt in fo.calls:
                    j = pairs.get(i)
                    if j is None or j not in calls_n:
                        continue
                    t2 = calls_n[j]
                    self.cvotes[tgt][t2] += 1
                    if t2 in self.n.by_start and tgt in self.o.by_start:
                        if self.add(tgt, t2, "callgraph"):
                            new_pairs.append((tgt, (t2, "callgraph")))
                drefs_n = collections.defaultdict(list)
                for j, t in fn.drefs:
                    drefs_n[j].append(t)
                for i, tgt in fo.drefs:
                    j = pairs.get(i)
                    if j is None:
                        continue
                    for t2 in drefs_n.get(j, ()):
                        self.dvotes[tgt][t2] += 1
                        # code pointers loaded with lea (callbacks, vtable thunks)
                        if tgt in self.o.by_start and t2 in self.n.by_start:
                            if self.add(tgt, t2, "lea"):
                                new_pairs.append((tgt, (t2, "lea")))
            total += len(new_pairs)
            frontier = new_pairs
        return total

    # stage 3
    def gap_fill(self):
        matched = sorted((a, b) for a, (b, _) in self.fmap.items())
        n = 0
        for (a1, b1), (a2, b2) in zip(matched, matched[1:]):
            if b1 - a1 != b2 - a2:
                continue
            d = b1 - a1
            i = bisect.bisect_right(self.o.starts, a1)
            while i < len(self.o.funcs) and self.o.funcs[i].start < a2:
                fo = self.o.funcs[i]
                fn = self.n.by_start.get(fo.start + d)
                if fn and fn.end - fn.start == fo.end - fo.start:
                    n += self.add(fo.start, fn.start, "gap")
                i += 1
        return n

    def run(self, rounds=4):
        log = [("hash", self.unique_hashes())]
        for r in range(rounds):
            p = self.propagate()
            g = self.gap_fill()
            log.append((f"round{r}", p, g))
            if not p and not g:
                break
        # data pairs from the matched functions not yet visited by propagate
        self.propagate_all_data()
        return log

    def propagate_all_data(self):
        seen_votes = set(self.dvotes)
        for a, (b, _) in list(self.fmap.items()):
            fo, fn = self.o.by_start[a], self.n.by_start[b]
            leaf_calls = [(i, t) for i, t in fo.calls if t not in self.o.by_start and t not in self.cvotes]
            if not fo.drefs and not leaf_calls:
                continue
            if all(t in seen_votes for _, t in fo.drefs) and not leaf_calls:
                continue
            pairs = dict(self.aligned(fo, fn))
            calls_n = dict(fn.calls)
            for i, tgt in leaf_calls:
                j = pairs.get(i)
                if j is not None and j in calls_n:
                    self.cvotes[tgt][calls_n[j]] += 1
            drefs_n = collections.defaultdict(list)
            for j, t in fn.drefs:
                drefs_n[j].append(t)
            for i, tgt in fo.drefs:
                j = pairs.get(i)
                for t2 in drefs_n.get(j, ()) if j is not None else ():
                    self.dvotes[tgt][t2] += 1

    # ---------------------------------------------------------- translation
    def data_pairs(self):
        out = {}
        for a, c in self.dvotes.items():
            (b, votes), = c.most_common(1)
            total = sum(c.values())
            if votes / total >= 0.8:
                out[a] = (b, votes, total)
        return out

    def translate(self, rva):
        sec = self.o.section(rva)
        if sec is None:
            return None, "outside image", 0.0
        if sec == ".text":
            fo = self.o.func_at(rva)
            if fo is None:
                # leaf function (no unwind entry): pair it through its callers,
                # or through lea/rip-relative loads of its address
                for votes, how in ((self.cvotes.get(rva), "leaf:calls"), (self.dvotes.get(rva), "leaf:refs")):
                    if votes:
                        (b, v), = votes.most_common(1)
                        t = sum(votes.values())
                        if v / t >= 0.8:
                            return b, f"{how} {v}/{t}", 1.0 if v >= 2 else 0.9
                r = self.sig_search(rva)
                if r is not None:
                    return r
                return None, "code, no function and no matched caller", 0.0
            m = self.fmap.get(fo.start)
            if m is None:
                return None, f"function {fo.start:#x} unmatched", 0.0
            fn = self.n.by_start[m[0]]
            off = rva - fo.start
            if off == 0:
                return fn.start, f"func:{m[1]}", 1.0 if m[1] in ("hash", "callgraph", "lea") else 0.8
            # mid-function: find the instruction containing rva
            k = bisect.bisect_right(fo.insn_offs, off) - 1
            intra = off - fo.insn_offs[k]
            pairs = dict(self.aligned(fo, fn))
            if k not in pairs:
                return None, f"mid-function site in changed code (func {fo.start:#x}+{off:#x})", 0.0
            j = pairs[k]
            conf = 1.0 if fo.h == fn.h else 0.7
            return fn.start + fn.insn_offs[j] + intra, f"mid:{m[1]}", conf
        # data
        dp = self.data_pairs()
        if rva in dp:
            b, v, t = dp[rva]
            return b, f"data:refs {v}/{t}", 1.0 if v >= 2 else 0.9
        vt = self.vtable_pair(rva)
        if vt is not None:
            return vt, "data:rtti", 1.0
        keys = sorted(dp)
        i = bisect.bisect_right(keys, rva) - 1
        if 0 <= i < len(keys) - 1:
            lo, hi = keys[i], keys[i + 1]
            dlo, dhi = dp[lo][0] - lo, dp[hi][0] - hi
            if dlo == dhi and rva - lo < 0x10000:
                return rva + dlo, f"data:interp {lo:#x}..{hi:#x}", 0.8
            if rva - lo < 0x40:
                return rva + dlo, f"data:inside {lo:#x}+{rva - lo:#x}", 0.6
        return None, f"data in {sec}, no reference", 0.0

    def local_delta(self, rva):
        """Delta of the nearest matched functions around rva, if they agree."""
        i = bisect.bisect_right(self.o.starts, rva)
        lo = hi = None
        for k in range(i - 1, max(-1, i - 200), -1):
            m = self.fmap.get(self.o.funcs[k].start)
            if m:
                lo = m[0] - self.o.funcs[k].start
                break
        for k in range(i, min(len(self.o.funcs), i + 200)):
            m = self.fmap.get(self.o.funcs[k].start)
            if m:
                hi = m[0] - self.o.funcs[k].start
                break
        return lo, hi

    def sig_search(self, rva, n=24, window=0x4000):
        """Find the code at rva in the new build near the local delta: masked
        bytes must match and every branch target must map to the same place."""
        sig, targets = _masked(self.io, rva, n)
        if len(sig) < 5:
            return None
        lo, hi = self.local_delta(rva)
        deltas = {d for d in (lo, hi) if d is not None}
        if not deltas:
            return None
        cands = set()
        for d in deltas:
            base = rva + d
            for c in range(base - window, base + window):
                if self.inew.read(c, 1) != sig[:1]:
                    continue
                s2, t2 = _masked(self.inew, c, n)
                if s2 != sig or len(t2) != len(targets):
                    continue
                ok = True
                for t_old, t_new in zip(targets, t2):
                    fo = self.o.func_at(t_old) if t_old not in self.o.by_start else self.o.by_start[t_old]
                    mapped = self.fmap.get(t_old, (None,))[0]
                    if mapped is None and t_old in self.cvotes:
                        mapped = self.cvotes[t_old].most_common(1)[0][0]
                    if mapped is not None and mapped != t_new:
                        ok = False
                        break
                if ok:
                    cands.add(c)
        if len(cands) == 1:
            return cands.pop(), f"sig:{n}B near delta", 0.9
        return None

    def vtable_pair(self, rva):
        if not hasattr(self, "_vt_old"):
            self._vt_old = {v: k for k, v in self.o.idx.vtables.items()}
        name = self._vt_old.get(rva)
        if name is None:
            # inside a vtable: slot address
            for base in range(rva, rva - 0x1000, -8):
                if base in self._vt_old:
                    nb = self.n.idx.vtables.get(self._vt_old[base])
                    return nb + (rva - base) if nb else None
            return None
        return self.n.idx.vtables.get(name)


def _masked(img, rva, n):
    """Bytes at rva with rel branch immediates and rip displacements zeroed,
    plus the list of absolute branch targets in order."""
    import capstone

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    code = img.read(rva, n + 16)
    out, targets, used = bytearray(), [], 0
    for ins in md.disasm(code, rva):
        if used >= n:
            break
        b = bytearray(ins.bytes)
        if ins.imm_size and ins.imm_offset and (ins.mnemonic in ("call", "jmp") or ins.mnemonic.startswith("j")):
            b[ins.imm_offset:ins.imm_offset + ins.imm_size] = b"\0" * ins.imm_size
            for op in ins.operands:
                if op.type == capstone.x86.X86_OP_IMM:
                    targets.append(op.imm)
        if ins.disp_offset and ins.disp_size and "rip" in ins.op_str:
            b[ins.disp_offset:ins.disp_offset + ins.disp_size] = b"\0" * ins.disp_size
        out += b
        used += ins.size
    return bytes(out), targets


def _tokens(img, f):
    """Normalised per-instruction tokens for diffing a changed function."""
    import capstone

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    code = img.read(f.start, f.end - f.start)
    out = []
    for ins in md.disasm(code, f.start):
        b = bytearray(ins.bytes)
        if ins.imm_size and ins.imm_offset and ins.mnemonic in ("call", "jmp") or ins.mnemonic.startswith("j"):
            if ins.imm_size and ins.imm_offset:
                b[ins.imm_offset:ins.imm_offset + ins.imm_size] = b"\0" * ins.imm_size
        if ins.disp_offset and ins.disp_size and "rip" in ins.op_str:
            b[ins.disp_offset:ins.disp_offset + ins.disp_size] = b"\0" * ins.disp_size
        out.append(bytes(b))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("old")
    ap.add_argument("new")
    ap.add_argument("--out", default="rva_map.json")
    a = ap.parse_args()
    io_, in_ = pe_index.Image(a.old), pe_index.Image(a.new)
    old, new = Side(pe_index.build(a.old)), Side(pe_index.build(a.new))
    print(f"old {old.idx.version}: {len(old.funcs)} funcs | new {new.idx.version}: {len(new.funcs)} funcs")
    m = Matcher(old, new, io_, in_)
    for row in m.run():
        print("  stage", row)
    print(f"matched functions: {len(m.fmap)}/{len(old.funcs)} ({100 * len(m.fmap) / len(old.funcs):.1f}%), "
          f"identical code: {sum(1 for a2, (b2, _) in m.fmap.items() if old.by_start[a2].h == new.by_start[b2].h)}")

    hits = inventory.scan()
    results = {}
    for h in hits:
        r = h["rva"]
        if r in results:
            results[r]["uses"].append(f"{h['file']}:{h['line']}")
            continue
        new_rva, how, conf = m.translate(r)
        sec = old.section(r)
        fo = old.func_at(r) if sec == ".text" else None
        fn = new.by_start.get(m.fmap.get(fo.start, (None,))[0]) if fo else None
        results[r] = {
            "old": f"{r:#x}", "new": f"{new_rva:#x}" if new_rva is not None else None,
            "section": sec, "method": how, "confidence": conf,
            "identical_code": bool(fo and fn and fo.h == fn.h),
            "old_size": (fo.end - fo.start) if fo else None,
            "new_size": (fn.end - fn.start) if fn else None,
            "uses": [f"{h['file']}:{h['line']}"], "context": h["context"],
        }
    Path(a.out).write_text(json.dumps(results, indent=1), encoding="utf-8")
    c = collections.Counter()
    for v in results.values():
        c["resolved" if v["new"] else ("not an address" if v["section"] is None else "UNRESOLVED")] += 1
    print(dict(c))
    print(f"wrote {a.out}")


if __name__ == "__main__":
    main()
