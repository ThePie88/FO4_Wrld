r"""Read the player's inventory out of a Fallout 4 save file (.fos).

L5 stage 2 (2026-09-27). The DLL captures the player's inventory from memory
once a second (fw_native/src/persist/inventory_capture.cpp). The proof that
the capture is the whole inventory is a diff against what the engine itself
writes: the inventory sub-record of the player's change form in a save. This
tool reads that sub-record.

Format, from the decomp of 1.11.191 (the writers, read 2026-09-27):
  BGSInventoryList::SaveGame sub_14034E9F0: u32 entry count, then per entry
  BGSInventoryItem::SaveGame sub_140349F40: refid(base) + u32 stack count,
  then per stack Stack::SaveGame sub_140349150: ExtraDataList::SaveGame
  sub_140292D70 + i32 count + u16 flags. ExtraDataList::SaveGame: vsval
  count of the extras written, then per extra u8 type + payload; in this
  context only the 24 types with bit 0x400 in dword_142ECED90 are written.
  A refid is 3 bytes big-endian: kind = top 2 bits (0 = index into the
  save's form-id array, 1 = base-game form id, 2 = runtime 0xFF form), value
  = low 22 bits. A vsval is 1, 2 or 4 bytes: low 2 bits give the width.

The sub-record sits behind actor-specific data of unknown layout, so it is
found by search: the first offset from which a full, consistent parse
succeeds. Every refid must resolve, every extra type must be one of the 24,
every count must be sane.

Usage:
  python tools/fos_inventory.py <save.fos> [--json out.json] [--diff fw_inventory.json]
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
import zlib
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Optional

PLAYER_REFID = 0x400014          # kind 1, form id 0x14
CHANGE_REFR_INVENTORY = 0x00000020
CHANGE_REFR_LEVELED_INVENTORY = 0x08000000

# The 24 extra types a save keeps per inventory stack.
PERSISTED = {
    0x1C: "ReferenceHandles", 0x21: "Ownership", 0x22: "Global", 0x23: "Rank",
    0x24: "Count", 0x25: "Health", 0x27: "TimeLeft", 0x28: "Charge",
    0x2E: "LeveledItem", 0x2F: "Scale", 0x35: "ObjectInstance", 0x3D: "CannotWear",
    0x3E: "Poison", 0x48: "StartingWorldOrCell", 0x49: "Favorite",
    0x88: "AliasInstanceArray", 0x8E: "OutfitItem", 0x95: "FromAlias",
    0x99: "TextDisplayData", 0x9B: "Enchantment", 0x9C: "Soul", 0x9F: "UniqueID",
    0xA0: "Flags", 0xC9: "ModRank",
}


class ParseError(ValueError):
    pass


class Reader:
    __slots__ = ("d", "pos", "end", "formids")

    def __init__(self, data: bytes, pos: int, end: int, formids: list[int]) -> None:
        self.d = data
        self.pos = pos
        self.end = end
        self.formids = formids

    def need(self, n: int) -> None:
        if self.pos + n > self.end:
            raise ParseError(f"truncated at {self.pos:#x} (need {n})")

    def u8(self) -> int:
        self.need(1); v = self.d[self.pos]; self.pos += 1; return v

    def u16(self) -> int:
        self.need(2); v = struct.unpack_from("<H", self.d, self.pos)[0]; self.pos += 2; return v

    def u32(self) -> int:
        self.need(4); v = struct.unpack_from("<I", self.d, self.pos)[0]; self.pos += 4; return v

    def i32(self) -> int:
        self.need(4); v = struct.unpack_from("<i", self.d, self.pos)[0]; self.pos += 4; return v

    def f32(self) -> float:
        self.need(4); v = struct.unpack_from("<f", self.d, self.pos)[0]; self.pos += 4; return v

    def vsval(self) -> int:
        self.need(1)
        b0 = self.d[self.pos]
        width = b0 & 3
        if width == 0:
            self.pos += 1
            return b0 >> 2
        if width == 1:
            v = self.u16()
            return v >> 2
        if width == 2:
            v = self.u32()
            return v >> 2
        raise ParseError(f"bad vsval width at {self.pos:#x}")

    def refid(self) -> int:
        """The form id a 3-byte reference names. Raises when it cannot."""
        self.need(3)
        b0, b1, b2 = self.d[self.pos], self.d[self.pos + 1], self.d[self.pos + 2]
        self.pos += 3
        kind = b0 >> 6
        value = ((b0 & 0x3F) << 16) | (b1 << 8) | b2
        if kind == 0:
            if value == 0:
                return 0
            if value - 1 >= len(self.formids):
                raise ParseError(f"refid index {value} beyond the form-id array")
            return self.formids[value - 1]
        if kind == 1:
            return value
        if kind == 2:
            return 0xFF000000 | value
        raise ParseError(f"refid kind 3 at {self.pos - 3:#x}")

    def string(self) -> str:
        n = self.u16()
        self.need(n)
        s = self.d[self.pos:self.pos + n].decode("latin-1")
        self.pos += n
        return s


@dataclass
class Stack:
    count: int
    flags: int
    extras: dict[str, Any] = field(default_factory=dict)
    extra_types: list[int] = field(default_factory=list)


@dataclass
class Entry:
    base_id: int
    stacks: list[Stack]


def read_extra(r: Reader, t: int) -> Any:
    if t == 0x1C:
        return {"handles": [r.refid(), r.refid()]}
    if t == 0x21:
        return {"owner": r.refid(), "form": r.refid(), "flag": r.u8()}
    if t in (0x22, 0x48, 0x8E, 0x3E):
        return {"form": r.refid()}
    if t in (0x23, 0x2E, 0xC9):
        return {"value": r.i32()}
    if t == 0x24:
        return {"value": r.u16()}
    if t in (0x25, 0x27, 0x28, 0x2F):
        return {"value": r.f32()}
    if t == 0x35:
        template = r.u16()
        n = r.u32()
        if n > 64:
            raise ParseError(f"OIE with {n} records")
        mods = []
        for _ in range(n):
            mod = r.refid()
            attach, rank, flag = r.u8(), r.u8(), r.u8()
            mods.append({"mod": mod, "attach": attach, "rank": rank, "flag": flag})
        return {"template": template, "mods": mods}
    if t == 0x3D:
        return {}
    if t in (0x49, 0x9C):
        return {"value": r.u8()}
    if t == 0x88:
        n = r.vsval()
        if n > 256:
            raise ParseError(f"alias array with {n} entries")
        return {"aliases": [{"quest": r.refid(), "alias": r.i32()} for _ in range(n)]}
    if t == 0x95:
        return {"quest": r.refid(), "alias": r.u32()}
    if t == 0x99:
        message = r.refid()
        quest = r.refid()
        owner = r.i32()
        header = r.u16()
        name = None
        if message == 0 and quest == 0 and owner == -2:
            name = r.string()
        npairs = r.vsval()
        if npairs > 64:
            raise ParseError(f"text display with {npairs} pairs")
        pairs = [{"text": r.string(), "form": r.refid()} for _ in range(npairs)]
        return {"message": message, "quest": quest, "owner": owner, "header": header,
                "name": name, "pairs": pairs}
    if t == 0x9B:
        return {"form": r.refid(), "charge": r.u16()}
    if t == 0x9F:
        return {"id": r.u16(), "owner": r.refid()}
    if t == 0xA0:
        return {"value": r.u32()}
    raise ParseError(f"extra type {t:#x} is not a persisted inventory type")


def read_extra_list(r: Reader) -> tuple[dict[str, Any], list[int]]:
    n = r.vsval()
    if n > 64:
        raise ParseError(f"extra list with {n} entries")
    extras: dict[str, Any] = {}
    types: list[int] = []
    for _ in range(n):
        t = r.u8()
        if t not in PERSISTED:
            raise ParseError(f"extra type {t:#x} at {r.pos - 1:#x} is not persisted")
        types.append(t)
        extras[PERSISTED[t]] = read_extra(r, t)
    return extras, types


def read_inventory(r: Reader) -> list[Entry]:
    n = r.u32()
    if not 1 <= n <= 4096:
        raise ParseError(f"entry count {n}")
    entries: list[Entry] = []
    for _ in range(n):
        base = r.refid()
        if base == 0:
            raise ParseError("null base")
        nstacks = r.u32()
        if not 1 <= nstacks <= 256:
            raise ParseError(f"stack count {nstacks}")
        stacks: list[Stack] = []
        for _ in range(nstacks):
            extras, types = read_extra_list(r)
            count = r.i32()
            flags = r.u16()
            if not -1_000_000 <= count <= 1_000_000:
                raise ParseError(f"stack count {count}")
            if flags & 0xFF00:
                raise ParseError(f"stack flags {flags:#x}")
            stacks.append(Stack(count=count, flags=flags, extras=extras, extra_types=types))
        entries.append(Entry(base_id=base, stacks=stacks))
    return entries


@dataclass
class Save:
    path: Path
    version: int
    form_version: int
    plugins: list[str]
    light_plugins: list[str]
    formids: list[int]
    change_forms_off: int
    change_form_count: int
    data: bytes


def parse_save(path: Path) -> Save:
    d = path.read_bytes()
    if d[:12] != b"FO4_SAVEGAME":
        raise ParseError("not a Fallout 4 save")
    hdr_size = struct.unpack_from("<I", d, 12)[0]
    version = struct.unpack_from("<I", d, 16)[0]
    o = 16 + hdr_size
    w, h = struct.unpack_from("<II", d, o - 8)
    o += w * h * 4
    form_version = d[o]; o += 1
    n = struct.unpack_from("<H", d, o)[0]; o += 2 + n
    pi_size = struct.unpack_from("<I", d, o)[0]; o += 4
    pi_start = o
    count = d[o]; o += 1
    plugins = []
    for _ in range(count):
        n = struct.unpack_from("<H", d, o)[0]; plugins.append(d[o + 2:o + 2 + n].decode("latin-1")); o += 2 + n
    light = struct.unpack_from("<H", d, o)[0]; o += 2
    lights = []
    for _ in range(light):
        n = struct.unpack_from("<H", d, o)[0]; lights.append(d[o + 2:o + 2 + n].decode("latin-1")); o += 2 + n
    o = pi_start + pi_size
    flt = struct.unpack_from("<25I", d, o)
    fid_off, cf_off, cf_count = flt[0], flt[4], flt[9]
    fid_count = struct.unpack_from("<I", d, fid_off)[0]
    formids = list(struct.unpack_from(f"<{fid_count}I", d, fid_off + 4))
    return Save(path, version, form_version, plugins, lights, formids, cf_off, cf_count, d)


def find_change_form(save: Save, refid: int) -> Optional[tuple[int, int, int, int]]:
    """(data offset, length, flags, type) of the change form with this refid.

    A compressed form (len2 set: the DLL's test checkpoint asks the engine
    for zlib change forms, a5 = 1) is inflated into a buffer of its own and
    the offset returned is into that buffer: see `change_form_buffer`."""
    d = save.data
    o = save.change_forms_off
    for _ in range(save.change_form_count):
        raw = (d[o] << 16) | (d[o + 1] << 8) | d[o + 2]
        flags = struct.unpack_from("<I", d, o + 3)[0]
        t = d[o + 7]
        lw, typ = t >> 6, t & 0x3F
        o2 = o + 9
        if lw == 0:
            l1, l2 = d[o2], d[o2 + 1]; o2 += 2
        elif lw == 1:
            l1, l2 = struct.unpack_from("<HH", d, o2); o2 += 4
        else:
            l1, l2 = struct.unpack_from("<II", d, o2); o2 += 8
        if raw == refid:
            if l2:
                try:
                    raw_bytes = zlib.decompress(d[o2:o2 + l1])
                except zlib.error as exc:
                    raise ParseError(f"compressed change form: zlib failed ({exc})") from exc
                if len(raw_bytes) != l2:
                    raise ParseError(f"compressed change form: inflated {len(raw_bytes)} bytes, header says {l2}")
                _INFLATED[(id(save), refid)] = raw_bytes
                return 0, l2, flags, typ
            _INFLATED.pop((id(save), refid), None)
            return o2, l1, flags, typ
        o = o2 + l1
    return None


# Inflated change-form buffers, keyed by (save, refid); see find_change_form.
_INFLATED: dict[tuple[int, int], bytes] = {}


def change_form_buffer(save: Save, refid: int) -> Save:
    """The Save whose `data` holds the change form's bytes: the save itself
    for a stored-flat form, a copy over the inflated buffer otherwise."""
    raw_bytes = _INFLATED.get((id(save), refid))
    return replace(save, data=raw_bytes) if raw_bytes is not None else save


def scan_inventory(save: Save, data_off: int, length: int) -> tuple[int, list[Entry], int]:
    """Search the change-form data for the inventory sub-record. Returns
    (offset, entries, end offset) of the best candidate: the one with the
    most entries whose whole parse is consistent."""
    end = data_off + length
    best: Optional[tuple[int, list[Entry], int]] = None
    for p in range(data_off, end - 8):
        n = struct.unpack_from("<I", save.data, p)[0]
        if not 2 <= n <= 4096:
            continue
        r = Reader(save.data, p, end, save.formids)
        try:
            entries = read_inventory(r)
        except ParseError:
            continue
        if best is None or len(entries) > len(best[1]):
            best = (p, entries, r.pos)
    if best is None:
        raise ParseError("no inventory sub-record found")
    return best


def player_inventory(save: Save) -> dict[str, Any]:
    found = find_change_form(save, PLAYER_REFID)
    if found is None:
        raise ParseError("the player's change form is not in this save")
    data_off, length, flags, typ = found
    if not flags & (CHANGE_REFR_INVENTORY | CHANGE_REFR_LEVELED_INVENTORY):
        raise ParseError(f"the player's change form has no inventory (flags {flags:#x})")
    buf = change_form_buffer(save, PLAYER_REFID)
    compressed = buf is not save
    off, entries, end = scan_inventory(buf, data_off, length)
    return {
        "save": save.path.name,
        "save_version": save.version,
        "form_version": save.form_version,
        "plugins": save.plugins + save.light_plugins,
        "change_form": {"offset": data_off, "length": length, "flags": flags, "type": typ,
                        "compressed": compressed},
        "inventory": {"offset": off, "end": end, "entries": len(entries),
                      "stacks": sum(len(e.stacks) for e in entries)},
        "entries": [
            {"base": e.base_id,
             "stacks": [{"count": s.count, "flags": s.flags,
                         "extra_types": s.extra_types, "extras": s.extras}
                        for s in e.stacks]}
            for e in entries
        ],
    }


def normalize(inv: dict[str, Any]) -> list[dict[str, Any]]:
    """One line per stack, the shape the DLL's manifest uses, for diffs."""
    out = []
    for e in inv["entries"]:
        for s in e["stacks"]:
            x = s["extras"]
            oie = x.get("ObjectInstance") or {}
            txt = x.get("TextDisplayData") or {}
            out.append({
                "base": e["base"], "count": s["count"], "flags": s["flags"],
                "extra_types": sorted(s["extra_types"]),
                "health": (x.get("Health") or {}).get("value"),
                "charge": (x.get("Charge") or {}).get("value"),
                "favorite": (x.get("Favorite") or {}).get("value"),
                "uid": (x.get("UniqueID") or {}).get("id"),
                "mods": [(m["mod"], m["attach"], m["rank"], m["flag"]) for m in oie.get("mods", [])],
                "template": oie.get("template"),
                "name": txt.get("name"), "text_owner": txt.get("owner"),
            })
    out.sort(key=lambda r: (r["base"], r["count"], r["flags"], str(r["mods"])))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("save", type=Path)
    ap.add_argument("--json", type=Path, default=None, help="write the parsed inventory here")
    ap.add_argument("--diff", type=Path, default=None,
                    help="the DLL's fw_inventory.json to compare with (stage 2 proof)")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    save = parse_save(args.save)
    inv = player_inventory(save)
    if not args.quiet:
        print(f"{save.path.name}: save v{save.version} form v{save.form_version}, "
              f"{len(save.formids)} form ids, {len(save.plugins)} + {len(save.light_plugins)} plugins")
        cf = inv["change_form"]; iv = inv["inventory"]
        print(f"player change form at {cf['offset']:#x} ({cf['length']} bytes, flags {cf['flags']:#010x}); "
              f"inventory at {iv['offset']:#x}..{iv['end']:#x}: {iv['entries']} entries, {iv['stacks']} stacks")
        for line in normalize(inv):
            mods = ",".join(f"{m[0]:X}" for m in line["mods"])
            extra = " ".join(PERSISTED[t] for t in line["extra_types"])
            print(f"  0x{line['base']:06X} x{line['count']:<4} flags=0x{line['flags']:04X}"
                  f"{'  hp=' + format(line['health'], '.3f') if line['health'] is not None else ''}"
                  f"{'  chg=' + format(line['charge'], '.1f') if line['charge'] is not None else ''}"
                  f"{'  fav=' + str(line['favorite']) if line['favorite'] is not None else ''}"
                  f"{'  uid=' + str(line['uid']) if line['uid'] is not None else ''}"
                  f"{'  mods=[' + mods + ']' if mods else ''}"
                  f"{'  name=' + repr(line['name']) if line['name'] else ''}"
                  f"{'  [' + extra + ']' if extra else ''}")
    if args.json:
        args.json.write_text(json.dumps(inv, indent=2), encoding="utf-8", newline="\n")
        print(f"written {args.json}")
    if args.diff:
        dll = json.loads(args.diff.read_text(encoding="utf-8"))
        rc = diff_against_dll(normalize(inv), dll)
        return rc
    return 0


def diff_against_dll(save_lines: list[dict[str, Any]], dll: dict[str, Any]) -> int:
    """Compare per-base totals and per-stack instance data with the DLL's
    manifest dump. Returns 0 when they agree."""
    def totals(lines):
        t: dict[int, int] = {}
        for l in lines:
            t[l["base"]] = t.get(l["base"], 0) + l["count"]
        return t
    dll_lines = dll.get("records", [])
    a, b = totals(save_lines), totals(dll_lines)
    bad = 0
    for base in sorted(set(a) | set(b)):
        if a.get(base, 0) != b.get(base, 0):
            bad += 1
            print(f"MISMATCH 0x{base:06X}: save {a.get(base, 0)} vs capture {b.get(base, 0)}")
    def keyset(lines):
        return sorted((l["base"], l["count"], tuple(tuple(m) for m in l["mods"]),
                       None if l.get("health") is None else round(l["health"], 3),
                       l.get("name") or None) for l in lines)
    ka, kb = keyset(save_lines), keyset(dll_lines)
    if ka != kb:
        only_save = [k for k in ka if k not in kb]
        only_dll = [k for k in kb if k not in ka]
        for k in only_save:
            bad += 1; print(f"only in the save:    base 0x{k[0]:06X} x{k[1]} mods={['%X' % m[0] for m in k[2]]} hp={k[3]} name={k[4]!r}")
        for k in only_dll:
            bad += 1; print(f"only in the capture: base 0x{k[0]:06X} x{k[1]} mods={['%X' % m[0] for m in k[2]]} hp={k[3]} name={k[4]!r}")
    print("IDENTICAL" if bad == 0 else f"{bad} difference(s)")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
