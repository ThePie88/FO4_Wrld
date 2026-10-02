"""L5 stage 3d (2026-09-29) — the player's position inside a save.

A synthetic save with the measured layout covers the reader, the writer and
the refusals. When real checkpoints are on this machine they are moved and
read back too; the suite does not need them.
"""
from __future__ import annotations

import struct
import sys
import zlib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from server.savepos import (  # noqa: E402
    COMMONWEALTH, FLT_COUNT, GLOBAL_AUDIO, GLOBAL_SKY, PLAYER_REFID, SaveFormatError,
    _lengths, _width_for, exterior_sky, move_player, read_global_entries, read_position,
    read_worn_frame,
)

WS = (1 << 22) | COMMONWEALTH
FRAME = (2 << 22) | 0x139F          # a runtime reference, the worn frame
ZOMBIE = (2 << 22) | 0x1353         # a destroyed copy the engine keeps saving
FRAME_BASE = (1 << 22) | 0x2079E


def _refid(v: int) -> bytes:
    return bytes(((v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF))


def _form(refid: int, flags: int, body: bytes, compressed: bool, width: int = 1,
          ftype: int = 1) -> bytes:
    """A change form: type 1 is an actor (the player), 0 a reference (a frame)."""
    stored = zlib.compress(body, 6) if compressed else body
    l2 = len(body) if compressed else 0
    return (_refid(refid) + struct.pack("<I", flags) + bytes(((width << 6) | ftype, 1))
            + _lengths(width, len(stored), l2) + stored)


CELLAR = (1 << 22) | 0x0A36EA       # the Sanctuary cellar, the measured interior


def _sky(outdoor: bool) -> bytes:
    """The sky entry as measured: 58 bytes of climate, weathers and times,
    the u32 mode (3 outdoors, 1 in an interior), the outdoor-data byte and,
    outdoors, 29 bytes of outdoor sky data."""
    head = (_refid(0x40015F) + _refid(0x5CC186) + b"\0\0\0" + _refid(0x5CC186) + b"\0" * 6
            + struct.pack("<3f", 14.8, 13.8, 1.0) + b"\x20\x00\x00\x01" + b"\0" * 20
            + struct.pack("<f", 0.8))
    assert len(head) == 58
    if not outdoor:
        return head + struct.pack("<I", 1) + b"\x00"
    return head + struct.pack("<I", 3) + b"\x01" + b"\xff\xff\x7f\x7f" + b"OUTDOOR-SKY-DATA-25BYTES!"


def _audio(outdoor: bool) -> bytes:
    return _refid(0x43C752) + b"\0" + _refid(0x4D4C3E if outdoor else 0x42D4C2) + b"\0" * 5


def _frame_body(pos, flags: int, space: int = WS) -> bytes:
    return (_refid(space) + struct.pack("<6f", pos[0] + 300.0, pos[1], pos[2], 0.0, 0.0, 0.9)
            + b"\x03" + _refid(FRAME_BASE) + struct.pack("<I", flags) + b"FRAME-TAIL" * 5)


def build_save(*, pos=(-79029.3, 90693.0, 7830.1), yaw=4.0, space=WS, move_flag=True,
               compressed=True, with_location=True, with_player=True, tail=b"PLAYER-TAIL" * 40,
               frame=False, linked=True, zombie=False, cell=None, sky=True) -> bytes:
    """`cell`: the player saved in that interior, the way the engine writes
    it (Player Location: the worldspace, grid (-1, 0), the cell; the move
    data: the cell), with the interior's sky and sound unless `sky` is
    False; outdoors, the outdoor ones."""
    header = struct.pack("<I", 15) + b"synthetic header" + struct.pack("<II", 0, 0)
    out = bytearray(b"FO4_SAVEGAME" + struct.pack("<I", len(header)) + header)
    out += bytes((69,))
    ver = b"1.11.191.0"
    out += struct.pack("<H", len(ver)) + ver
    plugin = b"Fallout4.esm"
    pi = bytes((1,)) + struct.pack("<H", len(plugin)) + plugin + struct.pack("<H", 0)
    out += struct.pack("<I", len(pi)) + pi
    flt_off = len(out)
    out += b"\0" * (FLT_COUNT * 4)

    g1 = len(out)
    g1n = 1
    out += struct.pack("<II", 0, 4) + b"MISC"
    if with_location:
        if cell is None:
            loc = (struct.pack("<I", 0xFF00270D) + _refid(space) + struct.pack("<ii", -20, 21)
                   + _refid(space) + struct.pack("<3f", *pos))
        else:
            loc = (struct.pack("<I", 0xFF00270D) + _refid(space) + struct.pack("<ii", -1, 0)
                   + _refid(cell) + struct.pack("<3f", *pos))
        out += struct.pack("<II", 1, len(loc)) + loc
        g1n += 1
    if sky:
        s, a = _sky(cell is None), _audio(cell is None)
        out += struct.pack("<II", GLOBAL_SKY, len(s)) + s
        out += struct.pack("<II", GLOBAL_AUDIO, len(a)) + a
        g1n += 2
    out += struct.pack("<II", 8, 5) + b"CELLS"      # an entry after them, as in a real save
    g1n += 1
    g2 = len(out)

    cf = len(out)
    forms = [_form(0x400001, 0, b"AAAA", False, 0)]
    here = space if cell is None else cell
    if frame:
        forms.append(_form(FRAME, 0x403, _frame_body(pos, 0x00404C0A, here), True, ftype=0))
    if with_player:
        link = (b"\x1e\xbb" + _refid(FRAME) + b"\x02") if (frame and linked) else b""
        body = _refid(here) + struct.pack("<6f", *pos, 0.17, 0.0, yaw) + tail + link + tail
        forms.append(_form(PLAYER_REFID, 0xB0000823 if move_flag else 0xB0000821, body, compressed))
    if zombie:
        forms.append(_form(ZOMBIE, 0x10000403, _frame_body((1.0, 2.0, 3.0), 0x0040090A), True,
                           ftype=0))
    forms.append(_form(0x800001, 0, b"BBBBBB", False, 0))
    for f in forms:
        out += f
    g3 = len(out)
    out += struct.pack("<II", 1000, 4) + b"GDT3"
    fid = len(out)
    out += struct.pack("<III", 2, 0x11, 0x22)
    unk3 = len(out)
    out += struct.pack("<II", 0, 0)
    flt = [0] * FLT_COUNT
    flt[0], flt[1], flt[2], flt[3], flt[4], flt[5] = fid, unk3, g1, g2, cf, g3
    flt[6], flt[7], flt[8], flt[9] = g1n, 0, 1, len(forms)
    struct.pack_into(f"<{FLT_COUNT}I", out, flt_off, *flt)
    return bytes(out)


def test_reads_both_copies():
    loc, mv = read_position(build_save())
    assert loc.worldspace == WS and loc.worldspace2 == WS
    assert (loc.grid_x, loc.grid_y) == (-20, 21)
    assert mv.space == WS
    assert mv.pos == loc.pos
    assert abs(mv.pos[0] - -79029.3) < 0.01
    assert abs(mv.rot[2] - 4.0) < 1e-6


@pytest.mark.parametrize("compressed", [True, False])
def test_move_rewrites_both_copies_and_nothing_else(compressed):
    d = build_save(compressed=compressed)
    out = move_player(d, -55911.7, 101867.7, 8542.9, 1.5)
    loc, mv = read_position(out)
    assert abs(loc.pos[1] - 101867.7) < 0.01 and abs(mv.pos[1] - 101867.7) < 0.01
    assert (loc.grid_x, loc.grid_y) == (-14, 24)
    assert mv.rot == (0.0, 0.0, pytest.approx(1.5))
    # The table moved exactly by the size change of the player's form.
    flt_off = d.index(b"Fallout4.esm") + len(b"Fallout4.esm") + 2
    before = struct.unpack_from(f"<{FLT_COUNT}I", d, flt_off)
    after = struct.unpack_from(f"<{FLT_COUNT}I", out, flt_off)
    delta = len(out) - len(d)
    assert [a - b for a, b in zip(after, before)][:6] == [delta, delta, 0, 0, 0, delta]
    # The forms around it and every table after it are untouched: form B
    # (an 11-byte header with u8 lengths) and all that follows it.
    form_b = d.index(b"BBBBBB") - 11
    assert out.endswith(d[form_b:])
    assert out[:flt_off] == d[:flt_off]
    assert out.startswith(d[:d.index(b"AAAA") + 4][:flt_off])


def test_move_is_a_round_trip():
    d = build_save()
    there = move_player(d, 1000.0, 2000.0, 300.0, 0.5)
    back = move_player(there, -79029.3, 90693.0, 7830.1, 4.0)
    assert read_position(back)[1].pos == read_position(d)[1].pos


def test_the_input_is_never_modified():
    d = build_save()
    copy = bytes(d)
    move_player(d, 0.0, 0.0, 0.0, 0.0)
    assert d == copy


@pytest.mark.parametrize("kwargs, why", [
    (dict(space=(0 << 22) | 5), "a worldspace of a plugin (an indexed refid)"),
    (dict(space=(0 << 22) | 5, cell=CELLAR), "an interior whose worldspace is a plugin's"),
    (dict(move_flag=False), "no move data"),
    (dict(with_location=False), "no Player Location"),
    (dict(with_player=False), "no player change form"),
])
def test_refusals(kwargs, why):
    with pytest.raises(SaveFormatError):
        move_player(build_save(**kwargs), 1.0, 2.0, 3.0, 0.0)


def test_refuses_garbage_and_truncation():
    d = build_save()
    with pytest.raises(SaveFormatError):
        read_position(b"NOT_A_SAVE" + d[10:])
    with pytest.raises(SaveFormatError):
        read_position(d[: len(d) // 2])
    with pytest.raises(SaveFormatError):
        move_player(d, float("nan"), 0.0, 0.0, 0.0)


def test_length_width():
    assert _width_for(200, 0) == 0 and _width_for(300, 200) == 1 and _width_for(10, 70000) == 2
    assert _lengths(1, 5, 7) == struct.pack("<HH", 5, 7)


REAL = sorted((Path.home() / "Documents/My Games/Fallout4/Saves").glob("fwck_*.fos"))


GENESIS = Path.home() / "Documents/My Games/Fallout4/Saves/world_base.fos"


@pytest.mark.skipif(not REAL, reason="no real checkpoint on this machine")
def test_real_checkpoints_move_and_read_back():
    outdoor = exterior_sky(GENESIS.read_bytes()) if GENESIS.is_file() else None
    for p in REAL[-3:]:
        d = p.read_bytes()
        loc, mv = read_position(d)
        assert loc.pos == mv.pos, p.name
        if loc.worldspace2 != loc.worldspace and outdoor is None:
            continue   # an interior, and no genesis save on this machine to take the sky from
        out = move_player(d, -55911.7, 101867.7, 8542.9, 0.0, exterior_globals=outdoor)
        assert read_position(out)[1].pos[0] == pytest.approx(-55911.7, abs=0.01), p.name
        exterior_sky(out)   # outdoors, with the outdoor sky, whatever the source was


def _stored_form(d: bytes, rid: int) -> bytes:
    """The raw bytes of one change form, found by walking them."""
    import server.savepos as sp
    lay = sp._layout(d)
    for f in sp._walk_forms(d, lay.flt):
        if f.rid == rid:
            return d[f.off:f.end]
    raise AssertionError(f"no form 0x{rid:06X}")


def test_the_worn_frame_moves_with_the_player():
    d = build_save(frame=True, zombie=True)
    wf = read_worn_frame(d)
    assert wf is not None and wf.refid == FRAME and wf.form_flags == 0x00404C0A
    out = move_player(d, -55911.7, 101867.7, 8542.9, 0.5)
    after = read_worn_frame(out)
    assert after.refid == FRAME
    assert after.move.pos[0] == pytest.approx(-55911.7, abs=0.01) and after.move.rot[2] == pytest.approx(0.5)
    assert after.form_flags == 0x00404C0A & ~0x4000
    assert read_position(out)[1].pos[1] == pytest.approx(101867.7, abs=0.01)
    assert _stored_form(out, ZOMBIE) == _stored_form(d, ZOMBIE)       # not linked: untouched


def test_a_frame_the_player_does_not_link_is_not_worn():
    d = build_save(frame=True, linked=False)
    assert read_worn_frame(d) is None
    out = move_player(d, 1.0, 2.0, 3.0, 0.0)
    assert _stored_form(out, FRAME) == _stored_form(d, FRAME)


OUTDOOR = exterior_sky(build_save())


def test_exterior_sky_reads_an_outdoor_save_and_refuses_an_interior():
    assert OUTDOOR == {GLOBAL_SKY: _sky(True), GLOBAL_AUDIO: _audio(True)}
    with pytest.raises(SaveFormatError):
        exterior_sky(build_save(cell=CELLAR))
    with pytest.raises(SaveFormatError):
        exterior_sky(build_save(sky=False))


def test_an_interior_needs_an_outdoor_sky():
    with pytest.raises(SaveFormatError):
        move_player(build_save(cell=CELLAR), 1.0, 2.0, 3.0, 0.0)
    with pytest.raises(SaveFormatError):
        move_player(build_save(cell=CELLAR), 1.0, 2.0, 3.0, 0.0,
                    exterior_globals={GLOBAL_SKY: _sky(True)})


def test_the_outdoor_sky_replaces_the_interiors_and_nothing_else():
    d = build_save(cell=CELLAR, pos=(-72.1, -104.1, -8.7), frame=True, zombie=True)
    out = move_player(d, -79857.5, 89852.6, 7821.7, 0.0, exterior_globals=OUTDOOR)
    assert read_global_entries(out, (GLOBAL_SKY, GLOBAL_AUDIO)) == OUTDOOR
    assert read_global_entries(out, (0, 8)) == read_global_entries(d, (0, 8))
    assert _stored_form(out, ZOMBIE) == _stored_form(d, ZOMBIE)
    assert _stored_form(out, 0x800001) == _stored_form(d, 0x800001)
    assert out.endswith(d[-len(b"GDT3") - 8 - 12 - 8:])   # global data 3 and the tables after it
    import server.savepos as sp
    grew = sp._layout(out).flt[3] - sp._layout(d).flt[3]   # where global data 2 starts
    assert grew == len(_sky(True)) - len(_sky(False))


def test_an_exterior_keeps_its_own_sky_even_when_one_is_given():
    d = build_save()
    other = {GLOBAL_SKY: _sky(True)[:-1] + b"?", GLOBAL_AUDIO: _audio(True)}
    out = move_player(d, 1.0, 2.0, 3.0, 0.0, exterior_globals=other)
    assert read_global_entries(out, (GLOBAL_SKY, GLOBAL_AUDIO)) == OUTDOOR


def test_an_interior_moves_out_to_the_point():
    d = build_save(cell=CELLAR, pos=(-72.1, -104.1, -8.7))
    loc, mv = read_position(d)
    assert (loc.worldspace, loc.worldspace2, mv.space) == (WS, CELLAR, CELLAR)
    out = move_player(d, -79857.5, 89852.6, 7821.7, 0.0, exterior_globals=OUTDOOR)
    loc, mv = read_position(out)
    assert (loc.worldspace, loc.worldspace2, mv.space) == (WS, WS, WS)
    assert (loc.grid_x, loc.grid_y) == (-20, 21)
    assert loc.pos[0] == pytest.approx(-79857.5, abs=0.01) and mv.pos[2] == pytest.approx(7821.7, abs=0.01)


def test_an_interior_entered_at_boot_moves_out_too():
    # Live test #21: B booted inside the cellar, its checkpoint names no
    # worldspace at all in Player Location.
    d = build_save(cell=CELLAR, space=0, pos=(-99.7, 47.5, 1.3))
    loc, mv = read_position(d)
    assert (loc.worldspace, loc.worldspace2, mv.space) == (0, CELLAR, CELLAR)
    out = move_player(d, -79857.5, 89852.6, 7821.7, 0.0, exterior_globals=OUTDOOR)
    loc, mv = read_position(out)
    assert (loc.worldspace, loc.worldspace2, mv.space) == (WS, WS, WS)
    assert exterior_sky(out) == OUTDOOR


def test_an_interior_with_a_worn_frame_takes_it_out_too():
    d = build_save(cell=CELLAR, pos=(-72.1, -104.1, -8.7), frame=True)
    assert read_worn_frame(d).move.space == CELLAR
    out = move_player(d, -79857.5, 89852.6, 7821.7, 0.0, expect_worn_frame=True,
                      exterior_globals=OUTDOOR)
    wf = read_worn_frame(out)
    assert wf.move.space == WS and wf.move.pos[1] == pytest.approx(89852.6, abs=0.01)


def test_an_interior_whose_copies_disagree_is_refused():
    d = build_save(cell=CELLAR)
    # The move data names another cell than Player Location.
    other = build_save(cell=(1 << 22) | 0x0A36EB)
    import server.savepos as sp
    lay = sp._layout(d)
    lo = lay.location_off
    mixed = d[:lo] + other[lo:lo + 30] + d[lo + 30:]
    assert read_position(mixed)[0].worldspace2 != read_position(mixed)[1].space
    with pytest.raises(SaveFormatError):
        move_player(mixed, 1.0, 2.0, 3.0, 0.0, exterior_globals=OUTDOOR)


def test_the_callers_expectation_is_enforced():
    with pytest.raises(SaveFormatError):
        move_player(build_save(), 1.0, 2.0, 3.0, 0.0, expect_worn_frame=True)
    with pytest.raises(SaveFormatError):
        move_player(build_save(frame=True), 1.0, 2.0, 3.0, 0.0, expect_worn_frame=False)
    assert read_worn_frame(move_player(build_save(frame=True), 1.0, 2.0, 3.0, 0.0,
                                       expect_worn_frame=True)) is not None
    assert read_worn_frame(move_player(build_save(), 1.0, 2.0, 3.0, 0.0,
                                       expect_worn_frame=False)) is None
