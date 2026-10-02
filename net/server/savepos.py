"""L5 stage 3d (2026-09-29) — the player's position inside a Fallout 4 save.

The server moves a dead player by editing the checkpoint the client will
reload: the reload itself lands the player on the respawn point, with one
loading screen and no fast travel. This module reads and writes the places
a save keeps the player's position, and refuses anything that does not look
exactly like what was measured.

Format (1.11.191 saves, form version 69, verified 2026-09-28/29 against
checkpoints whose position the server also had, to the decimal):

  "FO4_SAVEGAME", u32 header size, header (ending with the screenshot's
  u32 width and height), RGBA screenshot, u8 form version, u16-prefixed game
  version string, u32 plugin info size and the plugin info, then the file
  location table: 25 u32.
    [0] form id array count offset   [1] unknown table 3 offset
    [2] global data table 1 offset   [3] global data table 2 offset
    [4] change forms offset          [5] global data table 3 offset
    [6] [7] [8] entry counts of the global data tables 1, 2, 3
    [9] change form count            [10..24] unused
  Global data entries are u32 type, u32 length, data. Type 1 of table 1 is
  "Player Location", 30 bytes: u32 next object id, refid of the worldspace,
  i32 grid x, i32 grid y, refid of the worldspace, f32 x, y, z.
  A change form is a 3-byte big-endian refid, u32 change flags, u8 type
  whose top two bits give the width of the two lengths that follow (u8,
  u16, u32), u8 version, length 1 (the stored bytes), length 2 (the
  inflated size, 0 when stored flat), then the data. The player's (refid
  0x400014) is zlib-compressed in our checkpoints and starts with its move
  data: the refid of its worldspace (an exterior) or cell (an interior),
  then position and rotation, six f32.

A refid is kind (top 2 bits: 0 = index into the form id array, 1 = a form
of the base game, 2 = a runtime 0xFF form) and a 22-bit value.

Power armour (2026-09-29): a frame the player wears is a reference of its
own, a runtime one, and the engine re-seats the player into it at load, so
moving the player alone would leave the frame at its old place. Its change
form starts with the same move data, then a byte, the refid of its base
(the frame furniture 0x2079E) and its u32 form flags. The player's record
links it: extra type 0xBB (ExtraPowerArmor) followed by the frame's refid,
exactly once in the one checkpoint measured in power armour and never in
the others. Disabled frames that are not linked are the leftovers of
destroyed copies (the engine keeps saving them) and are left alone. The
worn frame is moved with the player, and the temporary bit (0x4000) our
world spawn put on its replicas is cleared in its saved flags: with that
bit the engine looks for a worn frame's cell in extra data it does not
have, and the next save of a player who carried the frame into another
cell crashed (live tests #11 and #12).

An interior (measured 2026-09-29 on five checkpoints written in the
Sanctuary cellar, cell 0x0A36EA, by both test clients): Player Location
keeps the worldspace (0x3C) in its first refid and names the cell in its
second, the grid reads (-1, 0), the position is the cell's own; the move
data names the same cell. The first refid is the last worldspace of the
session, null when the session started inside the interior (2026-09-30,
B's checkpoint written after booting in the cellar: 0x000000). Moving the player out of it writes the fields an
exterior move writes: both refids become the worldspace, the grid and the
position the point's.

The sky and the sound come with the place (2026-09-30, live test #20: a
cellar checkpoint moved outdoors loaded with no shadows, the saturation
and the gamma off and a purple sky, until the player went through a door).
Global data 1 type 6 holds the climate and weather refids, the weather
times, then at offset 58 a u32 sky mode (3 in all the saves written
outdoors, 1 in all those written in the cellar) and at 62 a byte that says
whether the outdoor sky data follows (92 bytes in all, 63 without); type 7
names the acoustic space among others. Moving a player out of an interior
replaces both with those of a save written outdoors (exterior_sky: the
genesis save), whole: the refids inside are forms of the base game and the
player (0x14), valid in any save. Global data 1 then changes size, and
every offset of the table past it moves by the difference.

Moving rewrites Player Location in place (fixed size) and the start of the
player's change form and of the worn frame's, compressed again: their
stored lengths change, so every offset of the table that points past the
change forms moves by the sum of the differences. The result is parsed
again and compared before it is returned.
"""
from __future__ import annotations

import math
import struct
import zlib
from dataclasses import dataclass
from typing import Iterator, Optional

MAGIC = b"FO4_SAVEGAME"
PLAYER_REFID = 0x400014
COMMONWEALTH = 0x3C
REFID_KIND_BASE_GAME = 1
REFID_KIND_RUNTIME = 2
GLOBAL_PLAYER_LOCATION = 1
PLAYER_LOCATION_SIZE = 30
CHANGE_REFR_MOVE = 0x00000002
MOVE_SIZE = 3 + 6 * 4
CELL_UNITS = 4096.0
FLT_COUNT = 25
FORM_TYPE_REFR = 0
PA_FRAME_BASE = 0x2079E
EXTRA_POWER_ARMOR = 0xBB
FRAME_BASE_OFF = 28          # in a frame's change form: move data, a byte, the base refid
FRAME_FLAGS_OFF = 31         # then the frame's form flags, u32
FORM_FLAG_TEMPORARY = 0x4000
GLOBAL_SKY = 6               # global data 1: the sky (see the module)
GLOBAL_AUDIO = 7             # global data 1: the sound of the place
SKY_MODE_OFF = 58            # in the sky entry: u32 mode, then the outdoor-data byte
SKY_MODE_FULL = 3            # outdoors; 1 in an interior


class SaveFormatError(ValueError):
    """The bytes are not a save this module understands. Nothing was changed."""


@dataclass(frozen=True)
class PlayerLocation:
    next_object_id: int
    worldspace: int        # refid, raw 24 bits
    grid_x: int
    grid_y: int
    worldspace2: int       # refid, raw 24 bits
    pos: tuple[float, float, float]


@dataclass(frozen=True)
class PlayerMove:
    space: int             # refid of the worldspace (exterior) or cell (interior)
    pos: tuple[float, float, float]
    rot: tuple[float, float, float]


@dataclass(frozen=True)
class WornFrame:
    refid: int             # raw 24 bits, kind 2
    move: PlayerMove       # the frame's own move data
    form_flags: int


@dataclass(frozen=True)
class _Form:
    rid: int
    off: int               # the header
    change_flags: int
    type_byte: int
    version: int
    width: int
    length1: int
    length2: int
    data_off: int

    @property
    def end(self) -> int:
        return self.data_off + self.length1


@dataclass(frozen=True)
class _Layout:
    flt_off: int
    flt: tuple[int, ...]
    location_off: int      # the 30 bytes of Player Location
    player: _Form


def _refid(d: bytes, o: int) -> int:
    return (d[o] << 16) | (d[o + 1] << 8) | d[o + 2]


def _refid_bytes(v: int) -> bytes:
    return bytes(((v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF))


def _need(d: bytes, o: int, n: int, what: str) -> None:
    if o < 0 or o + n > len(d):
        raise SaveFormatError(f"{what}: {n} byte(s) at offset {o} run past the end ({len(d)})")


def _walk_forms(d: bytes, flt: tuple[int, ...]) -> Iterator[_Form]:
    o = flt[4]
    for _ in range(flt[9]):
        _need(d, o, 9, "change form header")
        rid = _refid(d, o)
        flags = struct.unpack_from("<I", d, o + 3)[0]
        tb = d[o + 7]
        ver = d[o + 8]
        width = tb >> 6
        o2 = o + 9
        if width == 0:
            _need(d, o2, 2, "change form lengths")
            l1, l2 = d[o2], d[o2 + 1]
            o2 += 2
        elif width == 1:
            _need(d, o2, 4, "change form lengths")
            l1, l2 = struct.unpack_from("<HH", d, o2)
            o2 += 4
        elif width == 2:
            _need(d, o2, 8, "change form lengths")
            l1, l2 = struct.unpack_from("<II", d, o2)
            o2 += 8
        else:
            raise SaveFormatError(f"change form at {o}: length width {width}")
        _need(d, o2, l1, "change form data")
        yield _Form(rid, o, flags, tb, ver, width, l1, l2, o2)
        o = o2 + l1
    if o != flt[5]:
        raise SaveFormatError(f"change forms end at {o}, global data 3 starts at {flt[5]}")


def _layout(d: bytes) -> _Layout:
    _need(d, 0, 16, "header")
    if d[:12] != MAGIC:
        raise SaveFormatError("not a Fallout 4 save (magic)")
    hdr_size = struct.unpack_from("<I", d, 12)[0]
    o = 16 + hdr_size
    _need(d, o - 8, 8, "screenshot size")
    w, h = struct.unpack_from("<II", d, o - 8)
    if w > 4096 or h > 4096:
        raise SaveFormatError(f"screenshot {w}x{h} is not plausible")
    o += w * h * 4
    _need(d, o, 3, "form version")
    o += 1
    n = struct.unpack_from("<H", d, o)[0]
    o += 2 + n
    _need(d, o, 4, "plugin info size")
    pi_size = struct.unpack_from("<I", d, o)[0]
    o += 4 + pi_size
    flt_off = o
    _need(d, flt_off, FLT_COUNT * 4, "file location table")
    flt = struct.unpack_from(f"<{FLT_COUNT}I", d, flt_off)
    fid, unk3, g1, g2, cf, g3 = flt[0], flt[1], flt[2], flt[3], flt[4], flt[5]
    if not (flt_off + FLT_COUNT * 4 <= g1 <= g2 <= cf <= g3 <= fid <= unk3 <= len(d)):
        raise SaveFormatError(f"file location table out of order: {flt[:6]} for {len(d)} bytes")

    location_off = -1
    o = g1
    for _ in range(flt[6]):
        _need(d, o, 8, "global data 1 entry")
        t, ln = struct.unpack_from("<II", d, o)
        _need(d, o + 8, ln, "global data 1 body")
        if t == GLOBAL_PLAYER_LOCATION:
            if ln != PLAYER_LOCATION_SIZE:
                raise SaveFormatError(f"Player Location is {ln} bytes, {PLAYER_LOCATION_SIZE} expected")
            location_off = o + 8
        o += 8 + ln
    if o != g2:
        raise SaveFormatError(f"global data 1 ends at {o}, table 2 starts at {g2}")
    if location_off < 0:
        raise SaveFormatError("no Player Location in global data 1")

    player: Optional[_Form] = None
    for f in _walk_forms(d, flt):
        if f.rid == PLAYER_REFID:
            if player is not None:
                raise SaveFormatError("two change forms for the player")
            player = f
    if player is None:
        raise SaveFormatError("no change form for the player")
    return _Layout(flt_off, tuple(flt), location_off, player)


def _form_body(d: bytes, f: _Form, what: str) -> bytes:
    raw = d[f.data_off:f.end]
    if f.length2 == 0:
        return raw
    try:
        body = zlib.decompress(raw)
    except zlib.error as e:
        raise SaveFormatError(f"{what} does not inflate: {e}") from e
    if len(body) != f.length2:
        raise SaveFormatError(f"{what} inflates to {len(body)} bytes, {f.length2} expected")
    return body


def _player_form_bytes(d: bytes, lay: _Layout) -> bytes:
    return _form_body(d, lay.player, "the player's change form")


def _check_float(v: float, what: str) -> None:
    if not math.isfinite(v) or abs(v) > 1.0e7:
        raise SaveFormatError(f"{what} {v!r} is not a plausible coordinate")


def _read_move(body: bytes, what: str) -> PlayerMove:
    if len(body) < MOVE_SIZE:
        raise SaveFormatError(f"{what} is only {len(body)} bytes")
    vals = struct.unpack_from("<6f", body, 3)
    for v in vals:
        _check_float(v, what)
    return PlayerMove(_refid(body, 0), (vals[0], vals[1], vals[2]), (vals[3], vals[4], vals[5]))


def read_position(d: bytes) -> tuple[PlayerLocation, PlayerMove]:
    """Both copies of the player's position. SaveFormatError when anything
    is not as measured."""
    lay = _layout(d)
    lo = lay.location_off
    nxt = struct.unpack_from("<I", d, lo)[0]
    ws1 = _refid(d, lo + 4)
    gx, gy = struct.unpack_from("<ii", d, lo + 7)
    ws2 = _refid(d, lo + 15)
    lpos = struct.unpack_from("<3f", d, lo + 18)
    for v in lpos:
        _check_float(v, "Player Location")
    if not lay.player.change_flags & CHANGE_REFR_MOVE:
        raise SaveFormatError(f"the player's change form has no move data "
                              f"(flags 0x{lay.player.change_flags:08X})")
    mv = _read_move(_player_form_bytes(d, lay), "the player's move data")
    return PlayerLocation(nxt, ws1, gx, gy, ws2, (lpos[0], lpos[1], lpos[2])), mv


def _worn_frame(d: bytes, lay: _Layout, player_body: bytes) -> Optional[tuple[_Form, bytes]]:
    """The frame the player's record links through ExtraPowerArmor, with its
    body; None when the player wears none. SaveFormatError when the link is
    ambiguous."""
    frames: dict[int, tuple[_Form, bytes]] = {}
    base = (REFID_KIND_BASE_GAME << 22) | PA_FRAME_BASE
    for f in _walk_forms(d, lay.flt):
        if f.rid >> 22 != REFID_KIND_RUNTIME or (f.type_byte & 0x3F) != FORM_TYPE_REFR:
            continue
        if not f.change_flags & CHANGE_REFR_MOVE:
            continue
        body = _form_body(d, f, f"change form 0x{f.rid:06X}")
        if len(body) >= FRAME_FLAGS_OFF + 4 and _refid(body, FRAME_BASE_OFF) == base:
            frames[f.rid] = (f, body)
    links = set()
    i = player_body.find(bytes((EXTRA_POWER_ARMOR,)))
    while 0 <= i <= len(player_body) - 4:
        rid = _refid(player_body, i + 1)
        if rid in frames:
            links.add(rid)
        i = player_body.find(bytes((EXTRA_POWER_ARMOR,)), i + 1)
    if not links:
        return None
    if len(links) > 1:
        raise SaveFormatError("the player's record links more than one power armour frame: "
                              + ", ".join(f"0x{r:06X}" for r in sorted(links)))
    return frames[links.pop()]


def read_worn_frame(d: bytes) -> Optional[WornFrame]:
    """The frame the saved player wears, or None."""
    lay = _layout(d)
    got = _worn_frame(d, lay, _player_form_bytes(d, lay))
    if got is None:
        return None
    f, body = got
    return WornFrame(f.rid, _read_move(body, f"frame 0x{f.rid:06X} move data"),
                     struct.unpack_from("<I", body, FRAME_FLAGS_OFF)[0])


def _globals1(d: bytes, lay: _Layout) -> list[tuple[int, bytes]]:
    """The entries of global data 1, in file order, as (type, body)."""
    out = []
    o = lay.flt[2]
    for _ in range(lay.flt[6]):
        t, ln = struct.unpack_from("<II", d, o)
        out.append((t, d[o + 8:o + 8 + ln]))
        o += 8 + ln
    return out


def read_global_entries(d: bytes, types) -> dict[int, bytes]:
    """The bodies of the global data 1 entries of those types found in `d`."""
    want = set(types)
    out: dict[int, bytes] = {}
    for t, body in _globals1(d, _layout(d)):
        if t in want:
            if t in out:
                raise SaveFormatError(f"two global data 1 entries of type {t}")
            out[t] = body
    return out


def exterior_sky(d: bytes) -> dict[int, bytes]:
    """The sky and sound entries of a save written outdoors (the genesis
    save), for move_player to give a checkpoint written in an interior.
    SaveFormatError when the save does not have the player outdoors, or its
    sky is not the outdoor one as measured."""
    loc, mv = read_position(d)
    if not (mv.space >> 22 == REFID_KIND_BASE_GAME and loc.worldspace == mv.space
            and loc.worldspace2 == mv.space):
        raise SaveFormatError("the save does not have the player outdoors")
    got = read_global_entries(d, (GLOBAL_SKY, GLOBAL_AUDIO))
    if set(got) != {GLOBAL_SKY, GLOBAL_AUDIO}:
        raise SaveFormatError("the save lacks the sky or the sound entry")
    sky = got[GLOBAL_SKY]
    if (len(sky) < SKY_MODE_OFF + 5
            or struct.unpack_from("<I", sky, SKY_MODE_OFF)[0] != SKY_MODE_FULL
            or sky[SKY_MODE_OFF + 4] != 1):
        raise SaveFormatError("the save's sky is not the outdoor one")
    return got


def _replace_globals(d: bytes, repl: dict[int, bytes]) -> bytes:
    """`d` with the global data 1 entries of the types in `repl` replaced by
    those bodies: the rest of the file shifts and every offset of the table
    past global data 1 moves with it. Read back before it is returned."""
    lay = _layout(d)
    flt = list(lay.flt)
    g1, g2 = flt[2], flt[3]
    old = _globals1(d, lay)
    seen = [t for t, _ in old if t in repl]
    if sorted(seen) != sorted(repl):
        raise SaveFormatError(f"global data 1 has types {sorted(seen)} of the {sorted(repl)} "
                              f"to replace, each once")
    new_g1 = b"".join(struct.pack("<II", t, len(repl.get(t, b)))
                      + repl.get(t, b) for t, b in old)
    delta = len(new_g1) - (g2 - g1)
    for i in (0, 1, 3, 4, 5):
        flt[i] += delta
    out = bytearray(d[:g1] + new_g1 + d[g2:])
    struct.pack_into(f"<{FLT_COUNT}I", out, lay.flt_off, *flt)
    result = bytes(out)
    new_lay = _layout(result)
    after = _globals1(result, new_lay)
    if [t for t, _ in after] != [t for t, _ in old]:
        raise SaveFormatError("global data 1 changed its entries")
    for (t, b_old), (_, b_new) in zip(old, after):
        if b_new != repl.get(t, b_old):
            raise SaveFormatError(f"global data 1 type {t} does not read back")
    flt_end = lay.flt_off + FLT_COUNT * 4
    if d[:lay.flt_off] != result[:lay.flt_off] or d[flt_end:g1] != result[flt_end:g1]:
        raise SaveFormatError("bytes before global data 1 changed")
    if d[g2:] != result[g2 + delta:]:
        raise SaveFormatError("bytes after global data 1 changed")
    return result


def _width_for(l1: int, l2: int) -> int:
    top = max(l1, l2)
    if top <= 0xFF:
        return 0
    if top <= 0xFFFF:
        return 1
    return 2


def _lengths(width: int, l1: int, l2: int) -> bytes:
    if width == 0:
        return bytes((l1, l2))
    if width == 1:
        return struct.pack("<HH", l1, l2)
    return struct.pack("<II", l1, l2)


def _encode_form(d: bytes, f: _Form, body: bytes) -> bytes:
    """The change form `f` with a new body, stored the way it was (flat or
    zlib), its length width widened only when the new lengths need it."""
    if f.length2 == 0:
        stored, l1, l2 = body, len(body), 0
    else:
        stored = zlib.compress(body, 6)
        l1, l2 = len(stored), len(body)
    width = f.width if _width_for(l1, l2) <= f.width else _width_for(l1, l2)
    type_byte = (f.type_byte & 0x3F) | (width << 6)
    return d[f.off:f.off + 7] + bytes((type_byte, f.version)) + _lengths(width, l1, l2) + stored


def _move_bytes(ws: int, x: float, y: float, z: float, yaw: float) -> bytes:
    return _refid_bytes(ws) + struct.pack("<6f", x, y, z, 0.0, 0.0, yaw)


def move_player(d: bytes, x: float, y: float, z: float, yaw: float,
                worldspace: int = COMMONWEALTH,
                expect_worn_frame: Optional[bool] = None,
                exterior_globals: Optional[dict[int, bytes]] = None) -> bytes:
    """The same save with the player standing at (x, y, z) facing `yaw`
    (radians, the engine's rz) in an exterior of `worldspace` (a form id of
    the base game), from a base-game exterior or from an interior as
    measured (see the module). A power armour frame the player wears is moved with it
    and loses the temporary bit in its saved flags. `expect_worn_frame`:
    True = the caller knows the player is in power armour (a linked frame
    is required), False = it knows the player is not (a linked frame is an
    error), None = whatever the save says. `exterior_globals`: the sky and
    sound entries of a save written outdoors (exterior_sky), required to
    move a player out of an interior and ignored otherwise. The result is
    parsed again and must read back what was written, with every other byte
    unchanged. SaveFormatError otherwise, and the input is never modified."""
    for v, what in ((x, "x"), (y, "y"), (z, "z"), (yaw, "yaw")):
        if not math.isfinite(v):
            raise SaveFormatError(f"{what} is not finite")
    if not 0 < worldspace < (1 << 22):
        raise SaveFormatError(f"worldspace 0x{worldspace:X} is not a base-game form id")
    before_loc, before_move = read_position(d)
    lay = _layout(d)
    ws = (REFID_KIND_BASE_GAME << 22) | worldspace
    exterior = (before_move.space >> 22 == REFID_KIND_BASE_GAME
                and before_loc.worldspace == before_move.space)
    # 2026-09-29: an interior as measured (the module's docstring): a
    # base-game worldspace first, or none (2026-09-30, live test #21: a
    # session started inside the interior leaves it null), the cell second
    # and in the move data.
    interior = (not exterior
                and (before_loc.worldspace == 0
                     or before_loc.worldspace >> 22 == REFID_KIND_BASE_GAME)
                and before_loc.worldspace2 == before_move.space)
    if not (exterior or interior):
        # A worldspace of a plugin, or copies that disagree: the exterior
        # this function writes would contradict data it does not touch.
        raise SaveFormatError(
            f"the saved player is neither in a base-game exterior nor in an interior as measured "
            f"(move space 0x{before_move.space:06X}, location spaces "
            f"0x{before_loc.worldspace:06X} and 0x{before_loc.worldspace2:06X})")
    if interior:
        # 2026-09-30 (live test #20): the interior's sky and sound would come
        # outdoors with the player. Replaced with an outdoor save's, or the
        # move is refused.
        if not exterior_globals or set(exterior_globals) != {GLOBAL_SKY, GLOBAL_AUDIO}:
            raise SaveFormatError("the player is saved in an interior and no outdoor sky was "
                                  "given to replace the interior's (exterior_sky of a save "
                                  "written outdoors)")
        d = _replace_globals(d, dict(exterior_globals))
        before_loc, before_move = read_position(d)
        lay = _layout(d)

    player_body = _player_form_bytes(d, lay)
    frame = _worn_frame(d, lay, player_body)
    if expect_worn_frame is True and frame is None:
        raise SaveFormatError("the player is in power armour but its record links no frame")
    if expect_worn_frame is False and frame is not None:
        raise SaveFormatError(f"the player's record links frame 0x{frame[0].rid:06X} but the "
                              f"player is not in power armour")
    if frame is not None and _refid(frame[1], 0) != before_move.space:
        raise SaveFormatError(f"the worn frame 0x{frame[0].rid:06X} is saved in another space "
                              f"(0x{_refid(frame[1], 0):06X}) than the player")

    gx = int(math.floor(x / CELL_UNITS))
    gy = int(math.floor(y / CELL_UNITS))
    head = bytearray(d[:lay.player.off])
    lo = lay.location_off
    head[lo + 4:lo + 7] = _refid_bytes(ws)
    struct.pack_into("<ii", head, lo + 7, gx, gy)
    head[lo + 15:lo + 18] = _refid_bytes(ws)
    struct.pack_into("<3f", head, lo + 18, x, y, z)

    move = _move_bytes(ws, x, y, z, yaw)
    new_player = move + player_body[MOVE_SIZE:]
    edits: list[tuple[_Form, bytes]] = [(lay.player, _encode_form(d, lay.player, new_player))]
    old_frame_flags = 0
    if frame is not None:
        f, body = frame
        old_frame_flags = struct.unpack_from("<I", body, FRAME_FLAGS_OFF)[0]
        new_body = bytearray(body)
        new_body[0:MOVE_SIZE] = move
        struct.pack_into("<I", new_body, FRAME_FLAGS_OFF, old_frame_flags & ~FORM_FLAG_TEMPORARY)
        edits.append((f, _encode_form(d, f, bytes(new_body))))
    edits.sort(key=lambda e: e[0].off)

    # The change forms region rebuilt around the edited forms; everything
    # before the player's form keeps its place except Player Location's
    # bytes (edited in `head`), which sits before it.
    out = bytearray()
    cursor = 0
    delta = 0
    for f, enc in edits:
        if cursor == 0:
            out += head[:f.off] if f.off <= len(head) else head + d[len(head):f.off]
        else:
            out += d[cursor:f.off]
        out += enc
        delta += len(enc) - (f.end - f.off)
        cursor = f.end
    out += d[cursor:]
    flt = list(lay.flt)
    for i in (0, 1, 5):
        flt[i] += delta
    struct.pack_into(f"<{FLT_COUNT}I", out, lay.flt_off, *flt)
    result = bytes(out)

    # Read back: every copy says what was written, everything else intact.
    f32 = lambda v: struct.unpack("<f", struct.pack("<f", v))[0]  # noqa: E731
    want = tuple(f32(v) for v in (x, y, z))
    loc, mv = read_position(result)
    if tuple(loc.pos) != want or tuple(mv.pos) != want:
        raise SaveFormatError("the patched save does not read back the new position")
    if ((loc.grid_x, loc.grid_y) != (gx, gy) or loc.worldspace != ws or loc.worldspace2 != ws
            or mv.space != ws):
        raise SaveFormatError("the patched save does not read back the new cell")
    if mv.rot[2] != f32(yaw):
        raise SaveFormatError("the patched save does not read back the new facing")
    new_lay = _layout(result)
    if _player_form_bytes(result, new_lay)[MOVE_SIZE:] != player_body[MOVE_SIZE:]:
        raise SaveFormatError("the rest of the player's change form changed")
    worn_after = read_worn_frame(result)
    if frame is None:
        if worn_after is not None:
            raise SaveFormatError("a worn frame appeared in the patched save")
    else:
        f, body = frame
        if worn_after is None or worn_after.refid != f.rid:
            raise SaveFormatError("the patched save lost the worn frame's link")
        if tuple(worn_after.move.pos) != want or worn_after.move.space != ws:
            raise SaveFormatError("the worn frame does not read back the new position")
        if worn_after.form_flags != old_frame_flags & ~FORM_FLAG_TEMPORARY:
            raise SaveFormatError("the worn frame's flags do not read back as written")
        new_frame = next(g for g in _walk_forms(result, new_lay.flt) if g.rid == f.rid)
        nb = _form_body(result, new_frame, "the patched frame")
        if nb[MOVE_SIZE:FRAME_FLAGS_OFF] != body[MOVE_SIZE:FRAME_FLAGS_OFF] or \
                nb[FRAME_FLAGS_OFF + 4:] != body[FRAME_FLAGS_OFF + 4:]:
            raise SaveFormatError("the rest of the worn frame's change form changed")
    # File order: ... the table (flt_off), global data 1 holding Player
    # Location (lo), global data 2, the change forms (the edited ones among
    # them), global data 3 and the rest.
    flt_end = lay.flt_off + FLT_COUNT * 4
    if d[:lay.flt_off] != result[:lay.flt_off]:
        raise SaveFormatError("bytes before the file location table changed")
    got_flt = struct.unpack_from(f"<{FLT_COUNT}I", result, lay.flt_off)
    if any(got_flt[i] != lay.flt[i] + (delta if i in (0, 1, 5) else 0) for i in range(FLT_COUNT)):
        raise SaveFormatError("the file location table moved in the wrong places")
    if d[flt_end:lo] != result[flt_end:lo]:
        raise SaveFormatError("bytes between the table and Player Location changed")
    shift = 0
    prev_end_old = lo + PLAYER_LOCATION_SIZE
    for f, enc in edits:
        if d[prev_end_old:f.off] != result[prev_end_old + shift:f.off + shift]:
            raise SaveFormatError("bytes between the edited change forms changed")
        shift += len(enc) - (f.end - f.off)
        prev_end_old = f.end
    if d[prev_end_old:] != result[prev_end_old + shift:]:
        raise SaveFormatError("bytes after the edited change forms changed")
    return result
