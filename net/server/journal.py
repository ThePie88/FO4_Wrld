"""The durable journal: every result that changes the world, on disk before
anyone is told about it (stage 1 of L5, 2026-09-27).

Until this file existed the world lived in memory and reached the disk every
30 seconds as a snapshot. A client that got an ACK moved its items at once;
a crash inside those 30 seconds forgot the ACK and the items with it. From
here on `ServerState` appends a record for every mutation it accepts, a
writer thread groups the pending records and fsyncs them, and the server
holds every reliable frame until the record it depends on is durable
(see `ServerProtocol._send`). The snapshot becomes a compaction of the
journal: it carries the LSN it covers, and a boot replays what follows.

Format. A directory with `epoch.json` and segments `seg-EEEE-LLLLLLLLLLLL.jnl`
(epoch, first LSN). A segment is a sequence of records, each
`u32 payload_len | u32 crc32(payload) | payload`, the payload being one JSON
object {lsn, epoch, ts, op, args}. LSNs are global, monotonic and
contiguous; `op` and `args` name a `ServerState` method and its arguments,
already made JSON-safe by the state (dataclasses tagged with their class,
bytes as hex, int-keyed dicts as pair lists).

Recovery rules. A record that does not parse or fails its CRC is a TORN TAIL
when nothing follows it: a crash mid-write, expected, truncated away, and
writing continues from there. The same with data after it is corruption,
and the journal refuses to open (`JournalCorrupt`): the operator decides,
the server never guesses. A gap in the LSN sequence is corruption too.

Epoch. `epoch.json` records the epoch and the highest LSN known durable at
the last write of the file. A journal found shorter than that mark at boot
lost results that were acknowledged; the epoch is bumped so that later
stages (the checkpoint watermark is (epoch, lsn)) can tell such a history
apart from a clean one.

Failure. A write or fsync that raises marks the journal failed and tells
the server, which lets the frames it was holding go (what they describe is
already in memory and cannot be taken back) and refuses item ops from then
on (REJ_UNAVAILABLE): read-only, loudly, until a restart with a working
disk. The snapshot keeps running as before.
"""
from __future__ import annotations

import json
import logging
import os
import struct
import threading
import time
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, Optional

log = logging.getLogger("fw.journal")

RECORD_HEADER = struct.Struct("<II")        # payload length, crc32 of the payload
SEGMENT_BYTES_DEFAULT: int = 4 * 1024 * 1024
EPOCH_FILE = "epoch.json"
SEGMENT_PREFIX = "seg-"
SEGMENT_SUFFIX = ".jnl"
# The writer waits this long after being woken so a burst (a Take All is
# 69 ops in one datagram) lands in one fsync instead of 69.
GROUP_COMMIT_S: float = 0.003


class JournalCorrupt(RuntimeError):
    """A record that is not a torn tail failed to parse, or LSNs have a gap."""


@dataclass
class _Segment:
    path: Path
    first_lsn: int
    last_lsn: int
    size: int


def _segment_name(epoch: int, first_lsn: int) -> str:
    return f"{SEGMENT_PREFIX}{epoch:04d}-{first_lsn:012d}{SEGMENT_SUFFIX}"


def _parse_segment_name(path: Path) -> Optional[tuple[int, int]]:
    name = path.name
    if not (name.startswith(SEGMENT_PREFIX) and name.endswith(SEGMENT_SUFFIX)):
        return None
    body = name[len(SEGMENT_PREFIX):-len(SEGMENT_SUFFIX)]
    try:
        epoch_s, lsn_s = body.split("-", 1)
        return int(epoch_s), int(lsn_s)
    except ValueError:
        return None


def _frame(payload: bytes) -> bytes:
    return RECORD_HEADER.pack(len(payload), zlib.crc32(payload) & 0xFFFFFFFF) + payload


def _fsync_dir(directory: Path) -> None:
    if os.name == "nt":
        return
    try:
        fd = os.open(str(directory), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


class Journal:
    def __init__(self, directory: Path, *, segment_bytes: int = SEGMENT_BYTES_DEFAULT,
                 fsync: bool = True) -> None:
        self.directory = Path(directory)
        self._segment_bytes = max(64, int(segment_bytes))
        self._fsync = fsync
        self.epoch: int = 1
        self._hwm_lsn: int = 0
        self._head_lsn: int = 0
        self._durable_lsn: int = 0
        self._pending: list[tuple[int, bytes]] = []
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._writer: Optional[threading.Thread] = None
        self._closing = False
        self._failed: Optional[str] = None
        self._notify_durable: Optional[Callable[[int], None]] = None
        self._notify_failure: Optional[Callable[[str], None]] = None
        self._segments: list[_Segment] = []
        self.records_written: int = 0
        self.batches_written: int = 0

    # ------------------------------------------------------------ open

    @classmethod
    def open(cls, directory: Path, *, segment_bytes: int = SEGMENT_BYTES_DEFAULT,
             fsync: bool = True) -> "Journal":
        j = cls(directory, segment_bytes=segment_bytes, fsync=fsync)
        j.directory.mkdir(parents=True, exist_ok=True)
        j._read_epoch()
        j._scan_segments()
        j._durable_lsn = j._head_lsn
        if j._head_lsn < j._hwm_lsn:
            log.error("journal %s: head lsn %d is below the recorded high-water "
                      "mark %d: results that were acknowledged are gone. Epoch "
                      "%d -> %d", j.directory, j._head_lsn, j._hwm_lsn,
                      j.epoch, j.epoch + 1)
            j.epoch += 1
        j._hwm_lsn = j._head_lsn
        j._write_epoch()
        log.info("journal %s: epoch %d, head lsn %d, %d segment(s)",
                 j.directory, j.epoch, j._head_lsn, len(j._segments))
        return j

    def _read_epoch(self) -> None:
        path = self.directory / EPOCH_FILE
        if not path.is_file():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            self.epoch = max(1, int(data.get("epoch", 1)))
            self._hwm_lsn = max(0, int(data.get("hwm_lsn", 0)))
        except (OSError, ValueError, TypeError) as e:
            raise JournalCorrupt(f"{path}: unreadable epoch file: {e}") from e

    def _write_epoch(self) -> None:
        path = self.directory / EPOCH_FILE
        tmp = path.with_suffix(".json.tmp")
        data = {"epoch": self.epoch, "hwm_lsn": self._hwm_lsn}
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f)
            f.flush()
            if self._fsync:
                os.fsync(f.fileno())
        os.replace(tmp, path)
        _fsync_dir(self.directory)

    def _scan_segments(self) -> None:
        found: list[tuple[int, int, Path]] = []
        for p in self.directory.iterdir():
            parsed = _parse_segment_name(p)
            if parsed is None:
                continue
            found.append((parsed[1], parsed[0], p))
        found.sort()
        self._segments = []
        expected: Optional[int] = None
        for first_lsn, _epoch, path in found:
            last_lsn, good_size, n = self._scan_one(path, expected)
            if n == 0:
                # Nothing readable in it (a torn first record, or empty):
                # it says nothing, so it goes.
                log.warning("journal segment %s holds no readable record: removed",
                            path.name)
                try:
                    path.unlink()
                except OSError:
                    pass
                continue
            self._segments.append(_Segment(path, first_lsn, last_lsn, good_size))
            expected = last_lsn + 1
        if self._segments:
            self._head_lsn = self._segments[-1].last_lsn

    def _scan_one(self, path: Path, expected: Optional[int]) -> tuple[int, int, int]:
        """Validate one segment. Returns (last_lsn, byte size of the good
        prefix, record count) after truncating a torn tail. Raises
        JournalCorrupt for a bad record followed by more data or an LSN
        out of sequence."""
        raw = path.read_bytes()
        off = 0
        last_lsn = 0
        n = 0
        good = 0
        total = len(raw)
        while off < total:
            remaining = total - off
            torn = False
            if remaining < RECORD_HEADER.size:
                torn = True
            else:
                length, crc = RECORD_HEADER.unpack_from(raw, off)
                end = off + RECORD_HEADER.size + length
                if end > total:
                    torn = True
                else:
                    payload = raw[off + RECORD_HEADER.size:end]
                    ok = (zlib.crc32(payload) & 0xFFFFFFFF) == crc
                    rec = None
                    if ok:
                        try:
                            rec = json.loads(payload)
                            lsn = int(rec["lsn"])
                        except (ValueError, KeyError, TypeError):
                            ok = False
                    if not ok:
                        if end >= total:
                            torn = True
                        else:
                            raise JournalCorrupt(
                                f"{path.name}: record at offset {off} is corrupt "
                                f"and {total - end} byte(s) follow it")
                    else:
                        if expected is not None and lsn != expected:
                            raise JournalCorrupt(
                                f"{path.name}: record at offset {off} has lsn {lsn}, "
                                f"expected {expected}")
                        expected = lsn + 1
                        last_lsn = lsn
                        n += 1
                        off = end
                        good = off
                        continue
            if torn:
                log.warning("journal segment %s: torn tail of %d byte(s) at offset "
                            "%d dropped (a write was cut short)", path.name,
                            total - good, good)
                with open(path, "r+b") as f:
                    f.truncate(good)
                break
        return last_lsn, good, n

    # ------------------------------------------------------------ append

    @property
    def head_lsn(self) -> int:
        with self._lock:
            return self._head_lsn

    @property
    def durable_lsn(self) -> int:
        with self._lock:
            return self._durable_lsn

    @property
    def failed(self) -> Optional[str]:
        with self._lock:
            return self._failed

    def set_notify(self, on_durable: Optional[Callable[[int], None]],
                   on_failure: Optional[Callable[[str], None]] = None) -> None:
        """Callbacks: the durable LSN advanced, or the journal failed. Both
        are invoked on whatever thread did the write (the writer thread when
        it runs, the caller of flush() otherwise); the server wraps them in
        loop.call_soon_threadsafe."""
        with self._lock:
            self._notify_durable = on_durable
            self._notify_failure = on_failure

    def append(self, op: str, args: dict[str, Any]) -> int:
        """Queue one record. Returns its LSN. After a failure the LSN still
        advances and the record is dropped: the state changed either way,
        and the server is already read-only for what matters."""
        with self._lock:
            lsn = self._head_lsn + 1
            self._head_lsn = lsn
            if self._failed is not None:
                self._durable_lsn = lsn
                return lsn
            payload = json.dumps(
                {"lsn": lsn, "epoch": self.epoch, "ts": int(time.time() * 1000),
                 "op": op, "args": args},
                separators=(",", ":"), ensure_ascii=True).encode("utf-8")
            self._pending.append((lsn, _frame(payload)))
            self._cond.notify()
        return lsn

    # ------------------------------------------------------------ writing

    def _take_batch(self) -> list[tuple[int, bytes]]:
        with self._lock:
            batch = self._pending
            self._pending = []
            return batch

    def _active_segment(self, first_lsn: int) -> _Segment:
        if self._segments and self._segments[-1].size < self._segment_bytes:
            return self._segments[-1]
        seg = _Segment(self.directory / _segment_name(self.epoch, first_lsn),
                       first_lsn, first_lsn - 1, 0)
        self._segments.append(seg)
        return seg

    def _write_batch(self, batch: list[tuple[int, bytes]]) -> None:
        """One fsync per segment touched: a batch normally lands whole in
        the active segment, and rolls into a new file only when the active
        one is full (at least one record per segment, whatever the size)."""
        i = 0
        while i < len(batch):
            seg = self._active_segment(batch[i][0])
            j = i
            size = seg.size
            while j < len(batch) and (j == i or size + len(batch[j][1]) <= self._segment_bytes):
                size += len(batch[j][1])
                j += 1
            data = b"".join(frame for _, frame in batch[i:j])
            new_file = seg.size == 0
            with open(seg.path, "ab") as f:
                f.write(data)
                f.flush()
                if self._fsync:
                    os.fsync(f.fileno())
            if new_file:
                _fsync_dir(self.directory)
            seg.size += len(data)
            seg.last_lsn = batch[j - 1][0]
            self.records_written += j - i
            self.batches_written += 1
            i = j

    def _write_pending(self) -> None:
        """Write everything queued, then notify. Any thread; one at a time."""
        batch = self._take_batch()
        if not batch:
            return
        try:
            self._write_batch(batch)
        except Exception as e:  # noqa: BLE001 - the disk failing is the point
            self._fail(f"{type(e).__name__}: {e}")
            return
        with self._lock:
            self._durable_lsn = batch[-1][0]
            self._cond.notify_all()
            notify = self._notify_durable
            durable = self._durable_lsn
        if notify is not None:
            notify(durable)

    def _fail(self, reason: str) -> None:
        with self._lock:
            if self._failed is not None:
                return
            self._failed = reason
            self._pending.clear()
            self._durable_lsn = self._head_lsn
            self._cond.notify_all()
            notify = self._notify_failure
        log.error("journal %s FAILED: %s. Nothing more is recorded; item ops "
                  "are refused until a restart", self.directory, reason)
        if notify is not None:
            notify(reason)

    def mark_failed(self, reason: str) -> None:
        """What the writer does on an exception, callable by hand (tests)."""
        self._fail(reason)

    def start_writer(self) -> None:
        with self._lock:
            if self._writer is not None:
                return
            self._closing = False
            self._writer = threading.Thread(
                target=self._writer_main, name="fw-journal", daemon=True)
            self._writer.start()

    def _writer_main(self) -> None:
        while True:
            with self._lock:
                while not self._pending and not self._closing:
                    self._cond.wait()
                if self._closing and not self._pending:
                    return
            time.sleep(GROUP_COMMIT_S)
            self._write_pending()

    def flush(self, timeout_s: float = 10.0) -> bool:
        """Make everything appended so far durable. With a writer thread this
        waits for it; without one it writes on the calling thread. False on
        timeout or after a failure."""
        with self._lock:
            writer = self._writer
            if self._failed is not None:
                return False
        if writer is None:
            self._write_pending()
            return self.failed is None
        deadline = time.monotonic() + timeout_s
        with self._lock:
            while (self._durable_lsn < self._head_lsn and self._failed is None
                   and time.monotonic() < deadline):
                self._cond.notify()
                self._cond.wait(timeout=0.05)
            return self._durable_lsn >= self._head_lsn and self._failed is None

    def close(self) -> None:
        with self._lock:
            self._closing = True
            writer = self._writer
            self._writer = None
            self._cond.notify_all()
        if writer is not None:
            writer.join(timeout=10.0)
        self._write_pending()
        with self._lock:
            self._hwm_lsn = max(self._hwm_lsn, self._durable_lsn)
        try:
            self._write_epoch()
        except OSError as e:
            log.error("journal %s: epoch file not written at close: %s",
                      self.directory, e)

    # ------------------------------------------------------------ reading

    def iter_records(self, after_lsn: int = 0) -> Iterator[dict[str, Any]]:
        """Records with lsn > after_lsn, in order, from the segments on disk.
        Only what was scanned at open or written since; pending records are
        not on disk and not yielded."""
        for seg in list(self._segments):
            if seg.last_lsn <= after_lsn:
                continue
            raw = seg.path.read_bytes()
            off = 0
            total = len(raw)
            while off + RECORD_HEADER.size <= total:
                length, crc = RECORD_HEADER.unpack_from(raw, off)
                end = off + RECORD_HEADER.size + length
                if end > total:
                    break
                payload = raw[off + RECORD_HEADER.size:end]
                off = end
                if (zlib.crc32(payload) & 0xFFFFFFFF) != crc:
                    break
                try:
                    rec = json.loads(payload)
                except ValueError:
                    break
                if int(rec.get("lsn", 0)) > after_lsn:
                    yield rec

    def replay(self, state, after_lsn: int) -> int:
        """Apply every record after `after_lsn` to `state`. Returns how many
        were applied. The state journals nothing while replaying."""
        n = 0
        state.begin_replay()
        try:
            for rec in self.iter_records(after_lsn):
                try:
                    lsn = int(rec["lsn"])
                    if state.apply_journal_record(str(rec["op"]), rec.get("args") or {},
                                                  lsn):
                        n += 1
                except (KeyError, TypeError, ValueError) as e:
                    log.warning("journal record skipped (%s): %r", e, rec)
        finally:
            state.end_replay()
        return n

    # ------------------------------------------------------------ housekeeping

    def compact(self, up_to_lsn: int) -> int:
        """Delete the segments whose every record is at or below `up_to_lsn`,
        keeping the one being written to. Called after a snapshot that
        covers `up_to_lsn`. Returns how many files went."""
        removed = 0
        with self._lock:
            keep = self._segments[-1:] if self._segments else []
            candidates = [s for s in self._segments if s not in keep]
        for seg in candidates:
            if seg.last_lsn > up_to_lsn:
                continue
            try:
                seg.path.unlink()
            except OSError as e:
                log.warning("journal segment %s not removed: %s", seg.path.name, e)
                continue
            with self._lock:
                self._segments = [s for s in self._segments if s is not seg]
            removed += 1
        if removed:
            _fsync_dir(self.directory)
            log.info("journal %s: %d segment(s) compacted away below lsn %d",
                     self.directory, removed, up_to_lsn)
        return removed

    def note_high_water_mark(self) -> None:
        """Persist the durable LSN as the mark a later boot compares against.
        Called after each snapshot; cheap, one small file."""
        with self._lock:
            self._hwm_lsn = max(self._hwm_lsn, self._durable_lsn)
        try:
            self._write_epoch()
        except OSError as e:
            log.warning("journal %s: epoch file not written: %s", self.directory, e)

    def segment_count(self) -> int:
        with self._lock:
            return len(self._segments)
