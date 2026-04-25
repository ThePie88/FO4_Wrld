"""Packet format condiviso. Binario little-endian, fixed 44 byte."""
import struct

# <BI15s6f = little endian, u8 type, u32 seq, 15-byte id, 6 float
FMT = "<BI15s6f"
SIZE = struct.calcsize(FMT)   # 44
TYPE_HELLO = 0x48  # 'H'
TYPE_POS   = 0x50  # 'P'

def pack_pos(client_id: str, seq: int, x: float, y: float, z: float,
             rx: float, ry: float, rz: float) -> bytes:
    return struct.pack(FMT, TYPE_POS, seq & 0xFFFFFFFF,
                       client_id.encode('ascii')[:15].ljust(15, b'\0'),
                       x, y, z, rx, ry, rz)

def pack_hello(client_id: str) -> bytes:
    return struct.pack(FMT, TYPE_HELLO, 0,
                       client_id.encode('ascii')[:15].ljust(15, b'\0'),
                       0.0, 0.0, 0.0, 0.0, 0.0, 0.0)

def unpack(data: bytes):
    if len(data) != SIZE:
        return None
    typ, seq, id_raw, x, y, z, rx, ry, rz = struct.unpack(FMT, data)
    cid = id_raw.rstrip(b'\0').decode('ascii', errors='replace')
    return {
        'type': typ, 'seq': seq, 'id': cid,
        'x': x, 'y': y, 'z': z, 'rx': rx, 'ry': ry, 'rz': rz
    }
