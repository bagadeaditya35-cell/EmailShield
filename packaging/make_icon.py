"""Generates packaging/emailshield.ico and emailshield.png using only the standard library."""
import math
import struct
import zlib
from pathlib import Path

OUT = Path(__file__).resolve().parent
SHIELD = [(0.5, 0.07), (0.87, 0.19), (0.87, 0.5), (0.80, 0.68), (0.5, 0.94), (0.20, 0.68), (0.13, 0.5), (0.13, 0.19)]


def inside(poly, x, y):
    c = False
    for i in range(len(poly)):
        (x1, y1), (x2, y2) = poly[i], poly[(i + 1) % len(poly)]
        if (y1 > y) != (y2 > y) and x < (x2 - x1) * (y - y1) / (y2 - y1) + x1:
            c = not c
    return c


def seg_dist(px, py, a, b):
    (x1, y1), (x2, y2) = a, b
    dx, dy = x2 - x1, y2 - y1
    t = max(0, min(1, ((px - x1) * dx + (py - y1) * dy) / (dx * dx + dy * dy)))
    return math.hypot(px - (x1 + t * dx), py - (y1 + t * dy))


ENV = [((0.30, 0.36), (0.70, 0.36)), ((0.70, 0.36), (0.70, 0.60)), ((0.70, 0.60), (0.30, 0.60)), ((0.30, 0.60), (0.30, 0.36)),
       ((0.30, 0.36), (0.5, 0.52)), ((0.70, 0.36), (0.5, 0.52))]


def sample(x, y):
    if not inside(SHIELD, x, y):
        return (0, 0, 0, 0)
    if any(seg_dist(x, y, a, b) < 0.028 for a, b in ENV):
        return (255, 255, 255, 255)
    inner = [(0.5 + (px - 0.5) * 0.88, 0.5 + (py - 0.5) * 0.88) for px, py in SHIELD]
    if not inside(inner, x, y):
        return (120, 220, 235, 255)
    t = y
    return (int(14 + 6 * t), int(120 - 40 * t), int(150 - 20 * t), 255)


def render(n, ss=3):
    rows = []
    for j in range(n):
        row = bytearray([0])
        for i in range(n):
            acc = [0, 0, 0, 0]
            for sj in range(ss):
                for si in range(ss):
                    r, g, b, a = sample((i + (si + .5) / ss) / n, (j + (sj + .5) / ss) / n)
                    acc[0] += r * a; acc[1] += g * a; acc[2] += b * a; acc[3] += a
            a = acc[3]
            row += bytes([acc[0] // a, acc[1] // a, acc[2] // a, a // (ss * ss)]) if a else bytes(4)
        rows.append(bytes(row))
    return rows


def png(n):
    raw = b"".join(render(n))
    chunk = lambda t, d: struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)  # noqa: E731
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", n, n, 8, 6, 0, 0, 0)) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")


def main():
    sizes = [16, 32, 48, 64, 128, 256]
    imgs = [png(s) for s in sizes]
    head = struct.pack("<HHH", 0, 1, len(sizes))
    off, entries = 6 + 16 * len(sizes), b""
    for s, d in zip(sizes, imgs):
        entries += struct.pack("<BBBBHHII", s % 256, s % 256, 0, 0, 1, 32, len(d), off)
        off += len(d)
    (OUT / "emailshield.ico").write_bytes(head + entries + b"".join(imgs))
    (OUT / "emailshield.png").write_bytes(imgs[-1])
    print("wrote", OUT / "emailshield.ico", "and emailshield.png")


if __name__ == "__main__":
    main()
