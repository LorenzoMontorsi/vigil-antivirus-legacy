"""Converte un .ico con immagini PNG in uno leggibile da Windows XP:
le dimensioni fino a 64 px diventano bitmap 32 bit (BGRA + maschera), il 256 resta PNG.
Uso: python ico-xp.py ingresso.ico uscita.ico  (solo libreria standard)."""
import struct, sys, zlib

def png_rgba(data):
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    pos, idat, w = 8, b"", 0
    while pos < len(data):
        n, typ = struct.unpack(">I4s", data[pos:pos + 8])
        body = data[pos + 8:pos + 8 + n]
        if typ == b"IHDR":
            w, h, depth, ctype, _, _, interlace = struct.unpack(">IIBBBBB", body)
            assert depth == 8 and ctype in (2, 6) and interlace == 0, "PNG non supportato"
        elif typ == b"IDAT":
            idat += body
        pos += 12 + n
    bpp = 4 if ctype == 6 else 3
    raw, stride, rows, prev = zlib.decompress(idat), w * bpp, [], bytearray(w * bpp)
    for y in range(h):
        f, line = raw[y * (stride + 1)], bytearray(raw[y * (stride + 1) + 1:(y + 1) * (stride + 1)])
        for x in range(stride):
            a = line[x - bpp] if x >= bpp else 0
            b, c = prev[x], prev[x - bpp] if x >= bpp else 0
            if f == 1: line[x] = (line[x] + a) & 255
            elif f == 2: line[x] = (line[x] + b) & 255
            elif f == 3: line[x] = (line[x] + (a + b) // 2) & 255
            elif f == 4:
                p = a + b - c; pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                line[x] = (line[x] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 255
        rows.append(bytes(line) if bpp == 4 else bytes(v for i in range(w) for v in line[i*3:i*3+3] + b"\xff"))
        prev = line
    return w, h, rows

def bmp_entry(w, h, rows):
    out = struct.pack("<IiiHHIIiiII", 40, w, h * 2, 1, 32, 0, 0, 0, 0, 0, 0)
    for row in reversed(rows):
        out += bytes(v for i in range(w) for v in (row[i*4+2], row[i*4+1], row[i*4], row[i*4+3]))
    mask_stride = ((w + 31) // 32) * 4
    for row in reversed(rows):
        bits = bytearray(mask_stride)
        for i in range(w):
            if row[i * 4 + 3] == 0:
                bits[i // 8] |= 0x80 >> (i % 8)
        out += bytes(bits)
    return out

src = open(sys.argv[1], "rb").read()
count = struct.unpack("<HHH", src[:6])[2]
entries = []
for i in range(count):
    w, h, _, _, _, _, size, off = struct.unpack("<BBBBHHII", src[6 + 16 * i:22 + 16 * i])
    img = src[off:off + size]
    if img[:4] == b"\x89PNG" and (w or 256) <= 64:
        img = bmp_entry(*png_rgba(img))
    entries.append((w, h, img))
entries.sort(key=lambda e: e[0] or 256)
out, off = struct.pack("<HHH", 0, 1, len(entries)), 6 + 16 * len(entries)
for w, h, img in entries:
    out += struct.pack("<BBBBHHII", w, h, 0, 0, 1, 32, len(img), off); off += len(img)
open(sys.argv[2], "wb").write(out + b"".join(e[2] for e in entries))
print("ok:", [(e[0] or 256, "PNG" if e[2][:4] == b"\x89PNG" else "BMP") for e in entries])
