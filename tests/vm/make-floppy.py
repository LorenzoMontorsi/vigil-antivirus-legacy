"""Crea un'immagine di dischetto FAT12 da 1,44 MB con i file indicati (nomi 8.3).

Serve per WINNT.SIF: il programma di installazione di Windows XP, avviato dal CD, cerca il file
di risposte sul dischetto A:.  Uso: make-floppy.py uscita.flp FILE [FILE ...]
"""
import os
import struct
import sys

SECTOR = 512
TOTAL = 2880


def short_name(path):
    base, ext = os.path.splitext(os.path.basename(path).upper())
    return base[:8].ljust(8).encode("ascii") + ext[1:4].ljust(3).encode("ascii")


def main(out, files):
    img = bytearray(TOTAL * SECTOR)
    boot = bytearray(SECTOR)
    boot[0:3] = b"\xEB\x3C\x90"
    boot[3:11] = b"VIGIL   "
    # BPB: byte/settore, settori/cluster, riservati, FAT, voci radice, settori, media, settori/FAT,
    # settori/traccia, testine.
    boot[11:28] = struct.pack("<HBHBHHBHHH", SECTOR, 1, 1, 2, 224, TOTAL, 0xF0, 9, 18, 2)
    boot[38] = 0x29
    boot[39:43] = b"\x56\x49\x47\x4C"
    boot[43:54] = b"VIGIL      "
    boot[54:62] = b"FAT12   "
    boot[510:512] = b"\x55\xAA"
    img[0:SECTOR] = boot

    fat = bytearray(9 * SECTOR)
    entries = {0: 0xFF0, 1: 0xFFF}
    root = bytearray(14 * SECTOR)
    cluster = 2
    for i, f in enumerate(files):
        data = open(f, "rb").read()
        n = max(1, (len(data) + SECTOR - 1) // SECTOR)
        first = cluster
        for k in range(n):
            entries[cluster] = 0xFFF if k == n - 1 else cluster + 1
            off = (33 + cluster - 2) * SECTOR
            img[off:off + SECTOR] = data[k * SECTOR:(k + 1) * SECTOR].ljust(SECTOR, b"\0")
            cluster += 1
        e = short_name(f) + bytes([0x20]) + bytes(14) + struct.pack("<HI", first, len(data))
        root[i * 32:(i + 1) * 32] = e

    for c, v in entries.items():
        o = c * 3 // 2
        if c % 2 == 0:
            fat[o] = v & 0xFF
            fat[o + 1] = (fat[o + 1] & 0xF0) | (v >> 8)
        else:
            fat[o] = (fat[o] & 0x0F) | ((v & 0x0F) << 4)
            fat[o + 1] = v >> 4
    img[SECTOR:10 * SECTOR] = fat
    img[10 * SECTOR:19 * SECTOR] = fat
    img[19 * SECTOR:33 * SECTOR] = root
    open(out, "wb").write(img)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2:])
