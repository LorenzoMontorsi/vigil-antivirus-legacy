using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;

namespace Vigil.Engine
{
    /// <summary>
    /// Lettore ZIP minimale (metodi "stored" e "deflate"): .NET 4.0 non ha ZipArchive.
    /// Le voci cifrate, ZIP64 o con altri metodi vengono saltate.
    /// Ogni estrazione è limitata a <c>maxSize</c> byte, qualunque cosa dichiari l'intestazione.
    /// </summary>
    public sealed class ZipReader
    {
        public sealed class Entry
        {
            public string Name;
            public int Method;
            public bool Encrypted;
            public long CompressedSize, Size, LocalHeaderOffset;

            public bool IsDirectory
            {
                get { return Name.EndsWith("/") || Name.EndsWith("\\"); }
            }
        }

        readonly byte[] data;
        public List<Entry> Entries { get; private set; }

        ZipReader(byte[] data)
        {
            this.data = data;
            Entries = new List<Entry>();
        }

        public static bool LooksLikeZip(byte[] d)
        {
            return d.Length >= 4 && d[0] == 'P' && d[1] == 'K' && d[2] == 3 && d[3] == 4;
        }

        /// <summary>null se la directory centrale non si trova o è rovinata.</summary>
        public static ZipReader Open(byte[] data, int maxEntries)
        {
            try
            {
                var z = new ZipReader(data);
                return z.ReadCentralDirectory(maxEntries) ? z : null;
            }
            catch (Exception)
            {
                return null;
            }
        }

        bool ReadCentralDirectory(int maxEntries)
        {
            // Fine della directory centrale: entro gli ultimi 64 KB + 22 byte (commento).
            int eocd = -1;
            for (int i = data.Length - 22; i >= Math.Max(0, data.Length - 65557); i--)
            {
                if (U32(i) == 0x06054b50)
                {
                    eocd = i;
                    break;
                }
            }
            if (eocd < 0)
                return false;
            int count = U16(eocd + 10);
            long cd = U32(eocd + 16);
            if (cd >= data.Length)
                return false;
            int p = (int)cd;
            var utf8 = new UTF8Encoding(false, false);
            var oem = GetOemEncoding();
            for (int n = 0; n < count && n < maxEntries; n++)
            {
                if (p + 46 > data.Length || U32(p) != 0x02014b50)
                    break;
                int flags = U16(p + 8);
                int nameLen = U16(p + 28), extraLen = U16(p + 30), commentLen = U16(p + 32);
                if (p + 46 + nameLen > data.Length)
                    break;
                // Bit 11: nome in UTF-8; altrimenti codepage OEM (437 / 850).
                var enc = (flags & 0x800) != 0 ? utf8 : oem;
                Entries.Add(new Entry
                {
                    Name = enc.GetString(data, p + 46, nameLen),
                    Method = U16(p + 10),
                    Encrypted = (flags & 1) != 0,
                    CompressedSize = U32(p + 20),
                    Size = U32(p + 24),
                    LocalHeaderOffset = U32(p + 42),
                });
                p += 46 + nameLen + extraLen + commentLen;
            }
            return true;
        }

        static Encoding GetOemEncoding()
        {
            try
            {
                return Encoding.GetEncoding(437);
            }
            catch (Exception)
            {
                return Encoding.ASCII;
            }
        }

        /// <summary>Estrae una voce; null se non supportata, rovinata o più grande di <paramref name="maxSize"/>.</summary>
        public byte[] Extract(Entry e, long maxSize)
        {
            if (e.Encrypted || e.IsDirectory || (e.Method != 0 && e.Method != 8))
                return null;
            if (e.LocalHeaderOffset + 30 > data.Length || U32((int)e.LocalHeaderOffset) != 0x04034b50)
                return null;
            int lh = (int)e.LocalHeaderOffset;
            long start = lh + 30L + U16(lh + 26) + U16(lh + 28);
            if (start > data.Length)
                return null;
            long avail = Math.Min(e.CompressedSize, data.Length - start);
            try
            {
                using (var raw = new MemoryStream(data, (int)start, (int)avail, false))
                {
                    if (e.Method == 0)
                        return avail <= maxSize ? ReadLimited(raw, maxSize) : null;
                    using (var inflate = new DeflateStream(raw, CompressionMode.Decompress))
                        return ReadLimited(inflate, maxSize);
                }
            }
            catch (Exception)
            {
                return null; // dati compressi rovinati
            }
        }

        /// <summary>Legge al massimo maxSize byte: oltre, null (protezione anti zip-bomb).</summary>
        static byte[] ReadLimited(Stream s, long maxSize)
        {
            var ms = new MemoryStream();
            var buf = new byte[81920];
            int r;
            while ((r = s.Read(buf, 0, buf.Length)) > 0)
            {
                if (ms.Length + r > maxSize)
                    return null;
                ms.Write(buf, 0, r);
            }
            return ms.ToArray();
        }

        ushort U16(int o)
        {
            return BitConverter.ToUInt16(data, o);
        }

        uint U32(int o)
        {
            return BitConverter.ToUInt32(data, o);
        }
    }
}
