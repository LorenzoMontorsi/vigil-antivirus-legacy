using System;
using System.Security.Cryptography;
using System.Text;

namespace Vigil.Engine
{
    /// <summary>
    /// SHA-256 e conversioni esadecimali.
    /// Su Windows XP SHA256CryptoServiceProvider non esiste: si ripiega sull'implementazione gestita.
    /// </summary>
    public static class Hashing
    {
        static readonly bool CspAvailable = ProbeCsp();

        static bool ProbeCsp()
        {
            try
            {
                using (var h = new SHA256CryptoServiceProvider())
                    h.ComputeHash(new byte[1]);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        public static SHA256 CreateSha256()
        {
            return CspAvailable ? (SHA256)new SHA256CryptoServiceProvider() : new SHA256Managed();
        }

        public static byte[] Sha256(byte[] data)
        {
            return Sha256(data, 0, data.Length);
        }

        public static byte[] Sha256(byte[] data, int offset, int count)
        {
            using (var h = CreateSha256())
                return h.ComputeHash(data, offset, count);
        }

        public static string ToHex(byte[] bytes)
        {
            var sb = new StringBuilder(bytes.Length * 2);
            foreach (var b in bytes)
                sb.Append(b.ToString("x2"));
            return sb.ToString();
        }

        /// <summary>Decodifica una stringa esadecimale di lunghezza esatta; null se non valida.</summary>
        public static byte[] FromHex(string s, int expectedBytes)
        {
            if (s == null)
                return null;
            s = s.Trim();
            if (s.Length != expectedBytes * 2)
                return null;
            var result = new byte[expectedBytes];
            for (int i = 0; i < expectedBytes; i++)
            {
                int hi = HexValue(s[2 * i]), lo = HexValue(s[2 * i + 1]);
                if (hi < 0 || lo < 0)
                    return null;
                result[i] = (byte)(hi << 4 | lo);
            }
            return result;
        }

        static int HexValue(char c)
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        }
    }

    /// <summary>Hash SHA-256 come chiave di dizionario compatta (4 interi a 64 bit invece di una stringa).</summary>
    public struct Hash256 : IEquatable<Hash256>
    {
        readonly ulong a, b, c, d;

        public Hash256(byte[] h)
        {
            if (h == null || h.Length != 32)
                throw new ArgumentException("servono 32 byte");
            a = BitConverter.ToUInt64(h, 0);
            b = BitConverter.ToUInt64(h, 8);
            c = BitConverter.ToUInt64(h, 16);
            d = BitConverter.ToUInt64(h, 24);
        }

        public static bool TryParse(string hex, out Hash256 hash)
        {
            var bytes = Hashing.FromHex(hex, 32);
            hash = bytes != null ? new Hash256(bytes) : default(Hash256);
            return bytes != null;
        }

        public bool Equals(Hash256 o)
        {
            return a == o.a && b == o.b && c == o.c && d == o.d;
        }

        public override bool Equals(object obj)
        {
            return obj is Hash256 && Equals((Hash256)obj);
        }

        public override int GetHashCode()
        {
            return a.GetHashCode();
        }
    }
}
