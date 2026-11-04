using System;
using System.Collections.Generic;
using System.Text;

namespace Vigil.Engine
{
    /// <summary>
    /// Lettore minimale del formato PE (exe/dll): sezioni, punto di ingresso, import,
    /// presenza della firma. Tollera file troncati o malformati: in quel caso <see cref="TryParse"/> fallisce.
    /// </summary>
    public sealed class PeFile
    {
        public sealed class Section
        {
            public string Name;
            public uint VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData, Characteristics;
        }

        public sealed class Import
        {
            public string Dll;
            public string Name; // vuoto se importata per ordinale
        }

        public const uint ScnMemExecute = 0x20000000;
        public const uint ScnMemWrite = 0x80000000;

        const int MaxImports = 20000;

        public bool Is64 { get; private set; }
        public uint EntryPoint { get; private set; }
        public List<Section> Sections { get; private set; }
        public List<Import> Imports { get; private set; }
        public bool HasCertificate { get; private set; }
        public bool IsDotNet { get; private set; }

        byte[] data;

        public static PeFile TryParse(byte[] data)
        {
            try
            {
                var pe = new PeFile { data = data, Sections = new List<Section>(), Imports = new List<Import>() };
                return pe.Parse() ? pe : null;
            }
            catch (Exception)
            {
                // Indici fuori dai limiti su file malformati: non è un PE leggibile.
                return null;
            }
        }

        bool Parse()
        {
            if (data.Length < 0x40 || data[0] != 'M' || data[1] != 'Z')
                return false;
            int pe = (int)U32(0x3C);
            if (pe <= 0 || pe > data.Length - 24 || U32(pe) != 0x00004550)
                return false;
            int coff = pe + 4;
            int numSections = U16(coff + 2);
            int optSize = U16(coff + 16);
            int opt = coff + 20;
            ushort magic = U16(opt);
            if (magic == 0x20b) Is64 = true;
            else if (magic != 0x10b) return false;
            EntryPoint = U32(opt + 16);

            int ddBase = opt + (Is64 ? 112 : 96);
            uint numDirs = U32(opt + (Is64 ? 108 : 92));

            int sh = opt + optSize;
            for (int i = 0; i < numSections && i < 96; i++)
            {
                int o = sh + i * 40;
                if (o + 40 > data.Length)
                    break;
                Sections.Add(new Section
                {
                    Name = Encoding.ASCII.GetString(data, o, 8).TrimEnd('\0'),
                    VirtualSize = U32(o + 8),
                    VirtualAddress = U32(o + 12),
                    SizeOfRawData = U32(o + 16),
                    PointerToRawData = U32(o + 20),
                    Characteristics = U32(o + 36),
                });
            }

            // Directory 4 = certificati (offset nel file, non RVA); 1 = import; 14 = .NET.
            if (numDirs > 4)
                HasCertificate = U32(ddBase + 4 * 8) != 0 && U32(ddBase + 4 * 8 + 4) != 0;
            if (numDirs > 14)
                IsDotNet = U32(ddBase + 14 * 8) != 0;
            if (numDirs > 1)
                ParseImports(U32(ddBase + 8));
            return true;
        }

        void ParseImports(uint rva)
        {
            int desc = RvaToOffset(rva);
            if (desc < 0)
                return;
            for (int d = 0; d < 1024; d++, desc += 20)
            {
                if (desc + 20 > data.Length)
                    return;
                uint origThunk = U32(desc), nameRva = U32(desc + 12), firstThunk = U32(desc + 16);
                if (origThunk == 0 && nameRva == 0 && firstThunk == 0)
                    return;
                string dll = CString(RvaToOffset(nameRva));
                if (dll.Equals("mscoree.dll", StringComparison.OrdinalIgnoreCase))
                    IsDotNet = true;
                int thunk = RvaToOffset(origThunk != 0 ? origThunk : firstThunk);
                if (thunk < 0)
                    continue;
                int step = Is64 ? 8 : 4;
                for (; thunk + step <= data.Length; thunk += step)
                {
                    ulong v = Is64 ? BitConverter.ToUInt64(data, thunk) : U32(thunk);
                    if (v == 0)
                        break;
                    bool byOrdinal = Is64 ? (v & 0x8000000000000000UL) != 0 : (v & 0x80000000UL) != 0;
                    string name = "";
                    if (!byOrdinal)
                    {
                        int hint = RvaToOffset((uint)(v & 0x7FFFFFFF));
                        name = hint >= 0 ? CString(hint + 2) : "";
                    }
                    Imports.Add(new Import { Dll = dll, Name = name });
                    if (Imports.Count >= MaxImports)
                        return;
                }
            }
        }

        int RvaToOffset(uint rva)
        {
            if (rva == 0)
                return -1;
            foreach (var s in Sections)
            {
                uint size = Math.Max(s.VirtualSize, s.SizeOfRawData);
                if (rva >= s.VirtualAddress && rva < s.VirtualAddress + size)
                {
                    long off = (long)rva - s.VirtualAddress + s.PointerToRawData;
                    return off < data.Length ? (int)off : -1;
                }
            }
            // Intestazioni (prima della prima sezione).
            return rva < data.Length ? (int)rva : -1;
        }

        string CString(int off)
        {
            if (off < 0 || off >= data.Length)
                return "";
            int end = off;
            while (end < data.Length && data[end] != 0 && end - off < 256)
                end++;
            return Encoding.ASCII.GetString(data, off, end - off);
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
