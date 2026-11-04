using System;
using System.Collections.Generic;
using System.Linq;

namespace Vigil.Engine
{
    /// <summary>
    /// Euristica statica: indicatori sospetti nel nome del file e negli eseguibili PE.
    /// Ogni indicatore ha un peso; da <see cref="Threshold"/> in su il file è "sospetto".
    /// I pesi sono volutamente prudenti: un sospetto non è una condanna e non
    /// viene mai messo in quarantena automaticamente.
    /// </summary>
    public static class Heuristics
    {
        public const int Threshold = 60;

        static readonly string[] ExecExts = { "exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf", "hta", "lnk", "msi", "ps1" };
        static readonly string[] DecoyExts = { "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "jpg", "jpeg", "png", "gif", "mp3", "mp4", "avi", "zip", "rar" };
        static readonly string[] PackerSections =
        {
            "UPX0", "UPX1", "UPX2", ".aspack", ".adata", ".petite", ".MPRESS1", ".MPRESS2", ".nsp0", ".nsp1", "pebundle", ".packed",
            ".themida", ".vmp0", ".vmp1", ".enigma1", ".enigma2",
        };

        public sealed class Finding
        {
            public int Score;
            public List<string> Reasons = new List<string>();

            internal void Add(int weight, string reason)
            {
                Score += weight;
                if (weight > 0)
                    Reasons.Add(reason);
            }
        }

        /// <param name="fileName">Solo il nome del file, senza cartella.</param>
        /// <returns>null se il punteggio resta sotto la soglia.</returns>
        public static Finding Analyze(byte[] data, string fileName)
        {
            var f = new Finding();
            AnalyzeName(fileName ?? "", f);
            if (data.Length >= 2 && data[0] == 'M' && data[1] == 'Z')
            {
                var pe = PeFile.TryParse(data);
                if (pe != null)
                    AnalyzePe(pe, data, f);
            }
            return f.Score >= Threshold ? f : null;
        }

        static void AnalyzeName(string name, Finding f)
        {
            if (name.IndexOf('‮') >= 0)
                f.Add(80, "Il nome contiene un carattere di inversione del testo (RLO) che maschera l'estensione");
            var parts = name.ToLowerInvariant().Split('.');
            if (parts.Length >= 3)
            {
                string last = parts[parts.Length - 1], prev = parts[parts.Length - 2];
                if (ExecExts.Contains(last) && DecoyExts.Contains(prev))
                    f.Add(70, "Doppia estensione ingannevole (." + prev + "." + last + ")");
            }
        }

        static void AnalyzePe(PeFile pe, byte[] data, Finding f)
        {
            // Packer noti.
            var packer = pe.Sections.FirstOrDefault(s => PackerSections.Contains(s.Name));
            if (packer != null)
                f.Add(25, "Sezione tipica di un packer (" + packer.Name + ")");

            // Sezioni scrivibili ed eseguibili insieme (codice che si modifica da solo).
            if (pe.Sections.Any(s => (s.Characteristics & PeFile.ScnMemExecute) != 0 && (s.Characteristics & PeFile.ScnMemWrite) != 0))
                f.Add(25, "Sezione contemporaneamente scrivibile ed eseguibile");

            // Punto di ingresso in una sezione scrivibile.
            uint ep = pe.EntryPoint;
            var epSection = pe.Sections.FirstOrDefault(s => ep >= s.VirtualAddress && ep < s.VirtualAddress + Math.Max(s.VirtualSize, s.SizeOfRawData));
            if (epSection != null && (epSection.Characteristics & PeFile.ScnMemWrite) != 0)
                f.Add(20, "Il punto di ingresso si trova in una sezione scrivibile");

            // Codice ad alta entropia: compresso o cifrato.
            foreach (var s in pe.Sections)
            {
                if ((s.Characteristics & PeFile.ScnMemExecute) == 0 || s.SizeOfRawData < 1024)
                    continue;
                long start = s.PointerToRawData;
                long end = Math.Min(start + s.SizeOfRawData, data.Length);
                if (start < end && Entropy(data, (int)start, (int)(end - start)) > 7.2)
                {
                    f.Add(20, "Codice eseguibile con entropia molto alta (compresso o cifrato)");
                    break;
                }
            }

            // Import.
            if (!pe.IsDotNet)
            {
                var names = new HashSet<string>(pe.Imports.Select(i => i.Name), StringComparer.OrdinalIgnoreCase);
                Func<string[], bool> has = list => list.Any(names.Contains);
                if (pe.Imports.Count <= 6 && has(new[] { "GetProcAddress" }) && has(new[] { "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW" }))
                    f.Add(20, "Pochissimi import, risolti a runtime con LoadLibrary/GetProcAddress");
                if (has(new[] { "VirtualAllocEx" }) && has(new[] { "WriteProcessMemory" })
                    && has(new[] { "CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx", "QueueUserAPC", "SetThreadContext" }))
                    f.Add(30, "API per l'iniezione di codice in altri processi");
                if (has(new[] { "SetWindowsHookExA", "SetWindowsHookExW" }) && has(new[] { "GetAsyncKeyState", "GetKeyState", "GetKeyboardState" }))
                    f.Add(20, "API per intercettare la tastiera (keylogger)");
            }

            // Firma digitale (presenza, non validità: quella la controlla Trust).
            if (pe.HasCertificate)
                f.Add(-40, "");
            else
                f.Add(10, "Eseguibile non firmato digitalmente");
        }

        public static double Entropy(byte[] data, int offset, int count)
        {
            if (count <= 0)
                return 0;
            var counts = new long[256];
            for (int i = offset; i < offset + count; i++)
                counts[data[i]]++;
            double e = 0;
            foreach (var c in counts)
            {
                if (c == 0)
                    continue;
                double p = (double)c / count;
                e -= p * Math.Log(p, 2);
            }
            return e;
        }
    }
}
