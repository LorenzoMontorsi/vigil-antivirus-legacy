using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace Vigil.Engine
{
    /// <summary>
    /// Classificazione di una minaccia a partire dal nome della firma.
    ///
    /// I nomi di ClamAV seguono lo schema <c>Piattaforma.Categoria.Famiglia-IdFirma-Revisione</c>
    /// (es. <c>Win.Trojan.Agent-1234567-0</c>, <c>Doc.Downloader.Emotet-99</c>), con il prefisso
    /// <c>PUA.</c> per i programmi potenzialmente indesiderati. Da qui si ricava un nome nello stile
    /// di Microsoft (<c>Trojan:Win/Agent</c>) e una descrizione in italiano.
    /// </summary>
    public sealed class ThreatInfo
    {
        /// <summary>Categoria in inglese, come nei nomi delle firme (Trojan, Ransomware, …).</summary>
        public string Category { get; private set; }
        /// <summary>Piattaforma abbreviata (Win, Doc, Html, …) o null.</summary>
        public string Platform { get; private set; }
        public string Family { get; private set; }

        /// <summary>Es. "Trojan:Win/Agent".</summary>
        public string Display
        {
            get { return Category + ":" + (Platform ?? "Multi") + "/" + (Family ?? "Generic"); }
        }

        /// <summary>Es. "Trojan · Windows · famiglia Agent".</summary>
        public string Description
        {
            get
            {
                var parts = new List<string> { CategoryLabel(Category) };
                if (Platform != null) parts.Add(PlatformLabel(Platform));
                if (Family != null && Family != "Generic") parts.Add("famiglia " + Family);
                return string.Join(" · ", parts.ToArray());
            }
        }

        static readonly Dictionary<string, string> Categories = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "Adware", "Adware (pubblicità indesiderata)" },
            { "Backdoor", "Backdoor (accesso remoto nascosto)" },
            { "Coinminer", "Miner di criptovalute" },
            { "Downloader", "Downloader (scarica altro malware)" },
            { "Dropper", "Dropper (installa altro malware)" },
            { "Exploit", "Exploit (sfrutta una vulnerabilità)" },
            { "Infostealer", "Furto di dati" },
            { "Ircbot", "Bot controllato da remoto" },
            { "Keylogger", "Keylogger (registra i tasti)" },
            { "Loader", "Loader (carica altro malware)" },
            { "Macro", "Macro malevola" },
            { "Malware", "Malware" },
            { "Packed", "Eseguibile compresso sospetto" },
            { "Packer", "Packer sospetto" },
            { "Phishing", "Phishing (truffa)" },
            { "Proxy", "Proxy malevolo" },
            { "Ransomware", "Ransomware (cifra i file e chiede un riscatto)" },
            { "Rootkit", "Rootkit (si nasconde nel sistema)" },
            { "Spyware", "Spyware (spia l'utente)" },
            { "Test", "File di prova (innocuo)" },
            { "Tool", "Strumento di attacco" },
            { "Trojan", "Trojan" },
            { "Virus", "Virus" },
            { "Worm", "Worm (si diffonde da solo)" },
            { "PUA", "Programma potenzialmente indesiderato" },
            { "Heuristics", "Rilevamento euristico" },
        };

        static readonly Dictionary<string, string> Platforms = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "Win", "Windows" }, { "Doc", "documento Word" }, { "Xls", "foglio Excel" }, { "Ppt", "presentazione PowerPoint" },
            { "Pdf", "PDF" }, { "Rtf", "documento RTF" }, { "Html", "pagina web" }, { "Js", "JavaScript" }, { "Vbs", "VBScript" },
            { "Java", "Java" }, { "Php", "PHP" }, { "Asp", "ASP" }, { "Email", "e-mail" }, { "Img", "immagine" },
            { "Swf", "Flash" }, { "Andr", "Android" }, { "Osx", "macOS" }, { "Unix", "Linux/Unix" }, { "Multios", "più sistemi" },
            { "Txt", "testo" }, { "Xml", "XML" }, { "Ps1", "PowerShell" }, { "Archive", "archivio" },
        };

        static readonly Regex SigSuffix = new Regex(@"-\d+(-\d+)?$");

        public static ThreatInfo Parse(string name, DetectionSource source = DetectionSource.None)
        {
            if (string.IsNullOrEmpty(name))
                return new ThreatInfo { Category = "Malware" };
            if (name.StartsWith("EICAR", StringComparison.OrdinalIgnoreCase))
                return new ThreatInfo { Category = "Test", Family = "EICAR" };

            var parts = name.Split('.');
            bool pua = parts.Length > 1 && parts[0].Equals("PUA", StringComparison.OrdinalIgnoreCase);
            if (pua)
                parts = Rest(parts, 1);

            // Piattaforma.Categoria.Famiglia(.altro)
            if (parts.Length >= 3 && Platforms.ContainsKey(parts[0]) && Categories.ContainsKey(parts[1]))
                return Make(pua ? "PUA" : parts[1], parts[0], FamilyOf(string.Join(".", Rest(parts, 2))));
            // Categoria.Piattaforma.Famiglia (es. Heuristics.Win.…, Trojan.Win32.…)
            if (parts.Length >= 3 && Categories.ContainsKey(parts[0]) && PlatformFrom(parts[1]) != null)
                return Make(pua ? "PUA" : parts[0], PlatformFrom(parts[1]), FamilyOf(string.Join(".", Rest(parts, 2))));
            // Categoria.Famiglia (es. Heuristics.Broken.Executable, Vigil.Test.X)
            foreach (var p in parts)
            {
                if (Categories.ContainsKey(p))
                    return Make(pua ? "PUA" : p, null, FamilyOf(parts[parts.Length - 1]));
            }
            // Nome senza struttura (es. famiglia da MalwareBazaar: "AgentTesla").
            return Make(pua ? "PUA" : "Malware", null, FamilyOf(name));
        }

        static ThreatInfo Make(string category, string platform, string family)
        {
            foreach (var k in Categories.Keys)
                if (k.Equals(category, StringComparison.OrdinalIgnoreCase)) { category = k; break; }
            if (platform != null)
                foreach (var k in Platforms.Keys)
                    if (k.Equals(platform, StringComparison.OrdinalIgnoreCase)) { platform = k; break; }
            return new ThreatInfo { Category = category, Platform = platform, Family = string.IsNullOrEmpty(family) ? null : family };
        }

        static string PlatformFrom(string p)
        {
            if (Platforms.ContainsKey(p)) return p;
            if (p.StartsWith("Win", StringComparison.OrdinalIgnoreCase)) return "Win"; // Win32, Win64
            return null;
        }

        static string FamilyOf(string s)
        {
            s = SigSuffix.Replace(s ?? "", "");
            // "Agent.ABC" → "Agent"; le parti dopo il primo punto sono varianti.
            int dot = s.IndexOf('.');
            if (dot > 0) s = s.Substring(0, dot);
            return s.Length == 0 ? null : s;
        }

        static string[] Rest(string[] a, int from)
        {
            var r = new string[Math.Max(0, a.Length - from)];
            Array.Copy(a, from, r, 0, r.Length);
            return r;
        }

        public static string CategoryLabel(string c)
        {
            string l;
            return c != null && Categories.TryGetValue(c, out l) ? l : (c ?? "Malware");
        }

        public static string PlatformLabel(string p)
        {
            string l;
            return p != null && Platforms.TryGetValue(p, out l) ? l : p;
        }
    }
}
