using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Vigil.Engine
{
    /// <summary>
    /// Motore di scansione di Vigil Legacy.
    ///
    /// Livelli di rilevamento, in ordine:
    /// 1. hash SHA-256 di file noti come malevoli;
    /// 2. firme integrate sul contenuto (EICAR);
    /// 3. contenuto degli archivi ZIP (ricorsivo, con limiti anti zip-bomb);
    /// 4. ClamAV tramite clamd, se disponibile (solo sul file di primo livello:
    ///    ClamAV apre da sé archivi ed eseguibili compressi);
    /// 5. euristica statica (nome del file, struttura PE).
    ///
    /// Le firme si caricano da cartelle: file <c>*.txt</c> / <c>*.sha256</c>,
    /// una riga per file: <c>&lt;sha256&gt; [nome minaccia]</c>, <c>#</c> per i commenti.
    /// </summary>
    public sealed class ScanEngine
    {
        public const string Version = "0.1.0";
        const int MaxArchiveDepth = 3;
        const int MaxArchiveEntries = 10000;

        // La stringa EICAR è spezzata in due così il sorgente non contiene la sequenza intera
        // (alcuni antivirus segnalerebbero il file sorgente stesso).
        static readonly byte[] Eicar = Encoding.ASCII.GetBytes(@"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR" + "-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

        readonly Dictionary<Hash256, string> hashes = new Dictionary<Hash256, string>();
        readonly List<string> warnings = new List<string>();

        public int HashSignatures
        {
            get { return hashes.Count; }
        }

        /// <summary>Problemi non fatali durante il caricamento delle firme.</summary>
        public IList<string> Warnings
        {
            get { return warnings; }
        }

        public void AddHashList(string text, string origin)
        {
            int bad = 0;
            using (var r = new StringReader(text))
            {
                string line;
                while ((line = r.ReadLine()) != null)
                {
                    line = line.Trim();
                    if (line.Length == 0 || line[0] == '#')
                        continue;
                    int sp = line.IndexOfAny(new[] { ' ', '\t' });
                    string hex = sp < 0 ? line : line.Substring(0, sp);
                    string name = sp < 0 ? "" : line.Substring(sp + 1).Trim();
                    Hash256 h;
                    if (Hash256.TryParse(hex, out h))
                        hashes[h] = name.Length > 0 ? name : "Malware.Hash.Generic";
                    else
                        bad++;
                }
            }
            if (bad > 0)
                warnings.Add(origin + ": " + bad + " righe con hash SHA-256 non valido ignorate");
        }

        /// <summary>Carica tutte le firme presenti in una cartella (non ricorsivo).</summary>
        public void LoadSignatureDir(string dir)
        {
            if (!Directory.Exists(dir))
                return;
            string[] files;
            try
            {
                files = Directory.GetFiles(dir);
            }
            catch (Exception e)
            {
                warnings.Add(dir + ": " + e.Message);
                return;
            }
            Array.Sort(files, StringComparer.OrdinalIgnoreCase);
            foreach (var f in files)
            {
                var ext = Path.GetExtension(f).ToLowerInvariant();
                if (ext != ".txt" && ext != ".sha256")
                    continue;
                try
                {
                    AddHashList(File.ReadAllText(f), Path.GetFileName(f));
                }
                catch (Exception e)
                {
                    warnings.Add(Path.GetFileName(f) + ": " + e.Message);
                }
            }
        }

        public ScanResult ScanFile(string path, ScanOptions opts)
        {
            var result = new ScanResult { Path = path, Verdict = Verdict.Clean };
            FileInfo fi;
            try
            {
                fi = new FileInfo(path);
                result.Size = fi.Length;
            }
            catch (Exception e)
            {
                result.Verdict = IoErrorVerdict(e);
                return result;
            }
            if (opts.Cache != null && opts.Cache.IsClean(fi))
            {
                result.Cached = true;
                return result;
            }
            if (fi.Length > opts.MaxFileSize)
            {
                result.Verdict = Verdict.Skipped("file più grande del limite (" + opts.MaxFileSize / (1024 * 1024) + " MB)");
                return result;
            }
            byte[] data;
            try
            {
                data = ReadShared(path);
            }
            catch (Exception e)
            {
                result.Verdict = IoErrorVerdict(e);
                return result;
            }
            // Gli eseguibili con firma Microsoft valida saltano i controlli costosi
            // o soggetti a falsi positivi (ClamAV, euristica).
            if (opts.TrustMicrosoft && data.Length >= 2 && data[0] == 'M' && data[1] == 'Z')
                result.Signer = Trust.Signer(path);
            bool trusted = Trust.IsMicrosoft(result.Signer);
            byte[] digest;
            result.Verdict = Detect(data, path, opts, 0, trusted, out digest);
            result.Sha256 = Hashing.ToHex(digest);
            if (opts.Cache != null)
            {
                if (result.Verdict.Kind == VerdictKind.Clean)
                    opts.Cache.MarkClean(fi);
                else
                    opts.Cache.Forget(path);
            }
            return result;
        }

        /// <summary>Analizza dati in memoria; <paramref name="pathHint"/> serve all'euristica sul nome.</summary>
        public Verdict ScanBytes(byte[] data, string pathHint, ScanOptions opts)
        {
            byte[] digest;
            return Detect(data, pathHint, opts, 0, false, out digest);
        }

        Verdict Detect(byte[] data, string pathHint, ScanOptions opts, int depth, bool trusted, out byte[] digest)
        {
            digest = Hashing.Sha256(data);

            // 1. Hash noti.
            string name;
            if (hashes.TryGetValue(new Hash256(digest), out name))
                return Verdict.Infected(name, DetectionSource.Hash);

            // 2. Firme integrate: EICAR (la stringa all'inizio, al massimo 128 byte in tutto).
            if (data.Length <= 128 && StartsWith(data, Eicar))
                return Verdict.Infected("EICAR_Test_File", DetectionSource.Pattern, "File di test standard EICAR (innocuo)");

            // 3. Archivi.
            if (opts.ScanArchives && depth < MaxArchiveDepth && ZipReader.LooksLikeZip(data))
            {
                var v = ScanZip(data, opts, depth + 1);
                if (v != null)
                    return v;
            }

            // 4. ClamAV.
            if (depth == 0 && !trusted && opts.Clamd != null)
            {
                try
                {
                    var found = opts.Clamd.Scan(data);
                    if (found != null)
                        return Verdict.Infected(found, DetectionSource.Clamav);
                }
                catch (Exception e)
                {
                    return Verdict.Error(e.Message);
                }
            }

            // 5. Euristica.
            if (opts.Heuristics && !trusted)
            {
                var f = Heuristics.Analyze(data, FileName(pathHint));
                if (f != null)
                    return Verdict.Suspicious(f.Score, f.Reasons);
            }
            return Verdict.Clean;
        }

        /// <summary>La prima minaccia trovata nell'archivio, oppure null.</summary>
        Verdict ScanZip(byte[] data, ScanOptions opts, int depth)
        {
            var zip = ZipReader.Open(data, MaxArchiveEntries);
            if (zip == null)
                return null;
            long budget = opts.MaxFileSize * 4, total = 0;
            foreach (var e in zip.Entries)
            {
                if (e.IsDirectory || e.Size > opts.MaxFileSize)
                    continue;
                var inner = zip.Extract(e, opts.MaxFileSize);
                if (inner == null)
                    continue; // cifrata, metodo non supportato o troppo grande
                total += inner.Length;
                if (total > budget)
                    break;
                byte[] d;
                var v = Detect(inner, e.Name, opts, depth, false, out d);
                if (v.Kind == VerdictKind.Infected)
                    return v.WithLocation(v.Location != null ? e.Name + " › " + v.Location : e.Name);
            }
            return null;
        }

        /// <summary>Legge il file anche se è aperto in scrittura da un altro programma.</summary>
        static byte[] ReadShared(string path)
        {
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                var data = new byte[fs.Length];
                int off = 0, r;
                while (off < data.Length && (r = fs.Read(data, off, data.Length - off)) > 0)
                    off += r;
                if (off < data.Length)
                    Array.Resize(ref data, off);
                return data;
            }
        }

        static bool StartsWith(byte[] data, byte[] prefix)
        {
            if (data.Length < prefix.Length)
                return false;
            for (int i = 0; i < prefix.Length; i++)
                if (data[i] != prefix[i])
                    return false;
            return true;
        }

        static string FileName(string path)
        {
            if (string.IsNullOrEmpty(path))
                return "";
            int i = path.LastIndexOfAny(new[] { '\\', '/' });
            return i < 0 ? path : path.Substring(i + 1);
        }

        internal static Verdict IoErrorVerdict(Exception e)
        {
            if (e is UnauthorizedAccessException)
                return Verdict.Error("accesso negato");
            int code = System.Runtime.InteropServices.Marshal.GetHRForException(e) & 0xFFFF;
            // 225 = ERROR_VIRUS_INFECTED: un altro antivirus ha bloccato la lettura.
            if (code == 225)
                return Verdict.Error("lettura bloccata da un altro antivirus (probabile minaccia)");
            if (code == 32 || code == 33)
                return Verdict.Error("file in uso da un altro processo");
            return Verdict.Error(e.Message);
        }

        /// <summary>Identifica firme e opzioni, per invalidare la cache quando cambiano.</summary>
        public string Generation(ScanOptions opts, string clamavVersion)
        {
            var sb = new StringBuilder();
            sb.Append(Version).Append('|').Append(hashes.Count).Append('|').Append(clamavVersion ?? "-");
            sb.Append('|').Append(opts.Heuristics).Append(opts.ScanArchives).Append(opts.TrustMicrosoft).Append(opts.MaxFileSize);
            // Somma degli hash: cambia se cambiano le firme anche a parità di numero.
            ulong x = 0;
            foreach (var h in hashes.Keys)
                x += (ulong)h.GetHashCode() * 2654435761UL;
            sb.Append('|').Append(x.ToString("x"));
            return Hashing.ToHex(Hashing.Sha256(Encoding.UTF8.GetBytes(sb.ToString()))).Substring(0, 16);
        }
    }
}
