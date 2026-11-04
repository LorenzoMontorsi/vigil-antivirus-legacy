using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Vigil.Engine
{
    /// <summary>
    /// Firme scaricabili oltre a ClamAV: gli hash SHA-256 di MalwareBazaar (abuse.ch).
    /// Serve una Auth-Key gratuita (https://auth.abuse.ch/). Gli hash finiscono in
    /// <c>malwarebazaar.txt</c> nella cartella delle firme e si accumulano a ogni aggiornamento.
    /// </summary>
    public static class Feeds
    {
        public const string MalwareBazaarFile = "malwarebazaar.txt";
        const long MaxDownload = 200L * 1024 * 1024;

        public static bool IsValidKey(string key)
        {
            key = (key ?? "").Trim();
            return key.Length > 0 && key.All(c => (c < 128 && char.IsLetterOrDigit(c)) || c == '-' || c == '_');
        }

        /// <summary>Scarica gli hash delle ultime 48 ore; restituisce il messaggio da mostrare.</summary>
        public static string UpdateMalwareBazaar(string signaturesDir, string key)
        {
            key = (key ?? "").Trim();
            if (!IsValidKey(key))
                throw new ArgumentException("chiave non valida");
            Https.Response r;
            try
            {
                r = Https.Get("https://mb-api.abuse.ch/v2/files/exports/" + key + "/recent.csv", MaxDownload);
            }
            catch (Https.HttpException e)
            {
                if (e.Status == 401 || e.Status == 403)
                    throw new IOException("accesso negato (chiave non valida?)");
                throw;
            }
            var data = r.Body;
            if (data.Length >= 4 && data[0] == 'P' && data[1] == 'K' && data[2] == 3 && data[3] == 4)
                data = FirstCsv(data);
            var fresh = ParseCsv(Encoding.UTF8.GetString(data));
            if (fresh.Count == 0)
                throw new IOException("risposta senza hash (formato cambiato o chiave errata?)");

            Directory.CreateDirectory(signaturesDir);
            var path = Path.Combine(signaturesDir, MalwareBazaarFile);
            var known = new SortedDictionary<string, string>(StringComparer.Ordinal);
            if (File.Exists(path))
            {
                foreach (var line in File.ReadAllLines(path))
                {
                    int sp = line.IndexOf(' ');
                    if (sp == 64) known[line.Substring(0, 64)] = line.Substring(65);
                }
            }
            int before = known.Count;
            foreach (var kv in fresh)
                known[kv.Key] = kv.Value;
            var sb = new StringBuilder(known.Count * 100);
            foreach (var kv in known)
                sb.Append(kv.Key).Append(' ').Append(kv.Value).Append('\n');
            FileUtil.WriteAtomic(path, Encoding.UTF8.GetBytes(sb.ToString()));
            return (known.Count - before) + " nuovi hash, " + known.Count + " in totale";
        }

        static byte[] FirstCsv(byte[] zip)
        {
            var z = ZipReader.Open(zip, 16);
            foreach (var e in z.Entries)
                if (!e.IsDirectory && e.Name.EndsWith(".csv", StringComparison.OrdinalIgnoreCase))
                    return z.Extract(e, MaxDownload);
            throw new IOException("archivio senza file CSV");
        }

        /// <summary>Colonne: first_seen, sha256, md5, sha1, reporter, file_name, file_type, mime, signature, …</summary>
        public static List<KeyValuePair<string, string>> ParseCsv(string text)
        {
            var rows = new List<KeyValuePair<string, string>>();
            using (var r = new StringReader(text))
            {
                string line;
                while ((line = r.ReadLine()) != null)
                {
                    var t = line.Trim();
                    if (t.Length == 0 || t[0] == '#')
                        continue;
                    var f = SplitCsv(t);
                    if (f.Count < 2) continue;
                    var sha = f[1].ToLowerInvariant();
                    Hash256 h;
                    if (sha.Length != 64 || !Hash256.TryParse(sha, out h))
                        continue;
                    var family = f.Count > 8 ? f[8].Trim() : "";
                    string name;
                    if (family.Length == 0 || family == "n/a")
                        name = "MalwareBazaar.Generic";
                    else
                    {
                        var clean = new StringBuilder();
                        foreach (var c in family)
                            clean.Append(c < 128 && (char.IsLetterOrDigit(c) || c == '.' || c == '-') ? c : '_');
                        name = "MalwareBazaar." + clean;
                    }
                    rows.Add(new KeyValuePair<string, string>(sha, name));
                }
            }
            return rows;
        }

        static List<string> SplitCsv(string line)
        {
            var output = new List<string>();
            var cur = new StringBuilder();
            bool quoted = false;
            for (int i = 0; i < line.Length; i++)
            {
                char c = line[i];
                if (c == '"' && quoted && i + 1 < line.Length && line[i + 1] == '"') { cur.Append('"'); i++; }
                else if (c == '"') quoted = !quoted;
                else if (c == ',' && !quoted) { output.Add(cur.ToString().Trim()); cur.Length = 0; }
                else cur.Append(c);
            }
            output.Add(cur.ToString().Trim());
            return output;
        }
    }
}
