using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using Microsoft.Win32;
using Vigil.Engine;

namespace Vigil.Service
{
    /// <summary>
    /// Protezione contro i ransomware, senza driver kernel, con due segnali:
    ///
    /// 1. <b>File-esca</b> (honeypot): documenti finti e nascosti sparsi nelle cartelle dell'utente,
    ///    con nomi che vengono elaborati per primi o per ultimi. Un ransomware che cifra i documenti
    ///    in ordine ne colpisce quasi subito uno: se un'esca viene modificata, rinominata o cancellata
    ///    è quasi certamente un ransomware (l'utente non apre mai quei file).
    /// 2. <b>Ondata</b>: tanti documenti modificati in pochi secondi, o diversi file rinominati con
    ///    un'estensione tipica dei ransomware (.locked, .encrypted, …), o la comparsa di molte note
    ///    di riscatto.
    ///
    /// Alla reazione si fermano i programmi sospetti (non firmati, avviati da poco: com'è di solito
    /// un ransomware) e si avvisa l'utente. Senza driver non si può attribuire con certezza la
    /// scrittura a un processo, quindi la scelta è euristica: è una rete di sicurezza in più, non una
    /// garanzia. I file già colpiti non si possono recuperare da qui.
    /// </summary>
    sealed class RansomGuard
    {
        /// <summary>Estensioni con cui i ransomware rinominano i file cifrati.</summary>
        static readonly HashSet<string> RansomExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".locked", ".encrypted", ".enc", ".crypt", ".crypted", ".crypto", ".cry", ".locky", ".cerber",
            ".zepto", ".odin", ".thor", ".aesir", ".wncry", ".wcry", ".wncryt", ".onion", ".ecc", ".ezz",
            ".exx", ".xyz", ".zzz", ".micro", ".vvv", ".ccc", ".abc", ".xxx", ".ttt", ".vault", ".petya",
            ".lol", ".kraken", ".darkness", ".nochance", ".oops", ".kernel_pid", ".rokku", ".encrypt",
            ".R5A", ".R4A", ".pzdc", ".good", ".LeChiffre", ".keybtc", ".clf", ".rrk", ".cryptotorlocker",
        };

        /// <summary>Tipi di documento che un ransomware prende di mira (per contare le ondate).</summary>
        static readonly HashSet<string> DocumentExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".pdf", ".rtf", ".odt",
            ".ods", ".txt", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".psd", ".raw",
            ".zip", ".rar", ".7z", ".mdb", ".accdb", ".sql", ".csv", ".dwg", ".cdr", ".eps", ".mp3",
            ".mp4", ".avi", ".mkv", ".sln", ".cs", ".cpp", ".php", ".html",
        };

        /// <summary>Nomi tipici delle note di riscatto.</summary>
        static readonly string[] RansomNotes =
        {
            "decrypt", "how_to", "howto", "recover", "restore", "readme", "ransom", "your_files", "help_decrypt",
            "_locked", "unlock",
        };

        const int BurstWindowMs = 12000;     // finestra dell'ondata
        const int BurstThreshold = 40;       // documenti distinti modificati nella finestra
        const int RenameWindowMs = 30000;
        const int RenameThreshold = 5;       // rinomine con estensione da riscatto

        readonly ProtectionCore core;
        readonly object gate = new object();
        readonly Dictionary<string, Decoy> decoys = new Dictionary<string, Decoy>(StringComparer.OrdinalIgnoreCase);
        readonly Dictionary<string, long> recentDocs = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        readonly List<long> recentRansomRenames = new List<long>();
        long trippedAt;            // unix dell'ultima reazione (antirimbalzo)
        volatile bool deploying;

        public bool Enabled { get; private set; }
        public int DecoyCount { get { lock (gate) return decoys.Count; } }

        sealed class Decoy
        {
            public long Size;
            public string Sha;
        }

        public RansomGuard(ProtectionCore core)
        {
            this.core = core;
        }

        public void Start()
        {
            Enabled = core.Settings.AntiRansomware;
            if (!Enabled)
                return;
            // La semina dei file-esca può toccare molte cartelle: in background per non ritardare l'avvio.
            new Thread(() =>
            {
                try { DeployDecoys(); }
                catch (Exception e) { core.Emit("info", null, null, "Anti-ransomware: impossibile creare i file-esca: " + e.Message, "failed"); }
            }) { IsBackground = true, Name = "Vigil esche" }.Start();
        }

        public void SetEnabled(bool on)
        {
            Enabled = on;
            if (on) Start();
            else RemoveDecoys();
        }

        // ---- file-esca ----

        /// <summary>Cartelle in cui seminare le esche: profili utente (radice, Desktop, Documenti) e radici dei dischi.</summary>
        IEnumerable<string> DecoyFolders()
        {
            var folders = new List<string>();
            try
            {
                string profiles;
                using (var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"))
                    profiles = k != null ? Environment.ExpandEnvironmentVariables((string)k.GetValue("ProfilesDirectory", "")) : null;
                if (!string.IsNullOrEmpty(profiles) && Directory.Exists(profiles))
                {
                    foreach (var prof in Directory.GetDirectories(profiles))
                    {
                        var name = Path.GetFileName(prof);
                        if (name.Equals("All Users", StringComparison.OrdinalIgnoreCase) ||
                            name.StartsWith("Default", StringComparison.OrdinalIgnoreCase) ||
                            name.Equals("LocalService", StringComparison.OrdinalIgnoreCase) ||
                            name.Equals("NetworkService", StringComparison.OrdinalIgnoreCase))
                            continue;
                        folders.Add(prof);
                        foreach (var sub in new[] { "Desktop", "Documents", "Documenti", "My Documents", "Immagini", "Pictures" })
                        {
                            var p = Path.Combine(prof, sub);
                            if (Directory.Exists(p)) folders.Add(p);
                        }
                    }
                }
            }
            catch (Exception) { }
            return folders.Distinct(StringComparer.OrdinalIgnoreCase);
        }

        void DeployDecoys()
        {
            deploying = true;
            try
            {
                // Due esche per cartella: una che viene elaborata per prima (nomi che iniziano con "!"),
                // una per ultima ("~zzz"). Nascoste e di sistema, così l'utente non le vede né le tocca.
                var content = DecoyContent();
                var sha = Hashing.ToHex(Hashing.Sha256(content));
                foreach (var folder in DecoyFolders())
                {
                    foreach (var fn in new[] { "!!!_documenti_importanti.docx", "~zzz_archivio_backup.xlsx" })
                    {
                        var path = Path.Combine(folder, fn);
                        try
                        {
                            if (File.Exists(path)) File.SetAttributes(path, FileAttributes.Normal);
                            File.WriteAllBytes(path, content);
                            File.SetAttributes(path, FileAttributes.Hidden | FileAttributes.System | FileAttributes.NotContentIndexed);
                            lock (gate) decoys[path] = new Decoy { Size = content.Length, Sha = sha };
                        }
                        catch (Exception) { }
                    }
                }
                SaveRegistry();
                core.Emit("info", null, null, "Anti-ransomware attivo (" + DecoyCount + " file-esca)", null);
            }
            finally
            {
                // Lascia depositare gli eventi di scrittura delle esche prima di riattivare la sorveglianza.
                Thread.Sleep(3000);
                deploying = false;
            }
        }

        static byte[] DecoyContent()
        {
            // Testo plausibile e di dimensione fissa: l'hash noto permette di capire se è stato cifrato.
            var sb = new StringBuilder();
            sb.AppendLine("Elenco documenti - riservato");
            sb.AppendLine("Questo file è un segnaposto generato automaticamente. Non modificarlo.");
            for (int i = 1; i <= 60; i++)
                sb.AppendLine("Voce " + i.ToString("000") + " - pratica " + (1000 + i) + " - archiviata - riferimento interno.");
            return Encoding.UTF8.GetBytes(sb.ToString());
        }

        void SaveRegistry()
        {
            try
            {
                var sb = new StringBuilder();
                lock (gate)
                    foreach (var kv in decoys)
                        sb.Append(kv.Value.Size).Append('|').Append(kv.Value.Sha).Append('|').Append(kv.Key).Append('\n');
                FileUtil.WriteAtomic(Path.Combine(ServicePaths.DataDir, "decoys.dat"), Encoding.UTF8.GetBytes(sb.ToString()));
            }
            catch (Exception) { }
        }

        void RemoveDecoys()
        {
            lock (gate)
            {
                foreach (var path in decoys.Keys.ToList())
                {
                    try { File.SetAttributes(path, FileAttributes.Normal); File.Delete(path); } catch (Exception) { }
                }
                decoys.Clear();
            }
            try { File.Delete(Path.Combine(ServicePaths.DataDir, "decoys.dat")); } catch (Exception) { }
        }

        bool IsDecoy(string path)
        {
            lock (gate) return decoys.ContainsKey(path);
        }

        // ---- osservazione degli eventi dei file (dal FileGuard) ----

        /// <summary>Un file è stato creato/modificato (<paramref name="renamedFrom"/> != null se rinominato).</summary>
        public void Observe(string path, string renamedFrom)
        {
            if (!Enabled || deploying || core.IsPaused)
                return;
            try
            {
                // 1. Un'esca toccata: segnale fortissimo.
                if (renamedFrom != null && IsDecoy(renamedFrom))
                {
                    Trip("un file-esca è stato rinominato (" + Path.GetFileName(renamedFrom) + ")", path);
                    return;
                }
                if (IsDecoy(path) && DecoyTampered(path))
                {
                    Trip("un file-esca è stato cifrato o alterato (" + Path.GetFileName(path) + ")", path);
                    return;
                }

                var ext = Path.GetExtension(path);
                long now = Environment.TickCount & 0xffffffffL;

                // 2a. Rinomina verso un'estensione da riscatto.
                if (renamedFrom != null && RansomExtensions.Contains(ext))
                {
                    int renames;
                    lock (gate)
                    {
                        recentRansomRenames.Add(now);
                        recentRansomRenames.RemoveAll(t => now - t > RenameWindowMs);
                        renames = recentRansomRenames.Count;
                    }
                    if (renames >= RenameThreshold)
                        Trip(renames + " file rinominati con estensioni da ransomware", path);
                    return;
                }

                // 2b. Ondata di documenti modificati.
                if (DocumentExtensions.Contains(ext) || IsRansomNote(path))
                {
                    int count;
                    lock (gate)
                    {
                        recentDocs[path] = now;
                        if (recentDocs.Count > 5000)
                            foreach (var k in recentDocs.Where(kv => now - kv.Value > BurstWindowMs).Select(kv => kv.Key).ToList())
                                recentDocs.Remove(k);
                        count = recentDocs.Count(kv => now - kv.Value <= BurstWindowMs);
                    }
                    if (count >= BurstThreshold)
                        Trip(count + " documenti modificati in pochi secondi", path);
                }
            }
            catch (Exception) { }
        }

        bool DecoyTampered(string path)
        {
            Decoy d;
            lock (gate) if (!decoys.TryGetValue(path, out d)) return false;
            try
            {
                if (!File.Exists(path)) return true; // cancellata
                var data = File.ReadAllBytes(path);
                return data.Length != d.Size || !Hashing.ToHex(Hashing.Sha256(data)).Equals(d.Sha, StringComparison.OrdinalIgnoreCase);
            }
            catch (IOException)
            {
                return false; // ancora in scrittura: si rivaluta al prossimo evento
            }
        }

        static bool IsRansomNote(string path)
        {
            var name = Path.GetFileNameWithoutExtension(path).ToLowerInvariant();
            var ext = Path.GetExtension(path).ToLowerInvariant();
            if (ext != ".txt" && ext != ".html" && ext != ".hta" && ext != ".htm") return false;
            return RansomNotes.Any(n => name.Contains(n));
        }

        // ---- reazione ----

        void Trip(string reason, string path)
        {
            long now = FileUtil.NowUnix();
            lock (gate)
            {
                if (now - trippedAt < 60) return; // una reazione al minuto
                trippedAt = now;
            }
            core.Emit("ransom", path, "Ransomware.Sospetto", "Possibile ransomware: " + reason, "ransom");
            var killed = core.Settings.AntiRansomware ? KillSuspects() : new List<string>();
            if (killed.Count > 0)
                core.Emit("ransom", null, "Ransomware.Sospetto", "Programmi sospetti fermati: " + string.Join(", ", killed.Select(Path.GetFileName).ToArray()), "killed");
            else
                core.Emit("ransom", null, "Ransomware.Sospetto", "Nessun programma sospetto identificato: metti al sicuro i tuoi file e controlla subito il PC", "failed");
        }

        /// <summary>
        /// Ferma i candidati: processi non firmati, fuori da Windows, avviati di recente. Senza driver non
        /// si sa con certezza chi scrive, quindi si colpisce il profilo tipico del ransomware appena lanciato.
        /// </summary>
        List<string> KillSuspects()
        {
            var killed = new List<string>();
            var windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            var now = DateTime.Now;
            foreach (var p in Process.GetProcesses())
            {
                string path = null;
                try
                {
                    path = ProcessGuard.ImagePath(p.Id);
                    if (path == null || core.IsOwnPath(path))
                        continue;
                    if (path.StartsWith(windir, StringComparison.OrdinalIgnoreCase))
                        continue; // mai i processi di sistema
                    DateTime started;
                    try { started = p.StartTime; } catch (Exception) { continue; }
                    if ((now - started).TotalMinutes > 5)
                        continue; // il ransomware è appena partito; i programmi vecchi si risparmiano
                    if (Trust.Signer(path) != null)
                        continue; // firmato: considerato legittimo
                    p.Kill();
                    killed.Add(path);
                }
                catch (Exception) { }
                finally { p.Dispose(); }
            }
            return killed;
        }
    }
}
