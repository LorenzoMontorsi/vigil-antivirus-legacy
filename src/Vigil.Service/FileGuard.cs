using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using Vigil.Engine;

namespace Vigil.Service
{
    /// <summary>
    /// Sorveglianza dei file con FileSystemWatcher su ogni disco fisso.
    ///
    /// Senza driver kernel il controllo avviene subito DOPO la scrittura: si aspetta che il
    /// programma che scrive abbia chiuso il file, poi lo si analizza e, se infetto, lo si
    /// mette in quarantena. Si analizzano i tipi di file pericolosi e qualsiasi eseguibile
    /// (intestazione "MZ"), qualunque estensione abbia.
    /// </summary>
    sealed class FileGuard
    {
        static readonly HashSet<string> RiskyExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".scr", ".com", ".pif", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".hta",
            ".lnk", ".msi", ".msp", ".ps1", ".jar", ".zip", ".rar", ".7z", ".cab", ".iso", ".doc", ".docm", ".xls", ".xlsm",
            ".ppt", ".pptm", ".rtf", ".pdf", ".sys", ".cpl", ".ocx", ".reg", ".inf", ".chm",
        };

        /// <summary>Cartelle molto rumorose e innocue (o gestite da Windows) da non seguire.</summary>
        static readonly string[] NoisyDirs =
        {
            @"\System Volume Information\", @"\Windows\Prefetch\", @"\Windows\SoftwareDistribution\DataStore\",
            @"\Windows\System32\LogFiles\", @"\Windows\System32\wbem\Repository\", @"\Windows\Logs\",
            @"\$Recycle.Bin\", @"\RECYCLER\",
        };

        /// <summary>Un file che continua a cambiare viene analizzato quando resta fermo per questo tempo.</summary>
        static readonly TimeSpan Settle = TimeSpan.FromMilliseconds(1500);
        /// <summary>Oltre questo tempo di file bloccato da chi lo scrive si rinuncia.</summary>
        static readonly TimeSpan GiveUp = TimeSpan.FromMinutes(2);

        readonly ProtectionCore core;
        readonly List<FileSystemWatcher> watchers = new List<FileSystemWatcher>();
        readonly Dictionary<string, Pending> pending = new Dictionary<string, Pending>(StringComparer.OrdinalIgnoreCase);
        readonly AutoResetEvent wake = new AutoResetEvent(false);
        volatile bool stopping;
        Thread worker;

        public List<string> Drives { get; private set; }

        sealed class Pending
        {
            public DateTime LastEvent, First;
        }

        public FileGuard(ProtectionCore core)
        {
            this.core = core;
            Drives = new List<string>();
        }

        public void Start()
        {
            foreach (var d in DriveInfo.GetDrives())
            {
                try
                {
                    if (d.DriveType != DriveType.Fixed || !d.IsReady)
                        continue;
                    var w = new FileSystemWatcher(d.RootDirectory.FullName)
                    {
                        IncludeSubdirectories = true,
                        NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                        InternalBufferSize = 64 * 1024,
                    };
                    w.Created += (s, e) => Enqueue(e.FullPath);
                    w.Changed += (s, e) => Enqueue(e.FullPath);
                    w.Renamed += (s, e) => Enqueue(e.FullPath);
                    w.Error += (s, e) => core.Emit("info", null, null, "Troppe modifiche contemporanee su " + d.Name + ": alcune potrebbero non essere state controllate", null);
                    w.EnableRaisingEvents = true;
                    watchers.Add(w);
                    Drives.Add(d.Name);
                }
                catch (Exception e)
                {
                    core.Emit("info", null, null, "Impossibile sorvegliare " + d.Name + ": " + e.Message, "failed");
                }
            }
            worker = new Thread(Work) { IsBackground = true, Name = "Vigil file", Priority = ThreadPriority.BelowNormal };
            worker.Start();
        }

        public void Stop()
        {
            stopping = true;
            foreach (var w in watchers)
            {
                try { w.EnableRaisingEvents = false; w.Dispose(); } catch (Exception) { }
            }
            wake.Set();
        }

        void Enqueue(string path)
        {
            if (stopping || core.IsOwnPath(path) || NoisyDirs.Any(d => path.IndexOf(d, StringComparison.OrdinalIgnoreCase) >= 0))
                return;
            var now = DateTime.UtcNow;
            lock (pending)
            {
                Pending p;
                if (!pending.TryGetValue(path, out p))
                {
                    if (pending.Count > 20000)
                        return; // tempesta di modifiche (es. copia di migliaia di file): non si esaurisce la memoria
                    pending[path] = p = new Pending { First = now };
                }
                p.LastEvent = now;
            }
            wake.Set();
        }

        void Work()
        {
            while (!stopping)
            {
                wake.WaitOne(500);
                List<string> ready;
                var now = DateTime.UtcNow;
                lock (pending)
                {
                    ready = pending.Where(kv => now - kv.Value.LastEvent >= Settle).Select(kv => kv.Key).Take(200).ToList();
                }
                foreach (var path in ready)
                {
                    if (stopping) return;
                    Pending p;
                    lock (pending)
                    {
                        if (!pending.TryGetValue(path, out p)) continue;
                    }
                    var outcome = Check(path);
                    lock (pending)
                    {
                        if (outcome == Outcome.Retry && now - p.First < GiveUp)
                            p.LastEvent = DateTime.UtcNow; // riprova più tardi
                        else if (pending.ContainsKey(path) && pending[path].LastEvent <= now)
                            pending.Remove(path);
                    }
                }
            }
        }

        enum Outcome { Done, Retry }

        Outcome Check(string path)
        {
            if (core.IsPaused)
                return Outcome.Done;
            try
            {
                if (!File.Exists(path))
                    return Outcome.Done; // file temporaneo già sparito, o era una cartella
                if (!RiskyExtensions.Contains(Path.GetExtension(path)) && !StartsWithMz(path))
                    return Outcome.Done;
            }
            catch (IOException)
            {
                return Outcome.Retry; // ancora aperto in scrittura
            }
            catch (Exception)
            {
                return Outcome.Done;
            }

            var opts = core.Options();
            if (opts.Exclusions.IsExcluded(path, false))
                return Outcome.Done;
            var r = core.Engine.ScanFile(path, opts);
            Interlocked.Increment(ref core.FilesScanned);
            switch (r.Verdict.Kind)
            {
                case VerdictKind.Infected:
                    string error;
                    var id = core.QuarantineFile(path, r.Verdict, out error);
                    if (id == null && File.Exists(path))
                    {
                        // Probabilmente in esecuzione: si termina il processo e si riprova.
                        ProcessGuard.KillByImage(path);
                        Thread.Sleep(500);
                        id = core.QuarantineFile(path, r.Verdict, out error);
                    }
                    core.Emit("file", path, r.Verdict.Threat, id != null ? "Messo in quarantena" : "Quarantena non riuscita: " + error, id != null ? "quarantined" : "failed", id);
                    break;
                case VerdictKind.Suspicious:
                    core.Emit("file", path, null, string.Join("; ", r.Verdict.Reasons.ToArray()), "suspicious");
                    break;
                case VerdictKind.Error:
                    // File bloccato da chi lo scrive: si riprova finché si sblocca.
                    if (r.Verdict.Message.Contains("in uso"))
                        return Outcome.Retry;
                    break;
            }
            return Outcome.Done;
        }

        static bool StartsWithMz(string path)
        {
            using (var f = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                return f.Length >= 2 && f.ReadByte() == 'M' && f.ReadByte() == 'Z';
        }
    }
}
