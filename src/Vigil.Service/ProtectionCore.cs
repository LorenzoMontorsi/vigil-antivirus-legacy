using System;
using System.Text;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using Vigil.Engine;

namespace Vigil.Service
{
    /// <summary>Dati del servizio, per tutto il PC (su XP: "All Users\Dati applicazioni\VigilLegacy").</summary>
    static class ServicePaths
    {
        public static readonly string DataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "VigilLegacy");
        public static readonly string InstallDir = AppDomain.CurrentDomain.BaseDirectory;
        public static string Signatures { get { return Path.Combine(DataDir, "signatures"); } }
        public static string ClamavDb { get { return Path.Combine(DataDir, "clamav-db"); } }
        public static string Quarantine { get { return Path.Combine(DataDir, "quarantine"); } }
        public static string Logs { get { return Path.Combine(DataDir, "logs"); } }
        public static string Settings { get { return Path.Combine(DataDir, "service.json"); } }
        public static string Cache { get { return Path.Combine(DataDir, "rt-cache.bin"); } }
    }

    [DataContract]
    sealed class ServiceSettings
    {
        [DataMember(Name = "exclusions")] public Exclusions Exclusions = new Exclusions();
        [DataMember(Name = "update_interval_hours")] public int UpdateIntervalHours = 4;
        [DataMember(Name = "clamav_enabled")] public bool ClamavEnabled = true;
        [DataMember(Name = "anti_ransomware")] public bool AntiRansomware = true;
        [DataMember(Name = "self_protection")] public bool SelfProtection = true;
        [DataMember(Name = "yara_package")] public string YaraPackage = "none";
        [DataMember(Name = "yara")] public string Yara;
        [DataMember(Name = "last_update_unix")] public long LastUpdateUnix;
        [DataMember(Name = "last_update_ok")] public bool LastUpdateOk;
        [DataMember(Name = "malwarebazaar_key")] public string MalwareBazaarKey;
        [DataMember(Name = "malwarebazaar")] public string MalwareBazaar;

        [OnDeserializing]
        void Defaults(StreamingContext _)
        {
            Exclusions = new Exclusions();
            UpdateIntervalHours = 4;
            ClamavEnabled = true;
            AntiRansomware = true;
            SelfProtection = true;
            YaraPackage = "none";
        }
    }

    /// <summary>
    /// Il cuore del servizio: motore, ClamAV, quarantena di sistema, sorveglianza di file
    /// e processi, aggiornamenti periodici e pipe di comando per l'app.
    /// </summary>
    sealed class ProtectionCore
    {
        public event Action<string> Log;

        readonly object gate = new object();
        readonly List<RtEvent> events = new List<RtEvent>();
        long nextEventId = 1;

        public ServiceSettings Settings { get; private set; }
        public ClamavManager Clamav { get; private set; }
        public Quarantine Quarantine { get; private set; }
        volatile ScanEngine engine = new ScanEngine();
        public ScanEngine Engine { get { return engine; } }
        public ScanCache Cache { get; private set; }
        public RansomGuard Ransom { get; private set; }
        public DriverManager Driver { get; private set; }

        FileGuard files;
        ProcessGuard processes;
        PipeServer pipe;
        volatile bool stopping;
        int updating;

        long pausedUntil = -1; // -1 = attiva; 0 = sospesa fino al riavvio; altrimenti unix
        public long FilesScanned, ProcessesChecked, Threats;

        public ProtectionCore()
        {
            Directory.CreateDirectory(ServicePaths.DataDir);
            Settings = Json.Load<ServiceSettings>(ServicePaths.Settings) ?? new ServiceSettings();
            if (Settings.Exclusions == null) Settings.Exclusions = new Exclusions();
            Clamav = new ClamavManager(Path.Combine(ServicePaths.InstallDir, "clamav"), ServicePaths.ClamavDb, ServicePaths.DataDir, ServicePaths.Logs);
            Quarantine = new Quarantine(ServicePaths.Quarantine);
            Protect(ServicePaths.Quarantine);
            Protect(ServicePaths.Signatures);
            Ransom = new RansomGuard(this);
            Driver = new DriverManager((detail, action) => Emit("info", null, null, detail, action));
        }

        /// <summary>
        /// Solo SYSTEM e amministratori possono leggere o modificare: un utente normale
        /// (o un malware avviato da lui) non può ripristinare file né cambiare le firme.
        /// </summary>
        static void Protect(string dir)
        {
            try
            {
                Directory.CreateDirectory(dir);
                var sec = new DirectorySecurity();
                sec.SetAccessRuleProtection(true, false);
                foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
                    sec.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid, null), FileSystemRights.FullControl,
                        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                Directory.SetAccessControl(dir, sec);
            }
            catch (Exception) { }
        }

        public void Start()
        {
            Emit("info", null, null, "Protezione avviata", null);
            ReloadSignatures();
            pipe = new PipeServer(this);
            pipe.Start();
            files = new FileGuard(this);
            files.Start();
            processes = new ProcessGuard(this);
            processes.Start();
            Ransom.Start();
            if (Settings.SelfProtection && Driver.Available)
                new Thread(() => Driver.Enable()) { IsBackground = true, Name = "Vigil driver" }.Start();
            if (Settings.ClamavEnabled)
                Clamav.Start();
            if ((Settings.ClamavEnabled && !Clamav.HasDatabase) || IsUpdateDue())
                RunUpdate();
            new Thread(Scheduler) { IsBackground = true, Name = "Vigil aggiornamenti" }.Start();
        }

        public void Stop()
        {
            stopping = true;
            if (files != null) files.Stop();
            if (processes != null) processes.Stop();
            if (pipe != null) pipe.Stop();
            if (Driver != null) Driver.Disable();
            try { if (Cache != null) Cache.Save(); } catch (Exception) { }
            Clamav.Stop();
        }

        void Scheduler()
        {
            while (!stopping)
            {
                Thread.Sleep(TimeSpan.FromMinutes(15));
                if (IsUpdateDue())
                    RunUpdate();
                try { if (Cache != null) Cache.Save(); } catch (Exception) { }
            }
        }

        bool IsUpdateDue()
        {
            return Settings.LastUpdateUnix == 0 || FileUtil.NowUnix() - Settings.LastUpdateUnix >= Math.Max(1, Settings.UpdateIntervalHours) * 3600L;
        }

        public bool IsUpdating { get { return updating != 0; } }

        public void RunUpdate()
        {
            if (Interlocked.CompareExchange(ref updating, 1, 0) != 0)
                return;
            try
            {
                Emit("update", null, null, "Aggiornamento delle firme avviato", "info");
                bool ok = true;
                if (Settings.ClamavEnabled)
                {
                    ok = Clamav.UpdateDatabase(line => Emit("update", null, null, "ClamAV: " + line, "info"));
                    UpdateYara();
                    if (ok)
                        Clamav.AfterUpdate(); // ricarica clamd con firme ClamAV + regole YARA
                }
                if (!string.IsNullOrEmpty(Settings.MalwareBazaarKey))
                {
                    Emit("update", null, null, "MalwareBazaar: download degli hash recenti…", "info");
                    try
                    {
                        Settings.MalwareBazaar = Feeds.UpdateMalwareBazaar(ServicePaths.Signatures, Settings.MalwareBazaarKey);
                    }
                    catch (Exception e)
                    {
                        ok = false;
                        Settings.MalwareBazaar = "errore: " + e.Message;
                    }
                    Emit("update", null, null, "MalwareBazaar: " + Settings.MalwareBazaar, "info");
                }
                ReloadSignatures();
                Settings.LastUpdateUnix = FileUtil.NowUnix();
                Settings.LastUpdateOk = ok;
                SaveSettings();
                Emit("update", null, null, ok ? "Aggiornamento completato" : "Aggiornamento completato con errori", ok ? "info" : "failed");
            }
            finally
            {
                updating = 0;
            }
        }

        /// <summary>Scarica e installa le regole YARA secondo il pacchetto scelto (o le rimuove se "none").</summary>
        void UpdateYara()
        {
            var pkg = (Settings.YaraPackage ?? "none").Trim();
            if (pkg == "none" || pkg.Length == 0)
            {
                if (Clamav.HasYaraRules) Clamav.RemoveYaraRules();
                Settings.Yara = null;
                return;
            }
            Emit("update", null, null, "Regole YARA (" + pkg + "): download da YARA-Forge…", "info");
            try
            {
                var rules = Feeds.FetchYaraForge(pkg);
                int n;
                var err = Clamav.InstallYaraRules(rules, out n);
                Settings.Yara = err == null ? n + " regole (" + pkg + ")" : "errore: " + err;
            }
            catch (Exception e)
            {
                Settings.Yara = "errore: " + e.Message;
            }
            Emit("update", null, null, "Regole YARA: " + Settings.Yara, "info");
        }

        public void RunUpdateAsync()
        {
            new Thread(RunUpdate) { IsBackground = true }.Start();
        }

        public void ReloadSignatures()
        {
            var e = new ScanEngine();
            e.LoadSignatureDir(ServicePaths.Signatures);
            engine = e;
            Cache = null; // nuova generazione al prossimo uso
        }

        public void SaveSettings()
        {
            try { Json.Save(ServicePaths.Settings, Settings); } catch (Exception) { }
        }

        // ---- sospensione ----

        public bool IsPaused
        {
            get
            {
                long p = Interlocked.Read(ref pausedUntil);
                if (p < 0) return false;
                if (p == 0) return true;
                if (FileUtil.NowUnix() < p) return true;
                Interlocked.CompareExchange(ref pausedUntil, -1, p);
                Emit("info", null, null, "Protezione ripresa (fine della sospensione)", null);
                return false;
            }
        }

        public void Pause(int minutes)
        {
            Interlocked.Exchange(ref pausedUntil, minutes <= 0 ? 0 : FileUtil.NowUnix() + minutes * 60L);
            Emit("info", null, null, minutes <= 0 ? "Protezione sospesa fino al riavvio" : "Protezione sospesa per " + minutes + " minuti", null);
        }

        public void Resume()
        {
            Interlocked.Exchange(ref pausedUntil, -1);
            Emit("info", null, null, "Protezione ripresa", null);
        }

        // ---- analisi ----

        /// <summary>Opzioni per la protezione in tempo reale (con ClamAV e cache se disponibili).</summary>
        public ScanOptions Options()
        {
            var o = new ScanOptions { Exclusions = Settings.Exclusions, MaxFileSize = 64L * 1024 * 1024, Threads = 1 };
            if (Settings.ClamavEnabled && Clamav.IsReady)
                o.Clamd = Clamav.Client;
            var gen = Engine.Generation(o, o.Clamd != null ? Clamav.VersionText : null);
            var c = Cache;
            if (c == null || c.Generation != gen)
            {
                if (c != null) { try { c.Save(); } catch (Exception) { } }
                c = Cache = new ScanCache(ServicePaths.Cache, gen);
            }
            o.Cache = c;
            return o;
        }

        /// <summary>I file di Vigil stesso non si analizzano (quarantena, firme, log).</summary>
        public bool IsOwnPath(string path)
        {
            return path.StartsWith(ServicePaths.DataDir, StringComparison.OrdinalIgnoreCase)
                || path.StartsWith(ServicePaths.InstallDir, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>Isola un file infetto; restituisce l'id in quarantena o null.</summary>
        public string QuarantineFile(string path, Verdict v, out string error)
        {
            error = null;
            try
            {
                var item = Quarantine.Add(path, v.Threat, SourceKey(v.Source));
                return item.Id;
            }
            catch (Exception e)
            {
                error = e.Message;
                return null;
            }
        }

        static string SourceKey(DetectionSource s)
        {
            switch (s)
            {
                case DetectionSource.Clamav: return "clamav";
                case DetectionSource.Hash: return "hash";
                case DetectionSource.Pattern: return "pattern";
                default: return "heuristics";
            }
        }

        // ---- eventi ----

        public void Emit(string kind, string path, string threat, string detail, string action, string quarantineId = null)
        {
            var e = new RtEvent { Kind = kind, Path = path, Threat = threat, Detail = detail, Action = action ?? "info", Time = FileUtil.NowUnix(), QuarantineId = quarantineId };
            lock (gate)
            {
                e.Id = nextEventId++;
                events.Add(e);
                if (events.Count > 300)
                    events.RemoveRange(0, events.Count - 300);
            }
            if (threat != null)
                Interlocked.Increment(ref Threats);
            var h = Log;
            if (h != null) h(DateTime.Now.ToString("HH:mm:ss") + " [" + kind + "] " + (threat != null ? threat + " " : "") + (path ?? "") + " " + (detail ?? ""));
            WriteLog(e);
        }

        void WriteLog(RtEvent e)
        {
            if (e.Kind == "update" && e.Action == "info" && e.Detail != null && e.Detail.StartsWith("ClamAV:"))
                return; // l'output di freshclam ha già il suo log
            try
            {
                Directory.CreateDirectory(ServicePaths.Logs);
                // Codifica ANSI del sistema (non UTF-8): così le lettere accentate si leggono
                // correttamente con "type" e col Blocco note di Windows XP.
                File.AppendAllText(Path.Combine(ServicePaths.Logs, "realtime.log"),
                    DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "  " + e.Kind + "  " + e.Action + "  " + (e.Threat ?? "-") + "  " + (e.Path ?? "-") + "  " + (e.Detail ?? "") + Environment.NewLine,
                    Encoding.Default);
            }
            catch (Exception) { }
        }

        public List<RtEvent> EventsSince(long since)
        {
            lock (gate)
                return events.Where(e => e.Id > since).ToList();
        }

        public long LastEventId
        {
            get { lock (gate) return nextEventId - 1; }
        }

        int CountQuarantined()
        {
            try { return Directory.GetFiles(ServicePaths.Quarantine, "*.vq").Length; }
            catch (Exception) { return 0; }
        }

        public RtStatus Status()
        {
            long p = Interlocked.Read(ref pausedUntil);
            return new RtStatus
            {
                Version = ScanEngine.Version,
                Active = !IsPaused,
                Paused = IsPaused,
                PausedUntil = p > 0 ? p : 0,
                Clamav = Settings.ClamavEnabled ? Clamav.Status.ToString() : "Disabled",
                ClamavDetail = Clamav.Detail,
                ClamavVersion = Clamav.VersionText,
                FilesScanned = Interlocked.Read(ref FilesScanned),
                ProcessesChecked = Interlocked.Read(ref ProcessesChecked),
                Threats = Interlocked.Read(ref Threats),
                Signatures = Engine.HashSignatures,
                Updating = IsUpdating,
                LastUpdateUnix = Settings.LastUpdateUnix,
                LastUpdateOk = Settings.LastUpdateOk,
                ProcessMonitor = processes != null && processes.Running,
                WatchedDrives = files != null ? files.Drives : new List<string>(),
                Quarantined = CountQuarantined(),
                Ransomware = Ransom != null && Ransom.Enabled,
                Decoys = Ransom != null ? Ransom.DecoyCount : 0,
                SelfProtection = Driver != null && Driver.Loaded,
                Yara = Settings.ClamavEnabled && (Settings.YaraPackage ?? "none") != "none" ? Settings.Yara : null,
                MalwareBazaar = string.IsNullOrEmpty(Settings.MalwareBazaarKey) ? null : (Settings.MalwareBazaar ?? "in attesa del primo aggiornamento"),
            };
        }
    }
}
