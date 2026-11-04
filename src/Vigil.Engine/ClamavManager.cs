using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace Vigil.Engine
{
    public enum ClamavStatus
    {
        Disabled,
        /// <summary>I file di ClamAV non sono accanto a Vigil.</summary>
        Missing,
        /// <summary>Mancano le firme: serve un aggiornamento (freshclam).</summary>
        NoDatabase,
        Starting,
        Ready,
        Failed,
    }

    /// <summary>
    /// Gestisce il ClamAV "legacy" incluso (port win32 di Gianluigi Tiesi, gira da XP):
    /// avvia clamd in ascolto solo su 127.0.0.1 e aggiorna le firme con freshclam.
    /// I due programmi stanno nel job del processo: se Vigil termina, terminano anche loro.
    /// Lo usano sia l'app (dati per utente) sia il servizio (dati per tutto il PC).
    /// </summary>
    public sealed class ClamavManager
    {
        /// <summary>Non 3310: così non si scontra con un ClamAV già installato (o con Vigil moderno).</summary>
        public const int Port = 3311;

        readonly object gate = new object();
        Process clamd;
        volatile ClamavStatus status = ClamavStatus.Disabled;

        public event Action StatusChanged;

        public ClamavStatus Status { get { return status; } }
        public string Detail { get; private set; }
        public string VersionText { get; private set; }
        public ClamdClient Client { get; private set; }

        /// <summary>Cartella con clamd.exe, freshclam.exe e le DLL.</summary>
        public string InstallDir { get; private set; }
        /// <summary>Cartella delle firme (daily/main/bytecode).</summary>
        public string DbDir { get; private set; }
        /// <summary>Dove scrivere clamd.conf e freshclam.conf.</summary>
        public string ConfDir { get; private set; }
        public string LogDir { get; private set; }

        /// <summary>true se il clamd in ascolto l'abbiamo avviato noi (e quindi lo spegniamo noi).</summary>
        public bool OwnsDaemon { get; private set; }

        public ClamavManager(string installDir, string dbDir, string confDir, string logDir)
        {
            InstallDir = installDir;
            DbDir = dbDir;
            ConfDir = confDir;
            LogDir = logDir;
            Client = new ClamdClient("127.0.0.1", Port);
        }

        public bool IsInstalled
        {
            get { return File.Exists(Path.Combine(InstallDir, "clamd.exe")) && File.Exists(Path.Combine(InstallDir, "freshclam.exe")); }
        }

        public string BundledVersion
        {
            get
            {
                try { return File.ReadAllText(Path.Combine(InstallDir, "VERSION")).Trim(); }
                catch (Exception) { return null; }
            }
        }

        public bool HasDatabase
        {
            get
            {
                return Directory.Exists(DbDir) && Directory.GetFiles(DbDir).Any(f =>
                    f.EndsWith(".cvd", StringComparison.OrdinalIgnoreCase) || f.EndsWith(".cld", StringComparison.OrdinalIgnoreCase));
            }
        }

        public bool IsReady { get { return status == ClamavStatus.Ready; } }

        void Set(ClamavStatus s, string detail)
        {
            status = s;
            Detail = detail;
            var h = StatusChanged;
            if (h != null) h();
        }

        /// <summary>
        /// Usa un clamd già in ascolto (es. quello del servizio) senza avviarne uno.
        /// true se risponde.
        /// </summary>
        public bool Attach()
        {
            if (!Client.Ping())
                return false;
            OwnsDaemon = false;
            OnReady();
            return true;
        }

        /// <summary>Avvia clamd in background (il caricamento delle firme può richiedere qualche minuto su un PC vecchio).</summary>
        public void Start()
        {
            lock (gate)
            {
                if (!IsInstalled) { Set(ClamavStatus.Missing, "ClamAV non è installato accanto a Vigil"); return; }
                if (clamd != null && !clamd.HasExited) return;
                if (Attach()) return; // già attivo (avvio precedente o servizio)
                if (!HasDatabase) { Set(ClamavStatus.NoDatabase, "Firme di ClamAV assenti: esegui un aggiornamento"); return; }

                var conf = WriteClamdConf();
                var psi = new ProcessStartInfo(Path.Combine(InstallDir, "clamd.exe"), "--config-file=\"" + conf + "\"")
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WorkingDirectory = InstallDir,
                };
                try
                {
                    clamd = Process.Start(psi);
                    ChildProcessJob.Add(clamd);
                    OwnsDaemon = true;
                }
                catch (Exception e)
                {
                    Set(ClamavStatus.Failed, "impossibile avviare clamd: " + e.Message);
                    return;
                }
                Set(ClamavStatus.Starting, "ClamAV sta caricando le firme…");
            }
            new Thread(WaitReady) { IsBackground = true, Name = "clamd wait" }.Start();
        }

        void WaitReady()
        {
            var deadline = DateTime.UtcNow.AddMinutes(10);
            while (DateTime.UtcNow < deadline)
            {
                var p = clamd;
                if (p == null || p.HasExited)
                {
                    Set(ClamavStatus.Failed, "clamd si è chiuso durante l'avvio (vedi " + ClamdLog + ")" + MemoryHint());
                    return;
                }
                if (Client.Ping())
                {
                    OnReady();
                    return;
                }
                Thread.Sleep(1500);
            }
            Set(ClamavStatus.Failed, "clamd non risponde dopo 10 minuti");
        }

        void OnReady()
        {
            try { VersionText = Client.Version(); } catch (Exception) { VersionText = null; }
            Set(ClamavStatus.Ready, VersionText);
        }

        /// <summary>Le firme complete di ClamAV occupano circa 1 GB di RAM.</summary>
        static string MemoryHint()
        {
            var mem = TotalPhysicalMemory();
            return mem > 0 && mem < 1536UL * 1024 * 1024 ? ". Con meno di 1,5 GB di RAM ClamAV potrebbe non riuscire a caricare le firme." : "";
        }

        /// <summary>Ferma clamd se l'abbiamo avviato noi; altrimenti si limita a staccarsi.</summary>
        public void Stop()
        {
            lock (gate)
            {
                if (OwnsDaemon)
                {
                    try { if (Client.Ping()) Client.Shutdown(); } catch (Exception) { }
                    var p = clamd;
                    if (p != null)
                    {
                        try { if (!p.WaitForExit(5000)) p.Kill(); } catch (Exception) { }
                    }
                }
                clamd = null;
                OwnsDaemon = false;
                Set(ClamavStatus.Disabled, "ClamAV disattivato");
            }
        }

        /// <summary>
        /// Aggiorna le firme con freshclam (bloccante: chiamarlo da un thread di lavoro).
        /// Le righe di output vanno a <paramref name="log"/>. Restituisce true se riuscito.
        /// </summary>
        public bool UpdateDatabase(Action<string> log)
        {
            if (!IsInstalled)
            {
                log("ClamAV non è installato accanto a Vigil");
                return false;
            }
            Directory.CreateDirectory(DbDir);
            var conf = WriteFreshclamConf();
            var psi = new ProcessStartInfo(Path.Combine(InstallDir, "freshclam.exe"), "--config-file=\"" + conf + "\" --stdout")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                WorkingDirectory = InstallDir,
            };
            Process p;
            try
            {
                p = Process.Start(psi);
                ChildProcessJob.Add(p);
            }
            catch (Exception e)
            {
                log("impossibile avviare freshclam: " + e.Message);
                return false;
            }
            p.OutputDataReceived += (s, e) => { if (!string.IsNullOrEmpty(e.Data)) log(e.Data.Trim()); };
            p.ErrorDataReceived += (s, e) => { if (!string.IsNullOrEmpty(e.Data)) log(e.Data.Trim()); };
            p.BeginOutputReadLine();
            p.BeginErrorReadLine();
            if (!p.WaitForExit(30 * 60 * 1000))
            {
                try { p.Kill(); } catch (Exception) { }
                log("freshclam non ha terminato entro 30 minuti");
                return false;
            }
            p.WaitForExit(); // svuota l'output asincrono
            bool ok = p.ExitCode == 0 && HasDatabase;
            if (!ok)
                log("freshclam è terminato con codice " + p.ExitCode);
            return ok;
        }

        /// <summary>Dopo un aggiornamento: ricarica le firme se clamd è attivo, altrimenti lo avvia.</summary>
        public void AfterUpdate()
        {
            if (IsReady)
            {
                try
                {
                    Client.Reload();
                    OnReady();
                    return;
                }
                catch (Exception) { }
            }
            Start();
        }

        string ClamdLog { get { return Path.Combine(LogDir, "clamd.log"); } }

        string WriteClamdConf()
        {
            Directory.CreateDirectory(LogDir);
            Directory.CreateDirectory(ConfDir);
            var sb = new StringBuilder();
            sb.AppendLine("# Generato da Vigil Legacy: le modifiche vengono sovrascritte.");
            sb.AppendLine("TCPSocket " + Port);
            sb.AppendLine("TCPAddr 127.0.0.1");
            sb.AppendLine("DatabaseDirectory \"" + DbDir + "\"");
            sb.AppendLine("CVDCertsDirectory \"" + Path.Combine(InstallDir, "certs") + "\"");
            sb.AppendLine("LogFile \"" + ClamdLog + "\"");
            sb.AppendLine("LogFileMaxSize 2M");
            sb.AppendLine("LogTime yes");
            sb.AppendLine("MaxThreads 4");
            sb.AppendLine("StreamMaxLength 100M");
            sb.AppendLine("MaxFileSize 100M");
            sb.AppendLine("MaxScanSize 200M");
            // Su sistemi a 32 bit evita di tenere in memoria due copie delle firme durante RELOAD.
            sb.AppendLine("ConcurrentDatabaseReload no");
            var path = Path.Combine(ConfDir, "clamd.conf");
            File.WriteAllText(path, sb.ToString(), new UTF8Encoding(false));
            return path;
        }

        string WriteFreshclamConf()
        {
            Directory.CreateDirectory(LogDir);
            Directory.CreateDirectory(ConfDir);
            var sb = new StringBuilder();
            sb.AppendLine("# Generato da Vigil Legacy: le modifiche vengono sovrascritte.");
            sb.AppendLine("DatabaseDirectory \"" + DbDir + "\"");
            sb.AppendLine("CVDCertsDirectory \"" + Path.Combine(InstallDir, "certs") + "\"");
            sb.AppendLine("DatabaseMirror database.clamav.net");
            sb.AppendLine("UpdateLogFile \"" + Path.Combine(LogDir, "freshclam.log") + "\"");
            sb.AppendLine("LogFileMaxSize 2M");
            sb.AppendLine("LogTime yes");
            var path = Path.Combine(ConfDir, "freshclam.conf");
            File.WriteAllText(path, sb.ToString(), new UTF8Encoding(false));
            return path;
        }

        // ---- memoria fisica (GlobalMemoryStatusEx: da Windows 2000) ----

        [StructLayout(LayoutKind.Sequential)]
        struct MEMORYSTATUSEX
        {
            public uint dwLength, dwMemoryLoad;
            public ulong ullTotalPhys, ullAvailPhys, ullTotalPageFile, ullAvailPageFile, ullTotalVirtual, ullAvailVirtual, ullAvailExtendedVirtual;
        }

        [DllImport("kernel32.dll")]
        static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX m);

        public static ulong TotalPhysicalMemory()
        {
            var m = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf(typeof(MEMORYSTATUSEX)) };
            return GlobalMemoryStatusEx(ref m) ? m.ullTotalPhys : 0;
        }
    }
}
