using System;
using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Vigil.Engine;

namespace Vigil.Service
{
    /// <summary>
    /// Controllo dei programmi avviati, con l'evento WMI Win32_ProcessStartTrace (da XP).
    /// L'eseguibile viene analizzato appena il processo parte; se è infetto il processo viene
    /// terminato e il file messo in quarantena. Senza driver non si può bloccare PRIMA
    /// dell'avvio: il programma resta in esecuzione per il tempo dell'analisi (di solito
    /// pochi millisecondi grazie alla cache).
    /// </summary>
    sealed class ProcessGuard
    {
        readonly ProtectionCore core;
        ManagementEventWatcher watcher;

        public bool Running { get; private set; }

        public ProcessGuard(ProtectionCore core)
        {
            this.core = core;
        }

        public void Start()
        {
            try
            {
                watcher = new ManagementEventWatcher(new WqlEventQuery("SELECT ProcessID, ProcessName FROM Win32_ProcessStartTrace"));
                watcher.EventArrived += OnStart;
                watcher.Start();
                Running = true;
            }
            catch (Exception)
            {
                // Senza il provider di tracciamento (raro): sondaggio ogni 2 secondi.
                try
                {
                    watcher = new ManagementEventWatcher(new WqlEventQuery("SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_Process'"));
                    watcher.EventArrived += OnStart;
                    watcher.Start();
                    Running = true;
                }
                catch (Exception e)
                {
                    core.Emit("info", null, null, "Controllo dei processi non disponibile: " + e.Message, "failed");
                }
            }
        }

        public void Stop()
        {
            if (watcher == null) return;
            try { watcher.Stop(); watcher.Dispose(); } catch (Exception) { }
            Running = false;
        }

        void OnStart(object sender, EventArrivedEventArgs e)
        {
            int pid;
            try
            {
                var ev = e.NewEvent;
                var target = ev.Properties["TargetInstance"] != null ? ev["TargetInstance"] as ManagementBaseObject : null;
                pid = Convert.ToInt32(target != null ? target["ProcessId"] : ev["ProcessID"]);
            }
            catch (Exception)
            {
                return;
            }
            // L'analisi su un thread del pool: l'evento WMI va liberato subito.
            ThreadPool.QueueUserWorkItem(_ => Check(pid));
        }

        void Check(int pid)
        {
            if (core.IsPaused)
                return;
            var path = ImagePath(pid);
            if (path == null || core.IsOwnPath(path))
                return;
            var opts = core.Options();
            if (opts.Exclusions.IsExcluded(path, false))
                return;
            var r = core.Engine.ScanFile(path, opts);
            Interlocked.Increment(ref core.ProcessesChecked);
            if (r.Verdict.Kind != VerdictKind.Infected)
                return;
            bool killed = Kill(pid);
            Thread.Sleep(300);
            string error;
            var id = core.QuarantineFile(path, r.Verdict, out error);
            var detail = (killed ? "Programma terminato" : "Impossibile terminare il programma") + (id != null ? " e messo in quarantena" : "; quarantena non riuscita: " + error);
            core.Emit("process", path, r.Verdict.Threat, detail, killed ? "killed" : "failed", id);
        }

        static bool Kill(int pid)
        {
            try
            {
                using (var p = Process.GetProcessById(pid))
                {
                    p.Kill();
                    p.WaitForExit(3000);
                }
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>Termina tutti i processi avviati da quell'eseguibile (per poterlo mettere in quarantena).</summary>
        public static void KillByImage(string path)
        {
            foreach (var p in Process.GetProcesses())
            {
                try
                {
                    var img = ImagePath(p.Id);
                    if (img != null && string.Equals(img, path, StringComparison.OrdinalIgnoreCase))
                        p.Kill();
                }
                catch (Exception) { }
                finally { p.Dispose(); }
            }
        }

        /// <summary>
        /// Percorso dell'eseguibile. Da Vista c'è QueryFullProcessImageName (funziona anche da un
        /// servizio a 32 bit verso processi a 64 bit); su XP si ripiega su MainModule e poi su WMI.
        /// </summary>
        public static string ImagePath(int pid)
        {
            try
            {
                var h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                if (h != IntPtr.Zero)
                {
                    try
                    {
                        var sb = new StringBuilder(1024);
                        int size = sb.Capacity;
                        if (QueryFullProcessImageName(h, 0, sb, ref size))
                            return sb.ToString();
                    }
                    finally { CloseHandle(h); }
                }
            }
            catch (EntryPointNotFoundException) { } // Windows XP
            catch (Exception) { }
            try
            {
                using (var p = Process.GetProcessById(pid))
                    return p.MainModule.FileName;
            }
            catch (Exception) { }
            try
            {
                using (var s = new ManagementObjectSearcher("SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = " + pid))
                    foreach (ManagementObject o in s.Get())
                        return o["ExecutablePath"] as string;
            }
            catch (Exception) { }
            return null;
        }

        const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "QueryFullProcessImageNameW")]
        static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder name, ref int size);

        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr h);
    }
}
