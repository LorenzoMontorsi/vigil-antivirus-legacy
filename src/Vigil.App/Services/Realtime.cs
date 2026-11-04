using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Threading;
using Vigil.Engine;

namespace Vigil.App.Services
{
    /// <summary>
    /// Collegamento con il servizio della protezione in tempo reale (se installato).
    /// Ogni 2 secondi legge stato ed eventi nuovi; gli eventi arrivano su un thread di lavoro.
    /// </summary>
    public sealed class Realtime
    {
        long cursor = -1;
        string lastKey = "";

        static string Key(RtStatus s)
        {
            if (s == null) return "none";
            return string.Join("|", new[] { s.Paused.ToString(), s.PausedUntil.ToString(), s.Clamav, s.ClamavVersion, s.Updating.ToString(),
                s.LastUpdateUnix.ToString(), s.Threats.ToString(), s.Quarantined.ToString(), s.ProcessMonitor.ToString() });
        }
        volatile RtStatus status;

        /// <summary>Ultimo stato letto; null se il servizio non è installato o non risponde.</summary>
        public RtStatus Status { get { return status; } }
        public bool Available { get { return status != null; } }

        public event Action Changed;
        public event Action<RtEvent> EventReceived;

        public void Start()
        {
            new Thread(Poll) { IsBackground = true, Name = "Vigil tempo reale" }.Start();
        }

        void Poll()
        {
            while (true)
            {
                var resp = RtProtocol.TryCall(new RtRequest { Cmd = "events", Since = cursor });
                if (resp != null && resp.Ok)
                {
                    status = resp.Status;
                    foreach (var e in resp.Events ?? new List<RtEvent>())
                    {
                        cursor = Math.Max(cursor, e.Id);
                        if (e.Kind != "cursor")
                        {
                            var h = EventReceived;
                            if (h != null) h(e);
                        }
                    }
                }
                else
                {
                    status = null;
                    cursor = -1; // al ritorno del servizio non si ripropongono eventi vecchi
                }
                // Solo i cambiamenti che contano: i contatori dei file cambiano di continuo.
                var key = Key(status);
                if (key != lastKey)
                {
                    lastKey = key;
                    var c = Changed;
                    if (c != null) c();
                }
                Thread.Sleep(2000);
            }
        }

        /// <summary>
        /// Esegue un comando; se serve un amministratore rilancia Vigil con il consenso UAC
        /// (su XP la finestra "Esegui come"). Restituisce null se riuscito, altrimenti l'errore.
        /// </summary>
        public static string Command(RtRequest req)
        {
            RtResponse resp;
            try
            {
                resp = RtProtocol.Call(req);
            }
            catch (Exception e)
            {
                return "il servizio di Vigil non risponde (" + e.Message + ")";
            }
            if (resp.Ok)
                return null;
            if (resp.Error != "admin_required")
                return resp.Error;
            return RunElevated(req);
        }

        static string RunElevated(RtRequest req)
        {
            var exe = System.Reflection.Assembly.GetEntryAssembly().Location;
            // La richiesta viaggia in Base64 per non doversi preoccupare di virgolette e spazi.
            var arg = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(Json.Serialize(req)));
            try
            {
                using (var p = Process.Start(new ProcessStartInfo(exe, "--rt " + arg) { Verb = "runas", UseShellExecute = true }))
                {
                    p.WaitForExit();
                    return p.ExitCode == 0 ? null : "il comando non è riuscito (codice " + p.ExitCode + ")";
                }
            }
            catch (Win32Exception)
            {
                return "operazione annullata: servono i privilegi di amministratore";
            }
        }

        /// <summary>Eseguito nel processo elevato: invia la richiesta e termina.</summary>
        public static int RunHelper(string base64)
        {
            try
            {
                var req = Json.Deserialize<RtRequest>(System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(base64)));
                var resp = RtProtocol.Call(req);
                return resp.Ok ? 0 : 2;
            }
            catch (Exception)
            {
                return 1;
            }
        }
    }
}
