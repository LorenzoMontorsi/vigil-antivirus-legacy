using System;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace Vigil.Service
{
    /// <summary>
    /// Gestisce il minifilter di autodifesa vigilflt.sys (a 32 bit, XP/Win7 x86): lo registra con
    /// l'INF e lo carica/scarica tramite fltmc, strumenti già presenti in Windows da XP SP2.
    ///
    /// Sui Windows a 64 bit il driver a 32 bit non si carica (serve una build a 64 bit firmata):
    /// in quel caso il servizio prosegue senza, con la sola autodifesa a livello di ACL.
    /// </summary>
    sealed class DriverManager
    {
        public const string FilterName = "vigilflt";

        readonly Action<string, string> log; // (dettaglio, azione)
        public bool Loaded { get; private set; }

        public DriverManager(Action<string, string> log)
        {
            this.log = log;
        }

        string Sys { get { return Path.Combine(ServicePaths.InstallDir, "vigilflt.sys"); } }
        string Inf { get { return Path.Combine(ServicePaths.InstallDir, "vigilflt.inf"); } }
        public bool Available { get { return File.Exists(Sys) && File.Exists(Inf); } }

        /// <summary>Solo su Windows a 32 bit il driver a 32 bit può caricarsi.</summary>
        public static bool Is32BitWindows
        {
            get { return IntPtr.Size == 4 && !InWow64(); }
        }

        static bool InWow64()
        {
            try
            {
                bool wow;
                return IsWow64Process(Process.GetCurrentProcess().Handle, out wow) && wow;
            }
            catch (Exception) { return false; }
        }

        /// <summary>Registra (se serve) e carica il minifilter. Restituisce true se risulta attivo.</summary>
        public bool Enable()
        {
            if (!Available)
                return false;
            if (!Is32BitWindows)
            {
                log("Autodifesa del driver non disponibile su Windows a 64 bit (serve una build a 64 bit firmata)", "info");
                return false;
            }
            try
            {
                if (!Registered())
                    Register();
                int code = Run(Fltmc, "load " + FilterName, 30000);
                // 0 = caricato; già caricato = errore non fatale.
                Loaded = code == 0 || IsLoaded();
                log(Loaded ? "Autodifesa del driver attiva (minifilter vigilflt)" : "Impossibile caricare il minifilter (codice " + code + ")", Loaded ? "info" : "failed");
                return Loaded;
            }
            catch (Exception e)
            {
                log("Errore nell'attivare il driver di autodifesa: " + e.Message, "failed");
                return false;
            }
        }

        /// <summary>Scarica il minifilter (così i file di Vigil tornano modificabili, es. per aggiornarlo).</summary>
        public void Disable()
        {
            try
            {
                Run(Fltmc, "unload " + FilterName, 30000);
            }
            catch (Exception) { }
            Loaded = false;
        }

        /// <summary>
        /// Registra il minifilter senza finestre (InstallHinfSection mostra dialoghi): copia il .sys
        /// in system32\drivers, crea il servizio del filtro con sc e scrive le chiavi dell'istanza.
        /// </summary>
        void Register()
        {
            File.Copy(Sys, Path.Combine(Environment.SystemDirectory, "drivers", "vigilflt.sys"), true);
            Run(Sc, "create " + FilterName + " type= filesys start= demand binPath= System32\\drivers\\vigilflt.sys DisplayName= \"Vigil Legacy Self-Protection\"", 30000);
            Run(Sc, "description " + FilterName + " \"Protegge i file di Vigil Legacy (minifilter).\"", 15000);
            using (var k = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                @"SYSTEM\CurrentControlSet\Services\" + FilterName + @"\Instances"))
            {
                k.SetValue("DefaultInstance", "Vigil Legacy Instance");
                using (var inst = k.CreateSubKey("Vigil Legacy Instance"))
                {
                    inst.SetValue("Altitude", "328010");
                    inst.SetValue("Flags", 0, Microsoft.Win32.RegistryValueKind.DWord);
                }
            }
        }

        /// <summary>Rimuove del tutto il filtro (per la disinstallazione): scarica, elimina servizio e file.</summary>
        public void Uninstall()
        {
            Disable();
            try { Run(Sc, "delete " + FilterName, 15000); } catch (Exception) { }
            try { File.Delete(Path.Combine(Environment.SystemDirectory, "drivers", "vigilflt.sys")); } catch (Exception) { }
        }

        static string Sc { get { return Path.Combine(Environment.SystemDirectory, "sc.exe"); } }

        bool Registered()
        {
            try
            {
                using (var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\" + FilterName))
                    return k != null;
            }
            catch (Exception) { return false; }
        }

        bool IsLoaded()
        {
            try
            {
                var o = new StringBuilder();
                Run(Fltmc, "filters", 15000, o);
                return o.ToString().IndexOf(FilterName, StringComparison.OrdinalIgnoreCase) >= 0;
            }
            catch (Exception) { return false; }
        }

        static string Fltmc { get { return Path.Combine(Environment.SystemDirectory, "fltmc.exe"); } }

        static int Run(string exe, string args, int timeoutMs, StringBuilder output = null)
        {
            var psi = new ProcessStartInfo(exe, args)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using (var p = Process.Start(psi))
            {
                if (output != null)
                {
                    p.OutputDataReceived += (s, e) => { if (e.Data != null) lock (output) output.AppendLine(e.Data); };
                    p.ErrorDataReceived += (s, e) => { if (e.Data != null) lock (output) output.AppendLine(e.Data); };
                    p.BeginOutputReadLine();
                    p.BeginErrorReadLine();
                }
                if (!p.WaitForExit(timeoutMs))
                {
                    try { p.Kill(); } catch (Exception) { }
                    return -1;
                }
                p.WaitForExit();
                return p.ExitCode;
            }
        }

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        static extern bool IsWow64Process(IntPtr process, out bool wow64);
    }
}
