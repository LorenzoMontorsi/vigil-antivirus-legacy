using System;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace Vigil.Service
{
    /// <summary>
    /// Gestisce il minifilter di autodifesa vigilflt.sys: lo registra con sc + chiavi dell'istanza
    /// e lo carica/scarica tramite fltmc (strumenti presenti in Windows da XP SP2).
    ///
    /// Funziona sia a 32 sia a 64 bit: il driver incluso nell'edizione ha gli stessi bit del sistema.
    /// Il servizio è un processo a 32 bit; su Windows a 64 bit usa il percorso "Sysnative" per
    /// raggiungere il vero system32 senza la redirezione WOW64. Sui 64 bit il driver si carica solo
    /// se il sistema è in test-signing e il certificato di prova è fidato: lo abilita lo script
    /// "abilita-driver-64bit.cmd" incluso nell'edizione a 64 bit.
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
        public bool Available { get { return File.Exists(Sys); } }

        /// <summary>
        /// Vero system32: su Windows a 64 bit un processo a 32 bit verrebbe deviato in SysWOW64,
        /// quindi si usa l'alias "Sysnative" per installare il driver a 64 bit nella cartella giusta.
        /// </summary>
        static string SysDir
        {
            get
            {
                var win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
                if (IntPtr.Size == 4 && InWow64())
                {
                    var sysnative = Path.Combine(win, "Sysnative");
                    if (Directory.Exists(sysnative)) return sysnative;
                }
                return Environment.SystemDirectory;
            }
        }

        static bool Is64BitWindows { get { return IntPtr.Size == 8 || InWow64(); } }

        static bool InWow64()
        {
            try
            {
                bool wow;
                return IsWow64Process(Process.GetCurrentProcess().Handle, out wow) && wow;
            }
            catch (Exception) { return false; }
        }

        string Fltmc { get { return Path.Combine(SysDir, "fltmc.exe"); } }
        string Sc { get { return Path.Combine(SysDir, "sc.exe"); } }
        string DriversDir { get { return Path.Combine(SysDir, "drivers"); } }

        /// <summary>Registra (se serve) e carica il minifilter. Restituisce true se risulta attivo.</summary>
        public bool Enable()
        {
            if (!Available)
                return false;
            try
            {
                if (!Registered())
                    Register();
                int code = Run(Fltmc, "load " + FilterName, 30000);
                Loaded = code == 0 || IsLoaded();
                if (Loaded)
                    log("Autodifesa del driver attiva (minifilter vigilflt)", "info");
                else if (Is64BitWindows)
                    log("Driver di autodifesa non caricato: su Windows a 64 bit serve il test-signing (esegui 'abilita-driver-64bit.cmd' e riavvia)", "failed");
                else
                    log("Impossibile caricare il minifilter di autodifesa (codice " + code + ")", "failed");
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
            try { Run(Fltmc, "unload " + FilterName, 30000); } catch (Exception) { }
            Loaded = false;
        }

        /// <summary>
        /// Registra il minifilter senza finestre: copia il .sys in system32\drivers, crea il servizio
        /// del filtro con sc e scrive le chiavi dell'istanza (l'altitudine del filtro).
        /// </summary>
        void Register()
        {
            File.Copy(Sys, Path.Combine(DriversDir, "vigilflt.sys"), true);
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
            try { File.Delete(Path.Combine(DriversDir, "vigilflt.sys")); } catch (Exception) { }
        }

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
