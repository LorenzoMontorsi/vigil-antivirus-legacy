using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading;
using Microsoft.Win32;
using Vigil.Engine;

namespace Vigil.Setup
{
    /// <summary>Le operazioni vere e proprie di installazione e disinstallazione (senza interfaccia).</summary>
    static class Installer
    {
        public const string Product = "Vigil Legacy";
        public const string Version = "0.1.0";
        const string UninstallKey = @"Software\Microsoft\Windows\CurrentVersion\Uninstall\VigilLegacy";
        const string ServiceName = "VigilLegacy";

        public static string DefaultDir
        {
            // Processo a 32 bit: su Windows a 64 bit è "Program Files (x86)", come deve essere.
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Product); }
        }

        /// <summary>Cartella di un'installazione esistente, se c'è.</summary>
        public static string ExistingDir()
        {
            using (var k = Registry.LocalMachine.OpenSubKey(UninstallKey))
                return k != null ? k.GetValue("InstallLocation") as string : null;
        }

        public static bool HasPayload
        {
            get { return Assembly.GetExecutingAssembly().GetManifestResourceNames().Contains("payload.zip"); }
        }

        public static void Install(string dir, bool service, bool desktopShortcut, Action<string, double> progress)
        {
            progress("Chiusura di Vigil, se è aperto…", 0.02);
            StopEverything(dir);

            progress("Copia dei file…", 0.05);
            byte[] zip;
            using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("payload.zip"))
            {
                zip = new byte[s.Length];
                int off = 0, r;
                while (off < zip.Length && (r = s.Read(zip, off, zip.Length - off)) > 0)
                    off += r;
            }
            var archive = ZipReader.Open(zip, 100000);
            if (archive == null)
                throw new InvalidDataException("il pacchetto di installazione è danneggiato");
            var files = archive.Entries.Where(e => !e.IsDirectory).ToList();
            Directory.CreateDirectory(dir);
            for (int i = 0; i < files.Count; i++)
            {
                var e = files[i];
                var rel = e.Name.Replace('/', '\\');
                if (rel.Contains("..") || Path.IsPathRooted(rel))
                    throw new InvalidDataException("percorso non valido nel pacchetto: " + e.Name);
                var data = archive.Extract(e, 512L * 1024 * 1024);
                if (data == null)
                    throw new InvalidDataException("impossibile estrarre " + e.Name);
                var dest = Path.Combine(dir, rel);
                Directory.CreateDirectory(Path.GetDirectoryName(dest));
                WriteWithRetry(dest, data);
                progress("Copia dei file… " + rel, 0.05 + 0.6 * (i + 1) / files.Count);
            }

            // Il setup resta nella cartella: serve per la disinstallazione.
            var self = Assembly.GetExecutingAssembly().Location;
            var uninstaller = Path.Combine(dir, "VigilLegacySetup.exe");
            if (!string.Equals(self, uninstaller, StringComparison.OrdinalIgnoreCase))
                File.Copy(self, uninstaller, true);

            progress("Registrazione in «Programmi e funzionalità»…", 0.7);
            using (var k = Registry.LocalMachine.CreateSubKey(UninstallKey))
            {
                k.SetValue("DisplayName", Product);
                k.SetValue("DisplayVersion", Version);
                k.SetValue("Publisher", "Vigil Legacy contributors");
                k.SetValue("DisplayIcon", Path.Combine(dir, "VigilLegacy.exe") + ",0");
                k.SetValue("InstallLocation", dir);
                k.SetValue("UninstallString", "\"" + uninstaller + "\" /uninstall");
                k.SetValue("URLInfoAbout", "https://github.com/LorenzoMontorsi/vigil-antivirus-legacy");
                k.SetValue("NoModify", 1, RegistryValueKind.DWord);
                k.SetValue("NoRepair", 1, RegistryValueKind.DWord);
                k.SetValue("EstimatedSize", (int)(DirSize(dir) / 1024), RegistryValueKind.DWord);
            }

            progress("Collegamenti nel menu Start…", 0.75);
            var exe = Path.Combine(dir, "VigilLegacy.exe");
            var startDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms), Product);
            Directory.CreateDirectory(startDir);
            Shortcut(Path.Combine(startDir, Product + ".lnk"), exe, "", "Antivirus open source per Windows XP e successivi");
            Shortcut(Path.Combine(startDir, "Disinstalla " + Product + ".lnk"), uninstaller, "/uninstall", "Rimuove Vigil Legacy");
            var desktop = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory), Product + ".lnk");
            if (desktopShortcut)
                Shortcut(desktop, exe, "", "Vigil Legacy");
            else if (File.Exists(desktop))
                File.Delete(desktop);

            if (service)
            {
                progress("Avvio della protezione in tempo reale…", 0.85);
                int code = Run(Path.Combine(dir, "VigilLegacySvc.exe"), "--install");
                if (code != 0)
                    throw new Exception("impossibile installare il servizio (codice " + code + ")");
            }
            else
            {
                RemoveService(dir);
            }
            progress("Fatto", 1);
        }

        public static void Uninstall(string dir, bool removeData, Action<string, double> progress)
        {
            progress("Chiusura di Vigil…", 0.05);
            StopEverything(dir);
            progress("Rimozione del servizio…", 0.2);
            RemoveService(dir);

            progress("Rimozione dei collegamenti…", 0.4);
            TryDelete(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory), Product + ".lnk"));
            try { Directory.Delete(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms), Product), true); } catch (Exception) { }

            // Voci per l'utente corrente (menu del tasto destro e avvio automatico).
            try
            {
                foreach (var t in new[] { "*", "Directory", "Drive" })
                    Registry.CurrentUser.DeleteSubKeyTree(@"Software\Classes\" + t + @"\shell\VigilLegacyScan", false);
                using (var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true))
                    if (k != null && k.GetValue("VigilLegacy") != null) k.DeleteValue("VigilLegacy");
            }
            catch (Exception) { }

            progress("Rimozione dei file…", 0.6);
            try { Registry.LocalMachine.DeleteSubKeyTree(UninstallKey, false); } catch (Exception) { }
            foreach (var f in Directory.Exists(dir) ? Directory.GetFiles(dir, "*", SearchOption.AllDirectories) : new string[0])
            {
                // Il setup stesso è in uso: verrà rimosso al riavvio.
                if (!TryDelete(f))
                    MoveFileEx(f, null, MOVEFILE_DELAY_UNTIL_REBOOT);
            }
            try { Directory.Delete(dir, true); } catch (Exception) { MoveFileEx(dir, null, MOVEFILE_DELAY_UNTIL_REBOOT); }
            // Il setup in esecuzione non può cancellarsi: lo fa cmd.exe qualche secondo dopo la sua chiusura
            // (se non ci riesce, resta la cancellazione al riavvio prenotata qui sopra).
            var self = Assembly.GetExecutingAssembly().Location;
            if (self.StartsWith(dir, StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "cmd.exe"),
                        "/c ping 127.0.0.1 -n 4 >nul & del /f /q \"" + self + "\" & rmdir \"" + dir + "\"")
                    { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = Path.GetTempPath() });
                }
                catch (Exception) { }
            }

            if (removeData)
            {
                progress("Rimozione di firme, quarantena e impostazioni…", 0.85);
                try { Directory.Delete(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "VigilLegacy"), true); } catch (Exception) { }
                try { Directory.Delete(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "VigilLegacy"), true); } catch (Exception) { }
            }
            progress("Fatto", 1);
        }

        /// <summary>Chiude l'app e ferma il servizio: tengono aperti i file da sostituire.</summary>
        static void StopEverything(string dir)
        {
            foreach (var name in new[] { "VigilLegacy" })
            {
                foreach (var p in Process.GetProcessesByName(name))
                {
                    try { p.Kill(); p.WaitForExit(5000); } catch (Exception) { }
                }
            }
            if (ServiceExists())
            {
                Run(Path.Combine(Environment.SystemDirectory, "sc.exe"), "stop " + ServiceName);
                for (int i = 0; i < 30 && ServiceRunning(); i++)
                    Thread.Sleep(500);
            }
            // clamd del servizio o dell'app, se è rimasto in giro.
            foreach (var p in Process.GetProcessesByName("clamd"))
            {
                try
                {
                    if (p.MainModule.FileName.StartsWith(dir, StringComparison.OrdinalIgnoreCase)) { p.Kill(); p.WaitForExit(5000); }
                }
                catch (Exception) { }
            }
            // Scarica il minifilter di autodifesa: altrimenti la cartella del programma resta protetta
            // e i file non si possono rimuovere.
            try { Run(Path.Combine(Environment.SystemDirectory, "fltmc.exe"), "unload vigilflt"); } catch (Exception) { }
        }

        static void RemoveService(string dir)
        {
            // Rimuove anche il driver di autodifesa (servizio del filtro + file in system32\drivers).
            try
            {
                Run(Path.Combine(Environment.SystemDirectory, "fltmc.exe"), "unload vigilflt");
                Run(Path.Combine(Environment.SystemDirectory, "sc.exe"), "delete vigilflt");
                TryDelete(Path.Combine(Environment.SystemDirectory, "drivers", "vigilflt.sys"));
            }
            catch (Exception) { }

            if (!ServiceExists())
                return;
            var svc = Path.Combine(dir, "VigilLegacySvc.exe");
            if (File.Exists(svc))
                Run(svc, "--uninstall");
            else
                Run(Path.Combine(Environment.SystemDirectory, "sc.exe"), "delete " + ServiceName);
        }

        static bool ServiceExists()
        {
            return System.ServiceProcess.ServiceController.GetServices().Any(s => s.ServiceName == ServiceName);
        }

        static bool ServiceRunning()
        {
            var s = System.ServiceProcess.ServiceController.GetServices().FirstOrDefault(x => x.ServiceName == ServiceName);
            return s != null && s.Status != System.ServiceProcess.ServiceControllerStatus.Stopped;
        }

        static void WriteWithRetry(string path, byte[] data)
        {
            for (int attempt = 0; ; attempt++)
            {
                try
                {
                    if (File.Exists(path))
                        File.SetAttributes(path, FileAttributes.Normal);
                    File.WriteAllBytes(path, data);
                    return;
                }
                catch (IOException) when (attempt < 20)
                {
                    Thread.Sleep(500); // file ancora in uso da un processo che sta terminando
                }
            }
        }

        public static int Run(string exe, string args)
        {
            var psi = new ProcessStartInfo(exe, args) { UseShellExecute = false, CreateNoWindow = true };
            using (var p = Process.Start(psi))
            {
                p.WaitForExit(120000);
                return p.HasExited ? p.ExitCode : -1;
            }
        }

        /// <summary>Collegamento .lnk con WScript.Shell (presente da Windows 98).</summary>
        static void Shortcut(string lnk, string target, string args, string description)
        {
            var type = Type.GetTypeFromProgID("WScript.Shell");
            dynamic shell = Activator.CreateInstance(type);
            dynamic sc = shell.CreateShortcut(lnk);
            sc.TargetPath = target;
            sc.Arguments = args;
            sc.WorkingDirectory = Path.GetDirectoryName(target);
            sc.Description = description;
            sc.IconLocation = target + ",0";
            sc.Save();
        }

        static long DirSize(string dir)
        {
            return new DirectoryInfo(dir).GetFiles("*", SearchOption.AllDirectories).Sum(f => f.Length);
        }

        static bool TryDelete(string path)
        {
            try
            {
                if (!File.Exists(path)) return true;
                File.SetAttributes(path, FileAttributes.Normal);
                File.Delete(path);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// Avvia l'app come utente normale. Il setup gira da amministratore: con Process.Start
        /// anche l'app partirebbe elevata; passare da Esplora risorse la avvia con i diritti dell'utente.
        /// </summary>
        public static void LaunchAsUser(string exe)
        {
            try
            {
                if (Environment.OSVersion.Version.Major >= 6)
                    Process.Start(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"), "\"" + exe + "\"");
                else
                    Process.Start(exe); // XP: niente UAC
            }
            catch (Exception) { }
        }

        const int MOVEFILE_DELAY_UNTIL_REBOOT = 4;

        [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        static extern bool MoveFileEx(string existing, string replacement, int flags);
    }
}
