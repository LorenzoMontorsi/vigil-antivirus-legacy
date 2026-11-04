using System;
using System.IO;
using System.Linq;
using System.Windows;

namespace Vigil.Setup
{
    public partial class App : Application
    {
        /// <summary>
        /// VigilLegacySetup.exe                 installazione guidata
        /// VigilLegacySetup.exe /silent         installazione senza finestre (opzioni predefinite)
        /// VigilLegacySetup.exe /uninstall      disinstallazione guidata
        /// VigilLegacySetup.exe /uninstall /silent
        /// Codice di uscita: 0 riuscito, 1 errore.
        /// </summary>
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);
            var args = e.Args.Select(a => a.ToLowerInvariant()).ToArray();
            if (args.Contains("/silent"))
            {
                int code = 0;
                try
                {
                    Action<string, double> quiet = (t, f) => { };
                    if (args.Contains("/uninstall"))
                        Installer.Uninstall(Installer.ExistingDir() ?? AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\'), args.Contains("/removedata"), quiet);
                    else
                    {
                        var dir = Installer.ExistingDir() ?? Installer.DefaultDir;
                        bool service = !args.Contains("/noservice");
                        Installer.Install(dir, service, true, quiet);
                        // Sui 64 bit, attiva l'autodifesa del driver (certificato + test-signing); riavvia solo con /reboot.
                        if (service && Installer.DriverNeeds64BitEnable(dir))
                        {
                            Installer.EnableDriver64(dir);
                            if (args.Contains("/reboot"))
                                Installer.ScheduleReboot(5);
                        }
                    }
                }
                catch (Exception ex)
                {
                    code = 1;
                    try { File.WriteAllText(Path.Combine(Path.GetTempPath(), "VigilLegacySetup.log"), ex.ToString()); } catch (Exception) { }
                }
                Shutdown(code);
                return;
            }
            new MainWindow().Show();
        }
    }
}
