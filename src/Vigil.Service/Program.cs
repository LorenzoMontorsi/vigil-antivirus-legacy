using System;
using System.Diagnostics;
using System.IO;
using System.ServiceProcess;
using System.Threading;

namespace Vigil.Service
{
    /// <summary>
    /// VigilLegacySvc.exe
    ///   (nessun argomento)  avviato da Gestione servizi
    ///   --install           registra e avvia il servizio (amministratore)
    ///   --uninstall         ferma e rimuove il servizio (amministratore)
    ///   --console           esegue la protezione in primo piano (sviluppo)
    /// </summary>
    static class Program
    {
        public const string ServiceName = "VigilLegacy";

        static int Main(string[] args)
        {
            var cmd = args.Length > 0 ? args[0].ToLowerInvariant() : "";
            switch (cmd)
            {
                case "--install":
                    return Install();
                case "--uninstall":
                    return Uninstall();
                case "--trust-cert":
                    return TrustCert(args.Length > 1 ? args[1] : null);
                case "--console":
                    var core = new ProtectionCore();
                    core.Start();
                    Console.WriteLine("Vigil Legacy: protezione attiva in console. Invio per uscire.");
                    core.Log += Console.WriteLine;
                    Console.ReadLine();
                    core.Stop();
                    return 0;
                default:
                    ServiceBase.Run(new VigilService());
                    return 0;
            }
        }

        /// <summary>
        /// Rende fidato il certificato di prova del driver a 64 bit (Trusted Root + Trusted Publishers
        /// del computer), così il minifilter firmato si carica quando il sistema è in test-signing.
        /// Usa l'archivio certificati .NET per non dipendere da certutil (assente su alcuni XP).
        /// </summary>
        static int TrustCert(string path)
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path))
            {
                Console.WriteLine("Certificato non trovato: " + path);
                return 1;
            }
            try
            {
                var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(path);
                foreach (var name in new[]
                {
                    System.Security.Cryptography.X509Certificates.StoreName.Root,
                    System.Security.Cryptography.X509Certificates.StoreName.TrustedPublisher,
                })
                {
                    var store = new System.Security.Cryptography.X509Certificates.X509Store(
                        name, System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine);
                    store.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadWrite);
                    store.Add(cert);
                    store.Close();
                }
                Console.WriteLine("Certificato di prova reso fidato.");
                return 0;
            }
            catch (Exception e)
            {
                Console.WriteLine("Impossibile fidarsi del certificato: " + e.Message);
                return 1;
            }
        }

        // sc.exe c'è da Windows XP: niente ServiceInstaller/InstallUtil.
        static int Install()
        {
            var exe = Process.GetCurrentProcess().MainModule.FileName;
            Sc("stop " + ServiceName);
            Sc("delete " + ServiceName);
            Thread.Sleep(1000);
            int r = Sc("create " + ServiceName + " binPath= \"\\\"" + exe + "\\\"\" start= auto DisplayName= \"Vigil Legacy - protezione in tempo reale\"");
            if (r != 0)
                return r;
            Sc("description " + ServiceName + " \"Analizza i file nuovi o modificati e i programmi avviati (Vigil Legacy).\"");
            // Se si chiude per errore, Windows lo riavvia.
            Sc("failure " + ServiceName + " reset= 86400 actions= restart/5000/restart/5000/restart/60000");
            return Sc("start " + ServiceName);
        }

        static int Uninstall()
        {
            Sc("stop " + ServiceName);
            Thread.Sleep(1500);
            return Sc("delete " + ServiceName);
        }

        static int Sc(string args)
        {
            var psi = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "sc.exe"), args)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
            };
            using (var p = Process.Start(psi))
            {
                Console.Write(p.StandardOutput.ReadToEnd());
                p.WaitForExit();
                return p.ExitCode;
            }
        }
    }

    sealed class VigilService : ServiceBase
    {
        ProtectionCore core;

        public VigilService()
        {
            ServiceName = Program.ServiceName;
            CanStop = true;
            CanShutdown = true;
            AutoLog = true;
        }

        protected override void OnStart(string[] args)
        {
            core = new ProtectionCore();
            // L'avvio di ClamAV può durare minuti: tutto in background, così Gestione servizi non va in timeout.
            new Thread(core.Start) { IsBackground = true, Name = "Vigil avvio" }.Start();
        }

        protected override void OnStop()
        {
            if (core != null) core.Stop();
        }

        protected override void OnShutdown()
        {
            OnStop();
        }
    }
}
