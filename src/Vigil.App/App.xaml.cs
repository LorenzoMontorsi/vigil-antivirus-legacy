using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Threading;
using Vigil.App.Services;
using Vigil.Engine;

namespace Vigil.App
{
    public partial class App : Application
    {
        SingleInstance instance;
        Tray tray;
        bool exiting;
        bool hintShown;

        public static new App Current { get { return (App)Application.Current; } }
        public Tray Tray { get { return tray; } }

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);
            DispatcherUnhandledException += OnUnhandled;
            ShutdownMode = ShutdownMode.OnExplicitShutdown;

            // Aiutante elevato (consenso UAC): esegue un comando per il servizio ed esce.
            if (e.Args.Length == 2 && e.Args[0] == "--rt")
            {
                Shutdown(Realtime.RunHelper(e.Args[1]));
                return;
            }

            instance = new SingleInstance("VigilLegacy");
            if (!instance.IsFirst)
            {
                // Già aperto: gli passiamo la riga di comando (o la richiesta di mostrarsi) e usciamo.
                instance.Forward(e.Args.Length > 0 ? e.Args : new[] { "--show" });
                Shutdown();
                return;
            }
            instance.ArgsReceived += args => Dispatcher.BeginInvoke(new Action(() => HandleArgs(args)));

            var st = AppState.Init();
            ShellIntegration.ApplyContextMenu(st.Settings.ContextMenu);
            ShellIntegration.ApplyAutostart(st.Settings.StartAtLogin);

            var w = new MainWindow();
            MainWindow = w;
            w.Closing += OnMainClosing;

            tray = new Tray();
            tray.OpenRequested += ShowMain;
            tray.QuickScanRequested += () => { ShowMain(); w.Scan.StartScan("quick", AppState.QuickScanRoots()); w.ShowScan(); };
            tray.UpdateRequested += () => st.RunUpdateAsync();
            tray.ExitRequested += ExitApp;
            tray.PauseRequested += m => RtCommand(new Vigil.Engine.RtRequest { Cmd = "pause", Minutes = m });
            tray.ResumeRequested += () => RtCommand(Vigil.Engine.RtRequest.Of("resume"));
            st.Realtime.EventReceived += ev => Dispatcher.BeginInvoke(new Action(() => OnRealtimeEvent(ev)));
            st.Changed += () => Dispatcher.BeginInvoke(new Action(UpdateTray));
            UpdateTray();

            // --hidden: avvio automatico all'accesso, solo icona nell'area di notifica.
            if (!e.Args.Contains("--hidden"))
                w.Show();
            st.StartBackground();
            HandleArgs(e.Args);
        }

        void HandleArgs(IList<string> args)
        {
            var paths = ShellIntegration.ScanArgs(args);
            if (paths.Count > 0)
            {
                ShellIntegration.Queue(paths, batch => Dispatcher.BeginInvoke(new Action(() => StartShellScan(batch))));
                return;
            }
            if (args.Contains("--show"))
                ShowMain();
        }

        /// <summary>"Analizza con Vigil" dal menu del tasto destro: scansione personalizzata dei percorsi scelti.</summary>
        void StartShellScan(List<string> paths)
        {
            var w = (MainWindow)MainWindow;
            ShowMain();
            w.ShowScan();
            if (w.Scan.IsRunning)
            {
                ToastWindow.Show("C'è già una scansione in corso", "Attendi che finisca, poi riprova con «Analizza con Vigil».", false, 6);
                return;
            }
            w.Scan.StartScan("custom", paths);
        }

        public void ShowMain()
        {
            var w = MainWindow;
            if (w == null) return;
            if (!w.IsVisible) w.Show();
            if (w.WindowState == WindowState.Minimized) w.WindowState = WindowState.Normal;
            w.Activate();
            // Su XP Activate non basta sempre a portarla davanti.
            w.Topmost = true;
            w.Topmost = false;
        }

        void OnMainClosing(object sender, CancelEventArgs e)
        {
            if (exiting) return;
            // La X nasconde soltanto: Vigil resta attivo nell'area di notifica.
            e.Cancel = true;
            MainWindow.Hide();
            if (!hintShown)
            {
                hintShown = true;
                tray.Balloon("Vigil è ancora attivo", "Continua a lavorare nell'area di notifica. Per chiuderlo davvero: tasto destro sull'icona › Esci.", false);
            }
        }

        public void ExitApp()
        {
            var w = (MainWindow)MainWindow;
            if (w != null && w.Scan.IsRunning &&
                MessageBox.Show("C'è una scansione in corso. Uscire comunque?", "Vigil Legacy", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
                return;
            exiting = true;
            if (w != null) w.Close();
            Shutdown();
        }

        /// <summary>Comando al servizio in background (può comparire il consenso UAC).</summary>
        void RtCommand(Vigil.Engine.RtRequest req)
        {
            new System.Threading.Thread(() =>
            {
                var err = Realtime.Command(req);
                if (err != null)
                    Dispatcher.BeginInvoke(new Action(() => ToastWindow.Show("Operazione non riuscita", err, false, 8)));
            }) { IsBackground = true }.Start();
        }

        /// <summary>Avvisi per ciò che ha fatto la protezione in tempo reale.</summary>
        void OnRealtimeEvent(Vigil.Engine.RtEvent ev)
        {
            Action openQuarantine = () => { ShowMain(); ((MainWindow)MainWindow).ShowQuarantine(); };
            var name = string.IsNullOrEmpty(ev.Path) ? "" : Path.GetFileName(ev.Path);
            var kind = ev.Threat != null ? ThreatInfo.Parse(ev.Threat).Description + Environment.NewLine : "";
            switch (ev.Action)
            {
                case "quarantined":
                    ToastWindow.Show("Minaccia bloccata: " + ev.Threat, kind + name + " è stato messo in quarantena." + Environment.NewLine + ev.Path, true, 12,
                        Tuple.Create("Apri la quarantena", openQuarantine), Tuple.Create<string, Action>("OK", null));
                    break;
                case "killed":
                    ToastWindow.Show("Programma pericoloso fermato", kind + ev.Threat + ": " + name + ". " + ev.Detail + ".", true, 12,
                        Tuple.Create("Apri la quarantena", openQuarantine), Tuple.Create<string, Action>("OK", null));
                    break;
                case "failed":
                    if (ev.Threat != null)
                        ToastWindow.Show("Minaccia trovata: " + ev.Threat, ev.Path + Environment.NewLine + ev.Detail, true, 0,
                            Tuple.Create<string, Action>("Analizza il file", () => { ShowMain(); ((MainWindow)MainWindow).Scan.StartScan("custom", new[] { ev.Path }); ((MainWindow)MainWindow).ShowScan(); }),
                            Tuple.Create<string, Action>("Ignora", null));
                    break;
                case "ransom":
                    ToastWindow.Show("Possibile ransomware!", ev.Detail, true, 0,
                        Tuple.Create("Apri la quarantena", openQuarantine), Tuple.Create<string, Action>("Ho capito", null));
                    break;
                case "suspicious":
                    ToastWindow.Show("File sospetto", name + ": " + ev.Detail, false, 10,
                        Tuple.Create<string, Action>("Analizza", () => { ShowMain(); ((MainWindow)MainWindow).Scan.StartScan("custom", new[] { ev.Path }); ((MainWindow)MainWindow).ShowScan(); }),
                        Tuple.Create<string, Action>("Ignora", null));
                    break;
            }
        }

        void UpdateTray()
        {
            var st = AppState.Current;
            var rt = st.Realtime.Status;
            tray.SetRealtime(rt != null, rt != null && rt.Paused);
            string text;
            if (rt != null && rt.Paused) text = "protezione sospesa";
            else if (st.IsUpdating) text = "aggiornamento in corso";
            else if (st.Settings.ClamavEnabled && st.Clamav.Status == ClamavStatus.Starting) text = "avvio di ClamAV";
            else if (st.Settings.ClamavEnabled && !st.Clamav.IsReady) text = "protezione parziale";
            else text = "attivo";
            tray.SetStatus(text, st.IsUpdating);
        }

        protected override void OnExit(ExitEventArgs e)
        {
            if (tray != null) tray.Dispose();
            if (AppState.Current != null) AppState.Current.Shutdown();
            if (instance != null) instance.Dispose();
            base.OnExit(e);
        }

        void OnUnhandled(object sender, DispatcherUnhandledExceptionEventArgs e)
        {
            // Meglio un errore leggibile (e un file di log) che una chiusura improvvisa.
            try
            {
                Directory.CreateDirectory(AppPaths.LogDir);
                File.AppendAllText(Path.Combine(AppPaths.LogDir, "errors.log"), DateTime.Now + "  " + e.Exception + Environment.NewLine);
            }
            catch (Exception) { }
            MessageBox.Show(e.Exception.Message, "Vigil Legacy: errore imprevisto", MessageBoxButton.OK, MessageBoxImage.Error);
            e.Handled = true;
        }
    }
}
