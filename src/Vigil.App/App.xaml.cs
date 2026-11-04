using System;
using System.IO;
using System.Threading;
using System.Windows;
using System.Windows.Threading;
using Vigil.App.Services;

namespace Vigil.App
{
    public partial class App : Application
    {
        Mutex single;

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);
            DispatcherUnhandledException += OnUnhandled;

            bool created;
            single = new Mutex(true, @"Local\VigilLegacy.App", out created);
            if (!created)
            {
                // Già aperto: per ora si limita a non aprirne un secondo.
                Shutdown();
                return;
            }

            AppState.Init();
            var w = new MainWindow();
            MainWindow = w;
            w.Show();
            AppState.Current.StartBackground();
        }

        protected override void OnExit(ExitEventArgs e)
        {
            if (AppState.Current != null)
                AppState.Current.Shutdown();
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
