using System;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Threading;
using System.Windows;
using System.Windows.Media;

namespace Vigil.Setup
{
    public partial class MainWindow : Window
    {
        enum Stage { Options, Working, Done }

        readonly bool uninstall;
        Stage stage = Stage.Options;
        bool succeeded;
        string installedDir;

        public MainWindow()
        {
            InitializeComponent();
            var args = Environment.GetCommandLineArgs().Skip(1).Select(a => a.ToLowerInvariant()).ToArray();
            uninstall = args.Contains("/uninstall");
            VersionLabel.Text = "versione " + Installer.Version;
            var existing = Installer.ExistingDir();
            DirBox.Text = existing ?? Installer.DefaultDir;

            if (!IsAdmin())
            {
                // XP con un utente limitato: il manifest non basta a chiedere i privilegi.
                MessageBox.Show("Per installare o rimuovere Vigil Legacy servono i privilegi di amministratore.\n\nSu Windows XP: tasto destro sul programma › Esegui come… e scegli un amministratore.",
                    Installer.Product, MessageBoxButton.OK, MessageBoxImage.Warning);
                Loaded += (s, e) => Close();
                return;
            }

            if (uninstall)
            {
                Title = "Disinstallazione di Vigil Legacy";
                OptionsPage.Visibility = Visibility.Collapsed;
                UninstallPage.Visibility = Visibility.Visible;
                UninstallText.Text = "Vigil Legacy verrà rimosso da " + (existing ?? AppDomain.CurrentDomain.BaseDirectory) +
                                     ", insieme al servizio della protezione in tempo reale e ai collegamenti.";
                NextButton.Content = "Disinstalla";
                NextButton.Style = (Style)FindResource("Danger");
            }
            else
            {
                if (existing != null)
                {
                    WelcomeTitle.Text = "Aggiorna Vigil Legacy";
                    NextButton.Content = "Aggiorna";
                }
                if (!Installer.HasPayload)
                {
                    MessageBox.Show("Questo programma di installazione non contiene i file di Vigil (va creato con scripts\\build-dist.ps1).", Installer.Product, MessageBoxButton.OK, MessageBoxImage.Error);
                    NextButton.IsEnabled = false;
                }
            }
        }

        static bool IsAdmin()
        {
            try { return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator); }
            catch (Exception) { return false; }
        }

        void OnBrowse(object sender, RoutedEventArgs e)
        {
            using (var dlg = new System.Windows.Forms.FolderBrowserDialog { Description = "Dove installare Vigil Legacy", SelectedPath = DirBox.Text })
            {
                if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK)
                    DirBox.Text = dlg.SelectedPath.EndsWith(Installer.Product, StringComparison.OrdinalIgnoreCase) ? dlg.SelectedPath : Path.Combine(dlg.SelectedPath, Installer.Product);
            }
        }

        void OnCancel(object sender, RoutedEventArgs e)
        {
            Close();
        }

        void OnNext(object sender, RoutedEventArgs e)
        {
            if (stage == Stage.Done)
            {
                if (succeeded && !uninstall && LaunchBox.IsChecked == true)
                    Installer.LaunchAsUser(Path.Combine(installedDir, "VigilLegacy.exe"));
                Close();
                return;
            }
            var dir = uninstall ? (Installer.ExistingDir() ?? AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\')) : DirBox.Text.Trim();
            if (!uninstall && (dir.Length < 4 || !Path.IsPathRooted(dir)))
            {
                MessageBox.Show("Scegli una cartella di installazione valida.", Installer.Product, MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
            installedDir = dir;
            bool service = ServiceBox.IsChecked == true, desktop = DesktopBox.IsChecked == true, removeData = RemoveDataBox.IsChecked == true;

            stage = Stage.Working;
            OptionsPage.Visibility = UninstallPage.Visibility = Visibility.Collapsed;
            ProgressPage.Visibility = Visibility.Visible;
            ProgressTitle.Text = uninstall ? "Disinstallazione in corso…" : "Installazione in corso…";
            NextButton.IsEnabled = CancelButton.IsEnabled = false;

            Action<string, double> progress = (text, fraction) => Dispatcher.BeginInvoke(new Action(() =>
            {
                ProgressText.Text = text;
                Bar.Width = Math.Max(0, ((FrameworkElement)Bar.Parent).ActualWidth * fraction);
            }));

            new Thread(() =>
            {
                string error = null;
                try
                {
                    if (uninstall) Installer.Uninstall(dir, removeData, progress);
                    else Installer.Install(dir, service, desktop, progress);
                }
                catch (Exception ex)
                {
                    error = ex.Message;
                }
                Dispatcher.BeginInvoke(new Action(() => Finish(error, service)));
            }) { IsBackground = true }.Start();
        }

        void Finish(string error, bool service)
        {
            stage = Stage.Done;
            succeeded = error == null;
            ProgressPage.Visibility = Visibility.Collapsed;
            DonePage.Visibility = Visibility.Visible;
            NextButton.IsEnabled = true;
            NextButton.Content = "Fine";
            NextButton.Style = (Style)FindResource("Primary");
            CancelButton.Visibility = Visibility.Collapsed;
            LaunchBox.Visibility = succeeded && !uninstall ? Visibility.Visible : Visibility.Collapsed;
            if (!succeeded)
            {
                DoneIcon.Data = (Geometry)FindResource("IconAlert");
                DoneIcon.Stroke = (Brush)FindResource("GradDanger");
                DoneTitle.Text = uninstall ? "Disinstallazione non riuscita" : "Installazione non riuscita";
                DoneText.Text = error;
                return;
            }
            if (uninstall)
            {
                DoneTitle.Text = "Vigil Legacy è stato rimosso";
                DoneText.Text = "Alcuni file in uso verranno eliminati al prossimo riavvio.";
            }
            else
            {
                DoneTitle.Text = "Vigil Legacy è installato";
                DoneText.Text = service
                    ? "La protezione in tempo reale è attiva. Al primo avvio vengono scaricate le firme di ClamAV (circa 300 MB): su una connessione lenta ci vuole un po'."
                    : "Puoi avviare le scansioni quando vuoi. La protezione in tempo reale si può aggiungere ripetendo l'installazione.";
            }
        }
    }
}
