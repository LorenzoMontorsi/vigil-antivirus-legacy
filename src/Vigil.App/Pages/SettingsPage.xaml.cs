using System;
using System.Diagnostics;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using Vigil.App.Services;
using Vigil.Engine;

namespace Vigil.App.Pages
{
    public partial class SettingsPage : UserControl, IPage
    {
        static readonly int[] Sizes = { 16, 32, 64, 128, 256 };
        static readonly int[] Intervals = { 1, 2, 4, 8, 12, 24 };
        bool loading;

        public SettingsPage()
        {
            InitializeComponent();
            foreach (var mb in Sizes)
            {
                var c = new RadioButton { Content = mb + " MB", Style = (Style)FindResource("Chip"), GroupName = "size", Tag = mb };
                c.Checked += (s, e) => { if (!loading) { S.MaxFileSizeMb = (int)((RadioButton)s).Tag; Save(); } };
                SizeChips.Children.Add(c);
            }
            foreach (var h in Intervals)
            {
                var c = new RadioButton { Content = h == 1 ? "1 ora" : h + " ore", Style = (Style)FindResource("Chip"), GroupName = "interval", Tag = h };
                c.Checked += (s, e) => { if (!loading) { S.UpdateIntervalHours = (int)((RadioButton)s).Tag; Save(); } };
                IntervalChips.Children.Add(c);
            }
            foreach (var y in new[] { new[] { "none", "Nessuna" }, new[] { "core", "Core" }, new[] { "extended", "Estesa" } })
            {
                var c = new RadioButton { Content = y[1], Style = (Style)FindResource("Chip"), GroupName = "yara", Tag = y[0] };
                c.Checked += (s, e) => { if (!loading) OnYara((string)((RadioButton)s).Tag); };
                YaraChips.Children.Add(c);
            }
        }

        static Settings S { get { return AppState.Current.Settings; } }

        public void Refresh()
        {
            loading = true;
            Heuristics.IsChecked = S.Heuristics;
            Archives.IsChecked = S.ScanArchives;
            TrustMs.IsChecked = S.TrustMicrosoft;
            UseCache.IsChecked = S.UseCache;
            AutoQuarantine.IsChecked = S.AutoQuarantine;
            Clamav.IsChecked = S.ClamavEnabled || AppState.Current.ServiceMode;
            Clamav.IsEnabled = !AppState.Current.ServiceMode;
            AutoUpdate.IsChecked = S.AutoUpdate;
            StartAtLogin.IsChecked = S.StartAtLogin;
            ShellMenu.IsChecked = S.ContextMenu;
            IntervalPanel.Visibility = S.AutoUpdate ? Visibility.Visible : Visibility.Collapsed;
            foreach (RadioButton c in SizeChips.Children)
                c.IsChecked = (int)c.Tag == S.MaxFileSizeMb;
            foreach (RadioButton c in IntervalChips.Children)
                c.IsChecked = (int)c.Tag == S.UpdateIntervalHours;
            foreach (RadioButton c in YaraChips.Children)
                c.IsChecked = (string)c.Tag == (S.YaraPackage ?? "none");
            loading = false;

            var clam = AppState.Current.Clamav;
            var bundled = clam.BundledVersion;
            ClamavInfo.Text = AppState.Current.ServiceMode
                ? "ClamAV è gestito dal servizio della protezione in tempo reale (firme per tutto il PC) · stato: " +
                  (clam.IsReady ? "pronto, " + DashboardPage.ShortClamVersion(clam.VersionText) : "in attesa del servizio")
                : !clam.IsInstalled
                ? "ClamAV non è presente accanto a Vigil (cartella «clamav»)."
                : "ClamAV " + bundled + " per Windows legacy (port di Gianluigi Tiesi, progetto ClamWin) · stato: " +
                  (clam.IsReady ? "pronto, " + DashboardPage.ShortClamVersion(clam.VersionText) : clam.Detail ?? "non attivo");

            AntiRansom.IsChecked = S.AntiRansomware;
            AntiRansom.IsEnabled = AppState.Current.ServiceMode;
            var rt = AppState.Current.Realtime.Status;
            RtInfo.Text = !AppState.Current.ServiceMode
                ? "Il servizio della protezione in tempo reale non è installato: lo scudo funziona solo con il servizio."
                : S.AntiRansomware
                ? "Attivo · " + (rt != null ? rt.Decoys : 0) + " file-esca disseminati nelle cartelle dei documenti."
                : "Disattivato.";

            SelfProtect.IsChecked = S.SelfProtection;
            SelfProtect.IsEnabled = AppState.Current.ServiceMode;
            SelfProtectInfo.Text = !AppState.Current.ServiceMode
                ? "Richiede il servizio."
                : rt != null && rt.SelfProtection
                ? "Attiva: i file di Vigil sono protetti dal driver."
                : S.SelfProtection
                ? "Non attiva (il driver si carica solo su Windows a 32 bit)."
                : "Disattivata.";

            var yara = AppState.Current.YaraStatus;
            YaraInfo.Text = (S.YaraPackage ?? "none") == "none"
                ? "Nessuna regola YARA caricata."
                : !S.ClamavEnabled && !AppState.Current.ServiceMode
                ? "Richiede ClamAV attivo."
                : "Stato: " + (yara ?? "in attesa del prossimo aggiornamento");

            if (!MbKey.IsKeyboardFocusWithin)
                MbKey.Text = S.MalwareBazaarKey ?? "";
            var mb = AppState.Current.MalwareBazaarStatus;
            MbInfo.Text = string.IsNullOrEmpty(S.MalwareBazaarKey) ? "Non attivo." : "Stato: " + (mb ?? "in attesa del primo aggiornamento");

            RenderExclusions();

            var mem = new Microsoft.VisualBasic.Devices.ComputerInfo();
            About.Text = "Vigil Legacy " + ScanEngine.Version + " · motore " + ScanEngine.Version + "\n" +
                         mem.OSFullName.Trim() + " · .NET " + Environment.Version + " · RAM " + (mem.TotalPhysicalMemory / (1024 * 1024)) + " MB\n" +
                         "Dati: " + AppPaths.DataDir + "\n" +
                         "Software libero (GPL-3.0-or-later). ClamAV è di Cisco Talos (GPL-2.0).";
        }

        void RenderExclusions()
        {
            ExclusionList.Children.Clear();
            var ex = S.Exclusions;
            if (ex.Paths.Count == 0 && ex.Extensions.Count == 0)
            {
                ExclusionList.Children.Add(new TextBlock { Text = "Nessuna esclusione.", Style = (Style)FindResource("Faint") });
                return;
            }
            foreach (var p in ex.Paths.ToList())
                ExclusionList.Children.Add(ExclusionRow(p, () => ex.Paths.Remove(p)));
            foreach (var e in ex.Extensions.ToList())
                ExclusionList.Children.Add(ExclusionRow("Estensione ." + e.TrimStart('.'), () => ex.Extensions.Remove(e)));
        }

        UIElement ExclusionRow(string text, Action remove)
        {
            var g = new Grid { Margin = new Thickness(0, 0, 0, 6) };
            g.ColumnDefinitions.Add(new ColumnDefinition());
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            var b = new Border { Background = (Brush)FindResource("Surface2"), CornerRadius = new CornerRadius(8), Padding = new Thickness(10, 6, 10, 6) };
            b.Child = new TextBlock { Text = text, TextTrimming = TextTrimming.CharacterEllipsis, ToolTip = text };
            g.Children.Add(b);
            var x = new Button { Content = "Rimuovi", Style = (Style)FindResource("Small"), Margin = new Thickness(8, 0, 0, 0) };
            x.Click += (s, e) => { remove(); SaveExclusions(); RenderExclusions(); };
            Grid.SetColumn(x, 1);
            g.Children.Add(x);
            return g;
        }

        void Save()
        {
            AppState.Current.SaveSettings();
        }

        /// <summary>Dopo una modifica alle esclusioni: le invia anche al servizio (consenso UAC se serve).</summary>
        void SaveExclusions()
        {
            Save();
            var st = AppState.Current;
            if (!st.ServiceMode)
                return;
            new System.Threading.Thread(() =>
            {
                var err = st.PushExclusionsToService();
                if (err != null)
                    Dispatcher.BeginInvoke(new Action(() => MessageBox.Show(
                        "Le esclusioni valgono per le scansioni, ma la protezione in tempo reale non le ha ricevute: " + err,
                        "Vigil Legacy", MessageBoxButton.OK, MessageBoxImage.Warning)));
            }) { IsBackground = true }.Start();
        }

        void OnToggle(object sender, RoutedEventArgs e)
        {
            S.Heuristics = Heuristics.IsChecked == true;
            S.ScanArchives = Archives.IsChecked == true;
            S.TrustMicrosoft = TrustMs.IsChecked == true;
            S.UseCache = UseCache.IsChecked == true;
            S.AutoQuarantine = AutoQuarantine.IsChecked == true;
            S.AutoUpdate = AutoUpdate.IsChecked == true;
            IntervalPanel.Visibility = S.AutoUpdate ? Visibility.Visible : Visibility.Collapsed;
            Save();
        }

        void OnWindows(object sender, RoutedEventArgs e)
        {
            S.StartAtLogin = StartAtLogin.IsChecked == true;
            S.ContextMenu = ShellMenu.IsChecked == true;
            ShellIntegration.ApplyAutostart(S.StartAtLogin);
            ShellIntegration.ApplyContextMenu(S.ContextMenu);
            Save();
        }

        void OnClamav(object sender, RoutedEventArgs e)
        {
            S.ClamavEnabled = Clamav.IsChecked == true;
            Save();
            var st = AppState.Current;
            new System.Threading.Thread(() =>
            {
                if (S.ClamavEnabled)
                {
                    st.Clamav.Start();
                    if (!st.Clamav.HasDatabase && st.Clamav.IsInstalled)
                        st.RunUpdate();
                }
                else
                {
                    st.Clamav.Stop();
                }
            }) { IsBackground = true }.Start();
        }

        void OnSelfProtect(object sender, RoutedEventArgs e)
        {
            bool on = SelfProtect.IsChecked == true;
            var st = AppState.Current;
            new System.Threading.Thread(() =>
            {
                var err = st.SetSelfProtection(on);
                Dispatcher.BeginInvoke(new Action(() =>
                {
                    if (err != null)
                        MessageBox.Show("Non applicato: " + err, "Vigil Legacy", MessageBoxButton.OK, MessageBoxImage.Warning);
                    Refresh();
                }));
            }) { IsBackground = true }.Start();
        }

        void OnYara(string package)
        {
            var st = AppState.Current;
            YaraInfo.Text = package == "none" ? "Rimozione delle regole YARA…" : "Scaricamento delle regole YARA (" + package + ")…";
            new System.Threading.Thread(() =>
            {
                var err = st.SetYaraPackage(package);
                if (err == null && !st.ServiceMode && st.Settings.ClamavEnabled)
                    st.RunUpdate();
                Dispatcher.BeginInvoke(new Action(() =>
                {
                    if (err != null)
                        MessageBox.Show("Non applicato: " + err, "Vigil Legacy", MessageBoxButton.OK, MessageBoxImage.Warning);
                    Refresh();
                }));
            }) { IsBackground = true }.Start();
        }

        void OnAntiRansom(object sender, RoutedEventArgs e)
        {
            bool on = AntiRansom.IsChecked == true;
            var st = AppState.Current;
            new System.Threading.Thread(() =>
            {
                var err = st.SetAntiRansomware(on);
                Dispatcher.BeginInvoke(new Action(() =>
                {
                    if (err != null)
                        MessageBox.Show("Non applicato: " + err, "Vigil Legacy", MessageBoxButton.OK, MessageBoxImage.Warning);
                    Refresh();
                }));
            }) { IsBackground = true }.Start();
        }

        void OnSaveMbKey(object sender, RoutedEventArgs e)
        {
            var key = MbKey.Text;
            var st = AppState.Current;
            new System.Threading.Thread(() =>
            {
                var err = st.SetMalwareBazaarKey(key);
                if (err == null && !st.ServiceMode && !string.IsNullOrEmpty(st.Settings.MalwareBazaarKey))
                    st.RunUpdate();
                Dispatcher.BeginInvoke(new Action(() =>
                {
                    if (err != null)
                        MessageBox.Show("Chiave non salvata: " + err, "Vigil Legacy", MessageBoxButton.OK, MessageBoxImage.Warning);
                    Refresh();
                }));
            }) { IsBackground = true }.Start();
        }

        void OnGetMbKey(object sender, RoutedEventArgs e)
        {
            try { Process.Start("https://auth.abuse.ch/"); } catch (Exception) { }
        }

        void OnClearCache(object sender, RoutedEventArgs e)
        {
            AppState.Current.ClearCache();
            MessageBox.Show("Cache svuotata: la prossima scansione analizzerà di nuovo tutti i file.", "Vigil Legacy", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        void OnAddFolder(object sender, RoutedEventArgs e)
        {
            using (var dlg = new System.Windows.Forms.FolderBrowserDialog { Description = "Cartella da escludere dalle scansioni" })
            {
                if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK)
                    AddPath(dlg.SelectedPath);
            }
        }

        void OnAddFile(object sender, RoutedEventArgs e)
        {
            var dlg = new Microsoft.Win32.OpenFileDialog { Title = "File da escludere dalle scansioni", CheckFileExists = true };
            if (dlg.ShowDialog() == true)
                AddPath(dlg.FileName);
        }

        void AddPath(string p)
        {
            if (!S.Exclusions.Paths.Any(x => string.Equals(x, p, StringComparison.OrdinalIgnoreCase)))
                S.Exclusions.Paths.Add(p);
            SaveExclusions();
            RenderExclusions();
        }

        void OnAddExt(object sender, RoutedEventArgs e)
        {
            var ext = (ExtBox.Text ?? "").Trim().TrimStart('.', '*');
            if (ext.Length == 0 || ext.IndexOfAny(new[] { '\\', '/', ' ' }) >= 0)
                return;
            if (!S.Exclusions.Extensions.Any(x => string.Equals(x.TrimStart('.'), ext, StringComparison.OrdinalIgnoreCase)))
                S.Exclusions.Extensions.Add(ext);
            ExtBox.Text = "";
            SaveExclusions();
            RenderExclusions();
        }

        void OnExtKey(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
                OnAddExt(sender, e);
        }

        void OnOpenData(object sender, RoutedEventArgs e)
        {
            try { Process.Start("explorer.exe", "\"" + AppPaths.DataDir + "\""); } catch (Exception) { }
        }
    }
}
