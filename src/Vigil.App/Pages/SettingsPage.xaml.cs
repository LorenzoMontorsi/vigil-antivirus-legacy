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
            Clamav.IsChecked = S.ClamavEnabled;
            AutoUpdate.IsChecked = S.AutoUpdate;
            IntervalPanel.Visibility = S.AutoUpdate ? Visibility.Visible : Visibility.Collapsed;
            foreach (RadioButton c in SizeChips.Children)
                c.IsChecked = (int)c.Tag == S.MaxFileSizeMb;
            foreach (RadioButton c in IntervalChips.Children)
                c.IsChecked = (int)c.Tag == S.UpdateIntervalHours;
            loading = false;

            var clam = AppState.Current.Clamav;
            var bundled = ClamavManager.BundledVersion;
            ClamavInfo.Text = !ClamavManager.IsInstalled
                ? "ClamAV non è presente accanto a Vigil (cartella «clamav»)."
                : "ClamAV " + bundled + " per Windows legacy (port di Gianluigi Tiesi, progetto ClamWin) · stato: " +
                  (clam.IsReady ? "pronto, " + DashboardPage.ShortClamVersion(clam.VersionText) : clam.Detail ?? "non attivo");

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
            x.Click += (s, e) => { remove(); Save(); RenderExclusions(); };
            Grid.SetColumn(x, 1);
            g.Children.Add(x);
            return g;
        }

        void Save()
        {
            AppState.Current.SaveSettings();
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
                    if (!ClamavManager.HasDatabase && ClamavManager.IsInstalled)
                        st.RunUpdate();
                }
                else
                {
                    st.Clamav.Stop();
                }
            }) { IsBackground = true }.Start();
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
            Save();
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
            Save();
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
