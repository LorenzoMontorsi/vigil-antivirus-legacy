using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using Vigil.App.Pages;
using Vigil.App.Services;
using Vigil.Engine;

namespace Vigil.App
{
    /// <summary>Le pagine si aggiornano quando cambia lo stato (eventi dai thread di lavoro, raccolti qui).</summary>
    public interface IPage
    {
        void Refresh();
    }

    public partial class MainWindow : Window
    {
        public static MainWindow Instance { get; private set; }

        readonly Dictionary<RadioButton, UserControl> pages = new Dictionary<RadioButton, UserControl>();
        bool refreshQueued;

        public DashboardPage Dashboard { get; private set; }
        public ScanPage Scan { get; private set; }
        public QuarantinePage QuarantineView { get; private set; }
        public SettingsPage SettingsView { get; private set; }

        public MainWindow()
        {
            Instance = this;
            InitializeComponent();
            VersionText.Text = "versione " + ScanEngine.Version + " · .NET " + Environment.Version.ToString(2);
            Dashboard = new DashboardPage();
            Scan = new ScanPage();
            QuarantineView = new QuarantinePage();
            SettingsView = new SettingsPage();
            pages[NavDashboard] = Dashboard;
            pages[NavScan] = Scan;
            pages[NavQuarantine] = QuarantineView;
            pages[NavSettings] = SettingsView;
            Host.Content = Dashboard;

            AppState.Current.Changed += QueueRefresh;
            Loaded += (s, e) => RefreshAll();
        }

        /// <summary>Raggruppa le notifiche: al massimo un aggiornamento dell'interfaccia alla volta.</summary>
        void QueueRefresh()
        {
            lock (pages)
            {
                if (refreshQueued) return;
                refreshQueued = true;
            }
            Dispatcher.BeginInvoke(DispatcherPriority.Background, new Action(() =>
            {
                lock (pages) refreshQueued = false;
                RefreshAll();
            }));
        }

        void RefreshAll()
        {
            int n = 0;
            try { n = AppState.Current.Quarantine.List().Count; } catch (Exception) { }
            var rt = AppState.Current.Realtime.Status;
            if (rt != null) n += rt.Quarantined;
            QuarantineBadge.Visibility = n > 0 ? Visibility.Visible : Visibility.Collapsed;
            QuarantineCount.Text = n.ToString();
            var page = Host.Content as IPage;
            if (page != null)
                page.Refresh();
        }

        void OnNav(object sender, RoutedEventArgs e)
        {
            var rb = sender as RadioButton;
            UserControl page;
            if (rb == null || Host == null || !pages.TryGetValue(rb, out page))
                return;
            Host.Content = page;
            Scroller.ScrollToTop();
            var p = page as IPage;
            if (p != null) p.Refresh();
        }

        public void ShowScan() { NavScan.IsChecked = true; }
        public void ShowQuarantine() { NavQuarantine.IsChecked = true; }
        public void ShowSettings() { NavSettings.IsChecked = true; }
    }
}
