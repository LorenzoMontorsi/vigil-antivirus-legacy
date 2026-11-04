using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;
using Vigil.App.Services;
using Vigil.Engine;

namespace Vigil.App.Pages
{
    public partial class DashboardPage : UserControl, IPage
    {
        readonly List<string> log = new List<string>();

        public DashboardPage()
        {
            InitializeComponent();
            AppState.Current.UpdateLog += line => Dispatcher.BeginInvoke(new Action(() => AddLog(line)));
        }

        void AddLog(string line)
        {
            log.Add(DateTime.Now.ToString("HH:mm:ss") + "  " + line);
            if (log.Count > 8)
                log.RemoveAt(0);
            LogText.Text = string.Join(Environment.NewLine, log.ToArray());
            LogBox.Visibility = Visibility.Visible;
        }

        enum Mood { Ok, Warn, Danger }

        public void Refresh()
        {
            var st = AppState.Current;
            var p = st.Persisted;
            var clam = st.Clamav;
            int quarantined = 0;
            try { quarantined = st.Quarantine.List().Count; } catch (Exception) { }

            // Stato generale
            Mood mood;
            string title, text;
            bool clamOk = !st.Settings.ClamavEnabled || clam.IsReady;
            long scanAgeDays = p.LastScanUnix == 0 ? long.MaxValue : (FileUtil.NowUnix() - p.LastScanUnix) / 86400;
            if (p.LastScanUnix != 0 && p.LastScanThreats > 0)
            {
                mood = Mood.Danger;
                title = "Ci sono minacce da gestire";
                text = "L'ultima scansione ha trovato " + p.LastScanThreats + " elementi pericolosi o sospetti. Apri la pagina Scansione per decidere cosa farne.";
            }
            else if (st.Settings.ClamavEnabled && (clam.Status == ClamavStatus.Starting))
            {
                mood = Mood.Warn;
                title = "Avvio dei motori in corso";
                text = "ClamAV sta caricando le firme: su un PC datato può volerci qualche minuto. Nel frattempo Vigil usa i suoi controlli interni.";
            }
            else if (!clamOk)
            {
                mood = Mood.Warn;
                title = "Protezione parziale";
                text = clam.Detail ?? "ClamAV non è attivo.";
            }
            else if (scanAgeDays > 7)
            {
                mood = Mood.Warn;
                title = p.LastScanUnix == 0 ? "Fai la prima scansione" : "È passato un po' dall'ultima scansione";
                text = "I motori sono pronti. Una scansione rapida controlla le cartelle dove di solito arriva il malware.";
            }
            else
            {
                mood = Mood.Ok;
                title = "Il PC è protetto";
                text = "Firme caricate e nessuna minaccia nell'ultima scansione.";
            }
            ApplyMood(mood);
            HeroTitle.Text = title;
            HeroText.Text = text;

            // Riquadri
            LastScanValue.Text = p.LastScanUnix == 0 ? "Mai" : Ago(p.LastScanUnix);
            LastScanSub.Text = p.LastScanUnix == 0 ? "nessuna scansione ancora" : KindName(p.LastScanKind) + " · " + (p.LastScanThreats == 0 ? "nessuna minaccia" : p.LastScanThreats + " rilevamenti");
            SigValue.Text = clam.IsReady ? "ClamAV + Vigil" : st.Engine.HashSignatures > 0 ? st.Engine.HashSignatures.ToString("N0") + " hash" : "Integrate";
            SigSub.Text = clam.IsReady ? ShortClamVersion(clam.VersionText) : "euristica, EICAR, archivi";
            QuarValue.Text = quarantined.ToString();
            QuarSub.Text = quarantined == 0 ? "nessun file isolato" : "file isolati e resi innocui";

            // Motori
            Engines.Children.Clear();
            AddEngine("ClamAV", ClamText(st), ClamColor(st));
            AddEngine("Firme di Vigil", st.Engine.HashSignatures.ToString("N0") + " hash · EICAR · archivi ZIP", Brush("Ok"));
            AddEngine("Euristica", st.Settings.Heuristics ? "attiva: nomi ingannevoli, packer, iniezione di codice" : "disattivata", st.Settings.Heuristics ? Brush("Ok") : Brush("Text3"));
            AddEngine("Protezione in tempo reale", "in arrivo nelle prossime versioni", Brush("Text3"));

            // Aggiornamenti
            UpdateButton.IsEnabled = !st.IsUpdating;
            UpdateButton.Content = st.IsUpdating ? "Aggiornamento…" : "Aggiorna ora";
            UpdateInfo.Text = p.LastUpdateUnix == 0
                ? "Le firme non sono ancora mai state aggiornate."
                : "Ultimo aggiornamento " + Ago(p.LastUpdateUnix) + (p.LastUpdateOk ? "" : " (con errori)") + "." +
                  (st.Settings.AutoUpdate ? " Vigil controlla da solo ogni " + st.Settings.UpdateIntervalHours + (st.Settings.UpdateIntervalHours == 1 ? " ora." : " ore.") : " Aggiornamento automatico disattivato.");
        }

        static string ClamText(AppState st)
        {
            if (!st.Settings.ClamavEnabled) return "disattivato nelle impostazioni";
            var c = st.Clamav;
            switch (c.Status)
            {
                case ClamavStatus.Ready: return "pronto · " + ShortClamVersion(c.VersionText);
                case ClamavStatus.Starting: return "caricamento delle firme…";
                case ClamavStatus.NoDatabase: return st.IsUpdating ? "download delle firme in corso…" : "firme assenti: premi «Aggiorna ora»";
                default: return c.Detail ?? "non attivo";
            }
        }

        static Brush ClamColor(AppState st)
        {
            if (!st.Settings.ClamavEnabled) return Brush("Text3");
            switch (st.Clamav.Status)
            {
                case ClamavStatus.Ready: return Brush("Ok");
                case ClamavStatus.Starting:
                case ClamavStatus.NoDatabase: return Brush("Amber");
                default: return Brush("Rose");
            }
        }

        /// <summary>"ClamAV 1.5.2/27800/data" → "1.5.2 · firme 27800 del data".</summary>
        public static string ShortClamVersion(string v)
        {
            if (string.IsNullOrEmpty(v)) return "";
            var parts = v.Split('/');
            var ver = parts[0].Replace("ClamAV ", "");
            return parts.Length >= 3 ? ver + " · firme n. " + parts[1] + " del " + parts[2].Trim() : ver;
        }

        void AddEngine(string name, string detail, Brush color)
        {
            var row = new Grid { Margin = new Thickness(0, 5, 0, 5) };
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(200) });
            row.ColumnDefinitions.Add(new ColumnDefinition());
            row.Children.Add(new Ellipse { Width = 9, Height = 9, Fill = color, Margin = new Thickness(0, 0, 12, 0), VerticalAlignment = VerticalAlignment.Center });
            var n = new TextBlock { Text = name, FontWeight = FontWeights.SemiBold };
            Grid.SetColumn(n, 1);
            row.Children.Add(n);
            var d = new TextBlock { Text = detail, Foreground = Brush("Text2"), TextWrapping = TextWrapping.Wrap };
            Grid.SetColumn(d, 2);
            row.Children.Add(d);
            Engines.Children.Add(row);
        }

        void ApplyMood(Mood m)
        {
            string a = m == Mood.Ok ? "TealColor" : m == Mood.Warn ? "AmberColor" : "RoseColor";
            string b = m == Mood.Ok ? "LimeColor" : m == Mood.Warn ? "OrangeColor" : "MagentaColor";
            var ca = (Color)FindResource(a);
            var cb = (Color)FindResource(b);
            var grad = new LinearGradientBrush(ca, cb, 45);
            HeroRing.Stroke = grad;
            HeroIcon.Stroke = grad;
            HeroMark.Data = (Geometry)FindResource(m == Mood.Ok ? "IconCheck" : "IconAlert");
            HeroMark.Stroke = new SolidColorBrush(ca);
            HeroGlowColor.Color = Color.FromArgb(0x33, ca.R, ca.G, ca.B);
            var stripe = new LinearGradientBrush(ca, cb, 90);
            Stripe1.Fill = Stripe2.Fill = Stripe3.Fill = Stripe4.Fill = stripe;
        }

        static Brush Brush(string key)
        {
            return (Brush)Application.Current.FindResource(key);
        }

        public static string Ago(long unix)
        {
            var span = TimeSpan.FromSeconds(Math.Max(0, FileUtil.NowUnix() - unix));
            if (span.TotalMinutes < 1) return "adesso";
            if (span.TotalHours < 1) return (int)span.TotalMinutes + " min fa";
            if (span.TotalDays < 1) return (int)span.TotalHours + (span.TotalHours < 2 ? " ora fa" : " ore fa");
            if (span.TotalDays < 2) return "ieri";
            if (span.TotalDays < 30) return (int)span.TotalDays + " giorni fa";
            return FileUtil.FromUnix(unix).ToString("d");
        }

        public static string KindName(string kind)
        {
            switch (kind)
            {
                case "quick": return "Rapida";
                case "full": return "Completa";
                default: return "Personalizzata";
            }
        }

        void OnQuickScan(object sender, RoutedEventArgs e)
        {
            MainWindow.Instance.Scan.StartScan("quick", AppState.QuickScanRoots());
            MainWindow.Instance.ShowScan();
        }

        void OnUpdate(object sender, RoutedEventArgs e)
        {
            AppState.Current.RunUpdateAsync();
            UpdateButton.IsEnabled = false;
        }

        void OnOpenQuarantine(object sender, MouseButtonEventArgs e)
        {
            MainWindow.Instance.ShowQuarantine();
        }
    }
}
