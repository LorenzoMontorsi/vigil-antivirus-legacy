using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using Vigil.App.Services;
using Vigil.Engine;

namespace Vigil.App.Pages
{
    public partial class ScanPage : UserControl, IPage
    {
        ScanSession session;
        readonly DispatcherTimer timer;
        int shownDetections = -1;
        bool notified;
        double runner;

        public ScanPage()
        {
            InitializeComponent();
            // 5 aggiornamenti al secondo bastano e non pesano su un PC vecchio.
            timer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromMilliseconds(200) };
            timer.Tick += (s, e) => Tick();
        }

        public bool IsRunning { get { return session != null && !session.Finished; } }

        public void Refresh()
        {
            if (session != null)
                Tick();
        }

        /// <summary>Avvia una scansione (se un'altra è in corso viene ignorata).</summary>
        public void StartScan(string kind, IList<string> roots)
        {
            if (IsRunning)
                return;
            if (roots == null || roots.Count == 0)
            {
                MessageBox.Show("Nessuna cartella da analizzare.", "Vigil Legacy", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            session = new ScanSession(kind, roots);
            shownDetections = -1;
            notified = false;
            DetectionList.Children.Clear();
            session.Completed += () => Dispatcher.BeginInvoke(new Action(Tick));
            ChoicePanel.Visibility = Visibility.Collapsed;
            ProgressCard.Visibility = Visibility.Visible;
            DetectionsCard.Visibility = Visibility.Collapsed;
            CancelButton.Visibility = Visibility.Visible;
            CancelButton.IsEnabled = true;
            NewButton.Visibility = Visibility.Collapsed;
            Track.Visibility = Visibility.Visible;
            RootsInfo.Text = roots.Count == 1 ? "Percorso: " + roots[0]
                : roots.Count + " percorsi: " + string.Join(", ", roots.Take(6).Select(ShortName).ToArray()) + (roots.Count > 6 ? "…" : "");
            RootsInfo.ToolTip = string.Join(Environment.NewLine, roots.ToArray());
            session.Start();
            timer.Start();
            Tick();
        }

        void Tick()
        {
            if (session == null)
                return;
            ScanSummary s;
            string current;
            List<Detection> found;
            session.Snapshot(out s, out current, out found);

            bool done = session.Finished;
            StatScanned.Text = s.Scanned.ToString("N0");
            StatInfected.Text = s.Infected.ToString("N0");
            StatInfected.Foreground = s.Infected > 0 ? Brush("Rose") : Brush("Text");
            StatSuspicious.Text = s.Suspicious.ToString("N0");
            StatSuspicious.Foreground = s.Suspicious > 0 ? Brush("Amber") : Brush("Text");
            StatSkipped.Text = s.Skipped.ToString("N0");
            StatErrors.Text = s.Errors.ToString("N0");
            var t = TimeSpan.FromMilliseconds(done ? s.ElapsedMs : (DateTime.Now - session.Started).TotalMilliseconds);
            StatTime.Text = t.TotalHours >= 1 ? ((int)t.TotalHours).ToString("00") + ":" + t.Minutes.ToString("00") + ":" + t.Seconds.ToString("00") : t.Minutes.ToString("00") + ":" + t.Seconds.ToString("00");
            ExtraInfo.Text = s.Cached.ToString("N0") + " file già controllati (dalla cache) · " + s.Trusted.ToString("N0") + " eseguibili con firma Microsoft verificata";

            if (!done)
            {
                StateTitle.Text = session.CancelRequested ? "Interruzione in corso…" : "Scansione " + DashboardPage.KindName(session.Kind).ToLowerInvariant() + " in corso…";
                CurrentFile.Text = current;
                runner = (runner + 14) % (Math.Max(Track.ActualWidth, 200) + 140);
                RunnerX.X = runner - 140;
            }
            else
            {
                timer.Stop();
                Track.Visibility = Visibility.Collapsed;
                CancelButton.Visibility = Visibility.Collapsed;
                NewButton.Visibility = Visibility.Visible;
                CurrentFile.Text = "";
                bool threats = s.Infected + s.Suspicious > 0;
                StateTitle.Text = s.Cancelled ? "Scansione interrotta" : threats ? "Scansione completata: trovate " + (s.Infected + s.Suspicious) + " minacce" : "Scansione completata: nessuna minaccia";
                StateIcon.Data = (Geometry)FindResource(threats ? "IconAlert" : "IconShield");
                StateIcon.Stroke = threats ? Brush("Rose") : Brush("Ok");
                if (!notified)
                {
                    notified = true;
                    NotifyIfHidden(s);
                }
            }

            if (found.Count != shownDetections || done)
            {
                shownDetections = found.Count;
                RenderDetections(found);
            }
        }

        void RenderDetections(List<Detection> found)
        {
            var real = found.Where(d => !string.IsNullOrEmpty(d.Path)).ToList();
            DetectionsCard.Visibility = real.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
            QuarantineAllButton.Visibility = session.Finished && real.Any(d => d.IsInfected && d.Action == null) ? Visibility.Visible : Visibility.Collapsed;
            DetectionList.Children.Clear();
            foreach (var d in real.Take(500))
                DetectionList.Children.Add(Row(d));
            if (real.Count > 500)
                DetectionList.Children.Add(new TextBlock { Text = "… e altri " + (real.Count - 500), Style = (Style)FindResource("Faint") });
        }

        UIElement Row(Detection d)
        {
            var row = new Border
            {
                Background = Brush("Surface2"),
                BorderBrush = Brush("Border"),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(12),
                Padding = new Thickness(14, 10, 14, 10),
                Margin = new Thickness(0, 0, 0, 8),
            };
            var g = new Grid();
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(4) });
            g.ColumnDefinitions.Add(new ColumnDefinition());
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            g.Children.Add(new Border { CornerRadius = new CornerRadius(2), Background = d.IsInfected ? Brush("GradDanger") : Brush("GradWarn") });

            var info = new StackPanel { Margin = new Thickness(12, 0, 12, 0) };
            info.Children.Add(new TextBlock { Text = d.Title, FontWeight = FontWeights.SemiBold, Foreground = d.IsInfected ? Brush("Rose") : Brush("Amber") });
            info.Children.Add(new TextBlock { Text = d.Path, Foreground = Brush("Text"), TextTrimming = TextTrimming.CharacterEllipsis, ToolTip = d.Path, Margin = new Thickness(0, 2, 0, 2) });
            info.Children.Add(new TextBlock { Text = d.Detail, Style = (Style)FindResource("Faint") });
            Grid.SetColumn(info, 1);
            g.Children.Add(info);

            var actions = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            if (d.Action != null)
            {
                actions.Children.Add(new TextBlock { Text = d.Action, Foreground = d.Action == "In quarantena" ? Brush("Ok") : Brush("Text2"), VerticalAlignment = VerticalAlignment.Center, MaxWidth = 260, TextWrapping = TextWrapping.Wrap });
            }
            else if (session.Finished)
            {
                var q = new Button { Content = "Quarantena", Style = (Style)FindResource("Small") };
                q.Click += (s, e) => { ScanSession.TryQuarantine(d); RenderDetections(Current()); };
                var ex = new Button { Content = "Escludi", Style = (Style)FindResource("Small"), Margin = new Thickness(6, 0, 0, 0), ToolTip = "Non segnalare più questo file" };
                ex.Click += (s, e) => { Exclude(d); RenderDetections(Current()); };
                var ig = new Button { Content = "Ignora", Style = (Style)FindResource("Small"), Margin = new Thickness(6, 0, 0, 0) };
                ig.Click += (s, e) => { d.Action = "Ignorato"; RenderDetections(Current()); };
                actions.Children.Add(q);
                actions.Children.Add(ex);
                actions.Children.Add(ig);
            }
            Grid.SetColumn(actions, 2);
            g.Children.Add(actions);
            row.Child = g;
            return row;
        }

        List<Detection> Current()
        {
            ScanSummary s;
            string c;
            List<Detection> found;
            session.Snapshot(out s, out c, out found);
            return found;
        }

        /// <summary>Scansione finita mentre Vigil era nascosto (es. lanciata dal tasto destro e poi chiusa la finestra).</summary>
        void NotifyIfHidden(ScanSummary s)
        {
            var w = Window.GetWindow(this);
            if (w != null && w.IsVisible && w.WindowState != WindowState.Minimized)
                return;
            long n = s.Infected + s.Suspicious;
            Action open = () => { App.Current.ShowMain(); MainWindow.Instance.ShowScan(); };
            if (n == 0)
            {
                ToastWindow.Show("Scansione completata", s.Scanned.ToString("N0") + " file analizzati, nessuna minaccia.", false, 8,
                    Tuple.Create("Apri Vigil", open));
                return;
            }
            var actions = new List<Tuple<string, Action>>();
            if (s.Infected > 0 && !AppState.Current.Settings.AutoQuarantine)
                actions.Add(Tuple.Create<string, Action>("Metti in quarantena", () => { OnQuarantineAll(null, null); open(); }));
            actions.Add(Tuple.Create("Vedi i risultati", open));
            actions.Add(Tuple.Create<string, Action>("Ignora", null));
            ToastWindow.Show("Trovate " + n + (n == 1 ? " minaccia" : " minacce"),
                s.Infected + (s.Infected == 1 ? " infetto, " : " infetti, ") + s.Suspicious + (s.Suspicious == 1 ? " sospetto" : " sospetti") +
                " su " + s.Scanned.ToString("N0") + " file analizzati.", true, 0, actions.ToArray());
        }

        static void Exclude(Detection d)
        {
            var st = AppState.Current;
            if (!st.Settings.Exclusions.Paths.Any(p => string.Equals(p, d.Path, StringComparison.OrdinalIgnoreCase)))
                st.Settings.Exclusions.Paths.Add(d.Path);
            st.SaveSettings();
            d.Action = "Escluso dalle scansioni";
        }

        /// <summary>Nome del file o della cartella; per le unità ("D:\") il percorso intero.</summary>
        static string ShortName(string path)
        {
            var name = System.IO.Path.GetFileName(path.TrimEnd('\\'));
            return string.IsNullOrEmpty(name) ? path : name;
        }

        static Brush Brush(string key)
        {
            return (Brush)Application.Current.FindResource(key);
        }

        void OnQuick(object sender, RoutedEventArgs e)
        {
            StartScan("quick", AppState.QuickScanRoots());
        }

        void OnFull(object sender, RoutedEventArgs e)
        {
            StartScan("full", AppState.FullScanRoots());
        }

        void OnCustom(object sender, RoutedEventArgs e)
        {
            // Il selettore di cartelle di WinForms esiste su tutte le versioni di Windows.
            using (var dlg = new System.Windows.Forms.FolderBrowserDialog { Description = "Scegli la cartella o il disco da analizzare", ShowNewFolderButton = false })
            {
                if (dlg.ShowDialog() == System.Windows.Forms.DialogResult.OK)
                    StartScan("custom", new[] { dlg.SelectedPath });
            }
        }

        void OnCancel(object sender, RoutedEventArgs e)
        {
            if (session != null)
                session.Cancel();
            CancelButton.IsEnabled = false;
        }

        void OnNew(object sender, RoutedEventArgs e)
        {
            session = null;
            ChoicePanel.Visibility = Visibility.Visible;
            ProgressCard.Visibility = Visibility.Collapsed;
            DetectionsCard.Visibility = Visibility.Collapsed;
            StateIcon.Data = (Geometry)FindResource("IconScan");
            StateIcon.Stroke = Brush("Cyan");
        }

        void OnQuarantineAll(object sender, RoutedEventArgs e)
        {
            foreach (var d in Current().Where(x => x.IsInfected && x.Action == null))
                ScanSession.TryQuarantine(d);
            RenderDetections(Current());
        }
    }
}
