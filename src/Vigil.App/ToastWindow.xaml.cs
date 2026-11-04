using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;

namespace Vigil.App
{
    /// <summary>
    /// Avviso in basso a destra con pulsanti di azione (Quarantena, Apri, Ignora…).
    /// Più avvisi si impilano verso l'alto. Si chiude da solo dopo un po' se non serve una decisione.
    /// </summary>
    public partial class ToastWindow : Window
    {
        static readonly List<ToastWindow> open = new List<ToastWindow>();
        readonly DispatcherTimer life = new DispatcherTimer();

        public ToastWindow()
        {
            InitializeComponent();
            life.Tick += (s, e) => Close();
            Closed += (s, e) => { open.Remove(this); Restack(); };
        }

        /// <param name="danger">true: rosso (minaccia); false: colori del marchio (informazione).</param>
        /// <param name="seconds">0 = resta finché l'utente non sceglie.</param>
        public static ToastWindow Show(string title, string body, bool danger, int seconds, params Tuple<string, Action>[] actions)
        {
            var t = new ToastWindow();
            t.TitleText.Text = title;
            t.BodyText.Text = body;
            t.BodyText.ToolTip = body;
            t.Accent.Background = (Brush)Application.Current.FindResource(danger ? "GradDanger" : "GradBrand");
            bool first = true;
            foreach (var a in actions)
            {
                var action = a.Item2;
                var b = new Button { Content = a.Item1, Style = (Style)Application.Current.FindResource(first && danger ? "Danger" : "Small"), Margin = new Thickness(0, 0, 8, 0), Padding = new Thickness(12, 5, 12, 5), FontSize = 12.5 };
                b.Click += (s, e) => { t.Close(); if (action != null) action(); };
                t.Actions.Children.Add(b);
                first = false;
            }
            if (actions.Length == 0)
                t.Actions.Visibility = Visibility.Collapsed;
            if (seconds > 0)
            {
                t.life.Interval = TimeSpan.FromSeconds(seconds);
                t.life.Start();
            }
            // Il mouse sopra l'avviso lo tiene aperto.
            t.MouseEnter += (s, e) => t.life.Stop();
            t.MouseLeave += (s, e) => { if (seconds > 0) t.life.Start(); };
            open.Add(t);
            t.Show();
            Restack();
            return t;
        }

        static void Restack()
        {
            var area = SystemParameters.WorkArea;
            double bottom = area.Bottom - 12;
            for (int i = open.Count - 1; i >= 0; i--)
            {
                var w = open[i];
                w.UpdateLayout();
                w.Left = area.Right - w.Width - 12;
                w.Top = bottom - w.ActualHeight;
                bottom = w.Top - 10;
            }
        }

        void OnClose(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
