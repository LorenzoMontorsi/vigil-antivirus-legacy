using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Vigil.App.Services;
using Vigil.Engine;

namespace Vigil.App.Pages
{
    public partial class QuarantinePage : UserControl, IPage
    {
        public QuarantinePage()
        {
            InitializeComponent();
        }

        public void Refresh()
        {
            List<QuarantineItem> items;
            try
            {
                items = AppState.Current.Quarantine.List();
            }
            catch (Exception e)
            {
                items = new List<QuarantineItem>();
                MessageBox.Show("Impossibile leggere la quarantena: " + e.Message, "Vigil Legacy", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
            // Quarantena del servizio (protezione in tempo reale): per tutto il PC.
            List<QuarantineItem> service = new List<QuarantineItem>();
            if (AppState.Current.ServiceMode)
            {
                var resp = RtProtocol.TryCall(RtRequest.Of("quarantine_list"));
                if (resp != null && resp.Ok && resp.Items != null)
                    service = resp.Items;
            }
            EmptyCard.Visibility = items.Count + service.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            List.Children.Clear();
            foreach (var it in service)
                List.Children.Add(Row(it, true));
            foreach (var it in items)
                List.Children.Add(Row(it, false));
        }

        UIElement Row(QuarantineItem it, bool service)
        {
            var card = new Border { Style = (Style)FindResource("Card"), Padding = new Thickness(18, 14, 18, 14), Margin = new Thickness(0, 0, 0, 10) };
            var g = new Grid();
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(4) });
            g.ColumnDefinitions.Add(new ColumnDefinition());
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            g.Children.Add(new Border { CornerRadius = new CornerRadius(2), Background = Brush("GradDanger") });

            var info = new StackPanel { Margin = new Thickness(14, 0, 14, 0) };
            var type = ThreatInfo.Parse(it.Threat);
            var title = new TextBlock { FontWeight = FontWeights.SemiBold, Foreground = Brush("Rose"), TextTrimming = TextTrimming.CharacterEllipsis };
            title.Inlines.Add(it.Threat);
            title.Inlines.Add(new System.Windows.Documents.Run("   " + type.Display + " · " + type.Description) { FontWeight = FontWeights.Normal, Foreground = Brush("Text2") });
            info.Children.Add(title);
            info.Children.Add(new TextBlock { Text = it.OriginalPath, TextTrimming = TextTrimming.CharacterEllipsis, ToolTip = it.OriginalPath, Margin = new Thickness(0, 3, 0, 3) });
            info.Children.Add(new TextBlock
            {
                Text = FileUtil.FromUnix(it.QuarantinedAt).ToString("g") + " · " + Size(it.Size) + " · " + SourceName(it.Source) +
                       (service ? " · protezione in tempo reale" : ""),
                Style = (Style)FindResource("Faint"),
            });
            Grid.SetColumn(info, 1);
            g.Children.Add(info);

            var actions = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            var restore = new Button { Content = "Ripristina", Style = (Style)FindResource("Small") };
            restore.Click += (s, e) => { if (service) ServiceAction(it, "quarantine_restore"); else Restore(it); };
            var del = new Button { Content = "Elimina", Style = (Style)FindResource("Small"), Margin = new Thickness(6, 0, 0, 0) };
            del.Click += (s, e) => { if (service) ServiceAction(it, "quarantine_delete"); else Delete(it); };
            actions.Children.Add(restore);
            actions.Children.Add(del);
            Grid.SetColumn(actions, 2);
            g.Children.Add(actions);
            card.Child = g;
            return card;
        }

        void Restore(QuarantineItem it)
        {
            var ok = MessageBox.Show("Ripristinare \"" + it.OriginalPath + "\"?\n\nFallo solo se sei sicuro che il file sia innocuo: Vigil lo considera «" + it.Threat + "».",
                "Ripristina dalla quarantena", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (ok != MessageBoxResult.Yes)
                return;
            try
            {
                var dest = AppState.Current.Quarantine.Restore(it.Id);
                // Non segnalarlo di nuovo subito: l'utente ha deciso che è innocuo.
                var ex = AppState.Current.Settings.Exclusions;
                if (!ex.Paths.Contains(dest))
                    ex.Paths.Add(dest);
                AppState.Current.SaveSettings();
                MessageBox.Show("File ripristinato in " + dest + ".\nÈ stato aggiunto alle esclusioni.", "Vigil Legacy", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception e)
            {
                MessageBox.Show("Ripristino non riuscito: " + e.Message, "Vigil Legacy", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            AppState.Current.RaiseChanged();
        }

        void Delete(QuarantineItem it)
        {
            if (MessageBox.Show("Eliminare per sempre \"" + it.OriginalPath + "\"?", "Elimina dalla quarantena", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes)
                return;
            try
            {
                AppState.Current.Quarantine.Delete(it.Id);
            }
            catch (Exception e)
            {
                MessageBox.Show("Eliminazione non riuscita: " + e.Message, "Vigil Legacy", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            AppState.Current.RaiseChanged();
        }

        /// <summary>Ripristino/eliminazione dalla quarantena del servizio: serve un amministratore.</summary>
        void ServiceAction(QuarantineItem it, string cmd)
        {
            bool restore = cmd == "quarantine_restore";
            var question = restore
                ? "Ripristinare \"" + it.OriginalPath + "\"?\n\nFallo solo se sei sicuro che il file sia innocuo: Vigil lo considera «" + it.Threat + "». Verrà escluso dalla protezione in tempo reale."
                : "Eliminare per sempre \"" + it.OriginalPath + "\"?";
            if (MessageBox.Show(question, restore ? "Ripristina dalla quarantena" : "Elimina dalla quarantena", MessageBoxButton.YesNo,
                    restore ? MessageBoxImage.Warning : MessageBoxImage.Question) != MessageBoxResult.Yes)
                return;
            new System.Threading.Thread(() =>
            {
                var err = Realtime.Command(new RtRequest { Cmd = cmd, Id = it.Id });
                Dispatcher.BeginInvoke(new Action(() =>
                {
                    if (err != null)
                        MessageBox.Show((restore ? "Ripristino" : "Eliminazione") + " non riuscito: " + err, "Vigil Legacy", MessageBoxButton.OK, MessageBoxImage.Error);
                    AppState.Current.RaiseChanged();
                }));
            }) { IsBackground = true }.Start();
        }

        static string SourceName(string s)
        {
            switch (s)
            {
                case "clamav": return "ClamAV";
                case "hash": return "firma (hash)";
                case "pattern": return "firma integrata";
                default: return "euristica";
            }
        }

        public static string Size(long b)
        {
            if (b < 1024) return b + " B";
            if (b < 1024 * 1024) return (b / 1024.0).ToString("0.#") + " KB";
            return (b / (1024.0 * 1024)).ToString("0.#") + " MB";
        }

        static Brush Brush(string key)
        {
            return (Brush)Application.Current.FindResource(key);
        }
    }
}
