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
            EmptyCard.Visibility = items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            List.Children.Clear();
            foreach (var it in items)
                List.Children.Add(Row(it));
        }

        UIElement Row(QuarantineItem it)
        {
            var card = new Border { Style = (Style)FindResource("Card"), Padding = new Thickness(18, 14, 18, 14), Margin = new Thickness(0, 0, 0, 10) };
            var g = new Grid();
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(4) });
            g.ColumnDefinitions.Add(new ColumnDefinition());
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            g.Children.Add(new Border { CornerRadius = new CornerRadius(2), Background = Brush("GradDanger") });

            var info = new StackPanel { Margin = new Thickness(14, 0, 14, 0) };
            info.Children.Add(new TextBlock { Text = it.Threat, FontWeight = FontWeights.SemiBold, Foreground = Brush("Rose") });
            info.Children.Add(new TextBlock { Text = it.OriginalPath, TextTrimming = TextTrimming.CharacterEllipsis, ToolTip = it.OriginalPath, Margin = new Thickness(0, 3, 0, 3) });
            info.Children.Add(new TextBlock
            {
                Text = FileUtil.FromUnix(it.QuarantinedAt).ToString("g") + " · " + Size(it.Size) + " · " + SourceName(it.Source),
                Style = (Style)FindResource("Faint"),
            });
            Grid.SetColumn(info, 1);
            g.Children.Add(info);

            var actions = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            var restore = new Button { Content = "Ripristina", Style = (Style)FindResource("Small") };
            restore.Click += (s, e) => Restore(it);
            var del = new Button { Content = "Elimina", Style = (Style)FindResource("Small"), Margin = new Thickness(6, 0, 0, 0) };
            del.Click += (s, e) => Delete(it);
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
