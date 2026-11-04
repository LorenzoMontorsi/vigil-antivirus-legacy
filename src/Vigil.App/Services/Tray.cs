using System;
using System.Drawing;
using System.Windows.Forms;

namespace Vigil.App.Services
{
    /// <summary>
    /// Icona nell'area di notifica (NotifyIcon di WinForms: WPF in .NET 4.0 non ne ha una).
    /// Doppio clic apre Vigil; il menu offre le azioni rapide.
    /// </summary>
    public sealed class Tray : IDisposable
    {
        readonly NotifyIcon icon;
        readonly ToolStripMenuItem updateItem, pauseItem, resumeItem;
        readonly ToolStripSeparator rtSeparator;

        public event Action OpenRequested;
        public event Action QuickScanRequested;
        public event Action UpdateRequested;
        public event Action ExitRequested;
        /// <summary>Minuti di sospensione; 0 = fino al riavvio.</summary>
        public event Action<int> PauseRequested;
        public event Action ResumeRequested;

        public Tray()
        {
            var menu = new ContextMenuStrip { ShowImageMargin = false };
            var open = new ToolStripMenuItem("Apri Vigil") { Font = new Font(SystemFonts.MenuFont, FontStyle.Bold) };
            open.Click += (s, e) => Raise(OpenRequested);
            var quick = new ToolStripMenuItem("Scansione rapida");
            quick.Click += (s, e) => Raise(QuickScanRequested);
            updateItem = new ToolStripMenuItem("Aggiorna le firme");
            updateItem.Click += (s, e) => Raise(UpdateRequested);
            var exit = new ToolStripMenuItem("Esci da Vigil");
            exit.Click += (s, e) => Raise(ExitRequested);

            // Sospensione della protezione in tempo reale (solo se il servizio c'è).
            pauseItem = new ToolStripMenuItem("Sospendi la protezione");
            foreach (var choice in new[] { Tuple.Create("Per 15 minuti", 15), Tuple.Create("Per 1 ora", 60), Tuple.Create("Per 4 ore", 240), Tuple.Create("Fino al riavvio", 0) })
            {
                int minutes = choice.Item2;
                var it = new ToolStripMenuItem(choice.Item1);
                it.Click += (s, e) => { var h = PauseRequested; if (h != null) h(minutes); };
                pauseItem.DropDownItems.Add(it);
            }
            resumeItem = new ToolStripMenuItem("Riprendi la protezione");
            resumeItem.Click += (s, e) => Raise(ResumeRequested);
            rtSeparator = new ToolStripSeparator();
            menu.Items.AddRange(new ToolStripItem[] { open, new ToolStripSeparator(), quick, updateItem, rtSeparator, pauseItem, resumeItem, new ToolStripSeparator(), exit });
            SetRealtime(false, false);

            icon = new NotifyIcon
            {
                Icon = LoadIcon(),
                Text = "Vigil Legacy",
                ContextMenuStrip = menu,
                Visible = true,
            };
            icon.MouseDoubleClick += (s, e) => { if (e.Button == MouseButtons.Left) Raise(OpenRequested); };
        }

        static Icon LoadIcon()
        {
            try
            {
                var stream = System.Windows.Application.GetResourceStream(new Uri("pack://application:,,,/Assets/vigil.ico")).Stream;
                return new Icon(stream, SystemInformation.SmallIconSize);
            }
            catch (Exception)
            {
                return SystemIcons.Shield;
            }
        }

        static void Raise(Action a)
        {
            if (a != null) a();
        }

        /// <summary>Testo al passaggio del mouse (massimo 63 caratteri su XP).</summary>
        public void SetStatus(string text, bool updating)
        {
            var t = "Vigil Legacy · " + text;
            icon.Text = t.Length > 63 ? t.Substring(0, 63) : t;
            updateItem.Enabled = !updating;
            updateItem.Text = updating ? "Aggiornamento in corso…" : "Aggiorna le firme";
        }

        public void SetRealtime(bool available, bool paused)
        {
            rtSeparator.Visible = available;
            pauseItem.Visible = available && !paused;
            resumeItem.Visible = available && paused;
        }

        /// <summary>Fumetto di sistema: per gli avvisi senza azioni (funziona da XP).</summary>
        public void Balloon(string title, string text, bool warning)
        {
            icon.ShowBalloonTip(5000, title, text, warning ? ToolTipIcon.Warning : ToolTipIcon.Info);
        }

        public void Dispose()
        {
            icon.Visible = false;
            icon.Dispose();
        }
    }
}
