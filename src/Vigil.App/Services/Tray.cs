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
        readonly ToolStripMenuItem updateItem;

        public event Action OpenRequested;
        public event Action QuickScanRequested;
        public event Action UpdateRequested;
        public event Action ExitRequested;

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
            menu.Items.AddRange(new ToolStripItem[] { open, new ToolStripSeparator(), quick, updateItem, new ToolStripSeparator(), exit });

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
