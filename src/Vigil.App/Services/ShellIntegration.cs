using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using Microsoft.Win32;

namespace Vigil.App.Services
{
    /// <summary>
    /// "Analizza con Vigil Legacy" nel menu del tasto destro e avvio automatico all'accesso.
    /// Tutto in HKCU: niente privilegi di amministratore (HKCU\Software\Classes esiste da Windows 2000).
    /// Con più elementi selezionati Esplora risorse avvia Vigil una volta per ciascuno:
    /// i lanci ravvicinati arrivano all'istanza aperta e vengono raccolti in un'unica scansione.
    /// </summary>
    public static class ShellIntegration
    {
        const string Verb = "VigilLegacyScan";
        const string Label = "Analizza con Vigil";
        const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
        const string RunValue = "VigilLegacy";
        static readonly string[] Targets = { "*", "Directory", "Drive" };

        static string Exe
        {
            get { return System.Reflection.Assembly.GetEntryAssembly().Location; }
        }

        /// <summary>In sviluppo (build Debug) non si registra l'eseguibile di prova.</summary>
        static bool IsDevBuild
        {
            get
            {
#if DEBUG
                return true;
#else
                return false;
#endif
            }
        }

        public static void ApplyContextMenu(bool enabled)
        {
            if (IsDevBuild)
                return;
            foreach (var t in Targets)
            {
                var path = @"Software\Classes\" + t + @"\shell\" + Verb;
                try
                {
                    if (!enabled)
                    {
                        Registry.CurrentUser.DeleteSubKeyTree(path, false);
                        continue;
                    }
                    using (var k = Registry.CurrentUser.CreateSubKey(path))
                    {
                        k.SetValue("", Label);
                        k.SetValue("Icon", "\"" + Exe + "\",0");
                    }
                    using (var k = Registry.CurrentUser.CreateSubKey(path + @"\command"))
                        k.SetValue("", "\"" + Exe + "\" --scan \"%1\"");
                }
                catch (Exception) { }
            }
        }

        public static void ApplyAutostart(bool enabled)
        {
            if (IsDevBuild)
                return;
            try
            {
                using (var k = Registry.CurrentUser.CreateSubKey(RunKey))
                {
                    if (enabled)
                        k.SetValue(RunValue, "\"" + Exe + "\" --hidden");
                    else if (k.GetValue(RunValue) != null)
                        k.DeleteValue(RunValue);
                }
            }
            catch (Exception) { }
        }

        /// <summary>Percorsi passati con <c>--scan &lt;percorso&gt;</c>.</summary>
        public static List<string> ScanArgs(IList<string> args)
        {
            var out_ = new List<string>();
            for (int i = 0; i < args.Count; i++)
            {
                if (args[i] == "--scan" && i + 1 < args.Count && args[i + 1].Trim().Length > 0)
                    out_.Add(args[++i].Trim().Trim('"'));
            }
            return out_;
        }

        // ---- raccolta dei lanci ravvicinati ----

        static readonly object gate = new object();
        static readonly List<string> incoming = new List<string>();
        static bool gathering;

        /// <summary>Esplora risorse avvia un processo per elemento: si aspetta che arrivino tutti.</summary>
        const int GatherMs = 900;

        /// <summary>Accoda i percorsi; dopo <see cref="GatherMs"/> chiama <paramref name="ready"/> con tutti quelli arrivati.</summary>
        public static void Queue(IEnumerable<string> paths, Action<List<string>> ready)
        {
            lock (gate)
            {
                incoming.AddRange(paths);
                if (gathering || incoming.Count == 0)
                    return;
                gathering = true;
            }
            new Thread(() =>
            {
                Thread.Sleep(GatherMs);
                List<string> batch;
                lock (gate)
                {
                    gathering = false;
                    batch = incoming.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(p => p, StringComparer.OrdinalIgnoreCase).ToList();
                    incoming.Clear();
                }
                ready(batch);
            }) { IsBackground = true }.Start();
        }
    }
}
