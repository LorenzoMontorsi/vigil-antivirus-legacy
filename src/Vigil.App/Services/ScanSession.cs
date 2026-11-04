using System;
using System.Collections.Generic;
using System.Threading;
using Vigil.Engine;

namespace Vigil.App.Services
{
    /// <summary>Un rilevamento mostrato all'utente, con l'azione eventualmente già compiuta.</summary>
    public sealed class Detection
    {
        public ScanResult Result;
        public string Action; // null = nessuna azione ancora

        public string FileName { get { return System.IO.Path.GetFileName(Result.Path); } }
        public string Path { get { return Result.Path; } }
        public bool IsInfected { get { return Result.IsInfected; } }

        public string Title
        {
            get
            {
                var v = Result.Verdict;
                return v.Kind == VerdictKind.Infected ? v.Threat : "Sospetto (punteggio " + v.Score + ")";
            }
        }

        public string Detail
        {
            get
            {
                var v = Result.Verdict;
                if (v.Kind == VerdictKind.Infected)
                    return SourceName(v.Source) + (v.Location != null ? " · nell'archivio: " + v.Location : "");
                return string.Join(" · ", v.Reasons);
            }
        }

        public static string SourceName(DetectionSource s)
        {
            switch (s)
            {
                case DetectionSource.Clamav: return "ClamAV";
                case DetectionSource.Hash: return "Firma (hash)";
                case DetectionSource.Pattern: return "Firma integrata";
                case DetectionSource.Heuristics: return "Euristica";
                default: return "";
            }
        }

        public static string SourceKey(DetectionSource s)
        {
            switch (s)
            {
                case DetectionSource.Clamav: return "clamav";
                case DetectionSource.Hash: return "hash";
                case DetectionSource.Pattern: return "pattern";
                default: return "heuristics";
            }
        }
    }

    /// <summary>
    /// Scansione in un thread di lavoro. L'interfaccia legge l'istantanea con <see cref="Snapshot"/>
    /// a intervalli (DispatcherTimer) invece di ricevere un evento per ogni file: su un PC
    /// vecchio migliaia di aggiornamenti al secondo bloccherebbero la finestra.
    /// </summary>
    public sealed class ScanSession
    {
        readonly object gate = new object();
        readonly CancellationTokenSource cts = new CancellationTokenSource();
        readonly List<Detection> detections = new List<Detection>();
        ScanSummary summary = new ScanSummary();
        string current = "";

        public string Kind { get; private set; }
        public IList<string> Roots { get; private set; }
        public bool Finished { get; private set; }
        public DateTime Started { get; private set; }

        /// <summary>Al termine (dal thread di lavoro).</summary>
        public event Action Completed;

        public ScanSession(string kind, IList<string> roots)
        {
            Kind = kind;
            Roots = roots;
        }

        public void Start()
        {
            Started = DateTime.Now;
            var st = AppState.Current;
            new Thread(() =>
            {
                ScanSummary final;
                try
                {
                    var opts = st.BuildScanOptions();
                    final = Scanner.ScanPaths(st.Engine, Roots, opts, cts.Token, (r, s) =>
                    {
                        Detection d = null;
                        if (r.Verdict.IsDetection)
                        {
                            d = new Detection { Result = r };
                            // Solo gli infetti certi: i sospetti non si spostano mai da soli.
                            if (r.IsInfected && st.Settings.AutoQuarantine)
                                TryQuarantine(d);
                        }
                        lock (gate)
                        {
                            current = r.Path;
                            summary = s.Clone();
                            if (d != null)
                                detections.Add(d);
                        }
                    });
                }
                catch (Exception e)
                {
                    final = summary.Clone();
                    lock (gate)
                        detections.Add(new Detection { Result = new ScanResult { Path = "", Verdict = Verdict.Error(e.Message) } });
                }
                lock (gate)
                {
                    summary = final;
                    Finished = true;
                }
                st.Persisted.LastScanUnix = FileUtil.NowUnix();
                st.Persisted.LastScanKind = Kind;
                st.Persisted.LastScanThreats = final.Infected + final.Suspicious;
                st.Persisted.Save();
                st.RaiseChanged();
                var h = Completed;
                if (h != null) h();
            }) { IsBackground = true, Name = "Vigil scansione" }.Start();
        }

        public void Cancel()
        {
            cts.Cancel();
        }

        public bool CancelRequested { get { return cts.IsCancellationRequested; } }

        public void Snapshot(out ScanSummary s, out string currentPath, out List<Detection> found)
        {
            lock (gate)
            {
                s = summary.Clone();
                currentPath = current;
                found = new List<Detection>(detections);
            }
        }

        /// <summary>Mette in quarantena; restituisce il messaggio da mostrare.</summary>
        public static string TryQuarantine(Detection d)
        {
            try
            {
                var v = d.Result.Verdict;
                AppState.Current.Quarantine.Add(d.Path, v.Kind == VerdictKind.Infected ? v.Threat : "Sospetto", Detection.SourceKey(v.Source));
                d.Action = "In quarantena";
                AppState.Current.RaiseChanged();
            }
            catch (Exception e)
            {
                d.Action = "Quarantena non riuscita: " + e.Message;
            }
            return d.Action;
        }
    }
}
