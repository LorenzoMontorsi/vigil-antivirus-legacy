using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;

namespace Vigil.Engine
{
    public sealed class ScanOptions
    {
        public long MaxFileSize = 64L * 1024 * 1024;
        public int Threads = Math.Max(1, Math.Min(4, Environment.ProcessorCount));
        public Exclusions Exclusions = new Exclusions();

        /// <summary>Analizza il contenuto degli archivi ZIP.</summary>
        public bool ScanArchives = true;

        /// <summary>Segnala i file sospetti secondo l'euristica statica.</summary>
        public bool Heuristics = true;

        /// <summary>Motore ClamAV (demone clamd), opzionale.</summary>
        public ClamdClient Clamd;

        /// <summary>Gli eseguibili con firma Microsoft valida saltano ClamAV ed euristica.</summary>
        public bool TrustMicrosoft = true;

        /// <summary>Salta i file già trovati puliti e non modificati.</summary>
        public ScanCache Cache;
    }

    public sealed class ScanSummary
    {
        /// <summary>File analizzati (puliti + infetti + sospetti).</summary>
        public long Scanned, Infected, Suspicious, Skipped, Errors;

        /// <summary>File saltati perché già puliti in cache.</summary>
        public long Cached;

        /// <summary>Eseguibili con firma Microsoft verificata.</summary>
        public long Trusted;

        public bool Cancelled;
        public long ElapsedMs;

        public ScanSummary Clone()
        {
            return (ScanSummary)MemberwiseClone();
        }
    }

    public static class Scanner
    {
        /// <summary>
        /// Scansiona file e cartelle in parallelo. <paramref name="onResult"/> viene chiamato
        /// sul thread chiamante per ogni file, insieme al riepilogo aggiornato.
        /// </summary>
        public static ScanSummary ScanPaths(ScanEngine engine, IEnumerable<string> roots, ScanOptions opts, CancellationToken cancel,
            Action<ScanResult, ScanSummary> onResult)
        {
            var sw = Stopwatch.StartNew();
            var summary = new ScanSummary();
            var paths = new BlockingCollection<string>(4096);
            var results = new BlockingCollection<ScanResult>(4096);
            int workers = Math.Max(1, opts.Threads);
            int running = workers + 1;
            Action done = () =>
            {
                if (Interlocked.Decrement(ref running) == 0)
                    results.CompleteAdding();
            };

            var walker = new Thread(() =>
            {
                try
                {
                    foreach (var root in roots)
                        Walk(root, opts.Exclusions, cancel, paths, results);
                }
                finally
                {
                    paths.CompleteAdding();
                    done();
                }
            }) { IsBackground = true, Name = "Vigil walker" };
            walker.Start();

            for (int i = 0; i < workers; i++)
            {
                new Thread(() =>
                {
                    try
                    {
                        foreach (var p in paths.GetConsumingEnumerable())
                        {
                            // Annullata: si continua a svuotare la coda senza analizzare,
                            // così il thread che elenca i file non resta bloccato su una coda piena.
                            if (cancel.IsCancellationRequested)
                                continue;
                            ScanResult r;
                            try
                            {
                                r = engine.ScanFile(p, opts);
                            }
                            catch (Exception e)
                            {
                                r = new ScanResult { Path = p, Verdict = Verdict.Error(e.Message) };
                            }
                            results.Add(r);
                        }
                    }
                    finally
                    {
                        done();
                    }
                }) { IsBackground = true, Name = "Vigil scanner", Priority = ThreadPriority.BelowNormal }.Start();
            }

            foreach (var r in results.GetConsumingEnumerable())
            {
                if (r.Cached) summary.Cached++;
                if (Trust.IsMicrosoft(r.Signer)) summary.Trusted++;
                switch (r.Verdict.Kind)
                {
                    case VerdictKind.Clean: summary.Scanned++; break;
                    case VerdictKind.Infected: summary.Scanned++; summary.Infected++; break;
                    case VerdictKind.Suspicious: summary.Scanned++; summary.Suspicious++; break;
                    case VerdictKind.Skipped: summary.Skipped++; break;
                    case VerdictKind.Error: summary.Errors++; break;
                }
                summary.ElapsedMs = sw.ElapsedMilliseconds;
                if (onResult != null)
                    onResult(r, summary);
            }

            if (opts.Cache != null)
            {
                try { opts.Cache.Save(); } catch (Exception) { }
            }
            summary.Cancelled = cancel.IsCancellationRequested;
            summary.ElapsedMs = sw.ElapsedMilliseconds;
            return summary;
        }

        /// <summary>Visita in profondità, senza seguire giunzioni e collegamenti (evita cicli).</summary>
        static void Walk(string root, Exclusions ex, CancellationToken cancel, BlockingCollection<string> paths, BlockingCollection<ScanResult> results)
        {
            if (File.Exists(root))
            {
                if (!ex.IsExcluded(root, false))
                    paths.Add(root);
                return;
            }
            if (!Directory.Exists(root) || ex.IsExcluded(root, true))
                return;
            var stack = new Stack<string>();
            stack.Push(root);
            while (stack.Count > 0)
            {
                if (cancel.IsCancellationRequested)
                    return;
                var dir = stack.Pop();
                FileSystemInfo[] items;
                try
                {
                    items = new DirectoryInfo(dir).GetFileSystemInfos();
                }
                catch (Exception e)
                {
                    results.Add(new ScanResult { Path = dir, Verdict = ScanEngine.IoErrorVerdict(e) });
                    continue;
                }
                var subdirs = new List<string>();
                foreach (var it in items)
                {
                    bool isDir = (it.Attributes & FileAttributes.Directory) != 0;
                    if ((it.Attributes & FileAttributes.ReparsePoint) != 0 && isDir)
                        continue;
                    if (ex.IsExcluded(it.FullName, isDir))
                        continue;
                    if (isDir)
                        subdirs.Add(it.FullName);
                    else
                        paths.Add(it.FullName);
                }
                // Al contrario, così le sottocartelle si visitano in ordine alfabetico.
                for (int i = subdirs.Count - 1; i >= 0; i--)
                    stack.Push(subdirs[i]);
            }
        }
    }
}
