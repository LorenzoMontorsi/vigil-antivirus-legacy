using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using Vigil.Engine;

namespace Vigil.App.Services
{
    /// <summary>
    /// Stato condiviso dell'applicazione: impostazioni, motore, quarantena, ClamAV.
    /// Gli eventi possono arrivare da thread di lavoro: chi aggiorna l'interfaccia
    /// deve passare dal Dispatcher.
    /// </summary>
    public sealed class AppState
    {
        public static AppState Current { get; private set; }

        public Settings Settings { get; private set; }
        public AppStateFile Persisted { get; private set; }
        public Quarantine Quarantine { get; private set; }
        public ClamavManager Clamav { get; private set; }

        volatile ScanEngine engine = new ScanEngine();
        public ScanEngine Engine { get { return engine; } }

        public event Action Changed;
        public event Action<string> UpdateLog;

        int updating;
        public bool IsUpdating { get { return updating != 0; } }

        AppState()
        {
            Directory.CreateDirectory(AppPaths.DataDir);
            Settings = Settings.Load();
            Persisted = AppStateFile.Load();
            Quarantine = new Quarantine(AppPaths.QuarantineDir);
            Clamav = new ClamavManager();
            Clamav.StatusChanged += RaiseChanged;
        }

        public static AppState Init()
        {
            Current = new AppState();
            return Current;
        }

        public void RaiseChanged()
        {
            var h = Changed;
            if (h != null) h();
        }

        /// <summary>Caricamento iniziale (in background): firme locali e ClamAV.</summary>
        public void StartBackground()
        {
            new Thread(() =>
            {
                ReloadSignatures();
                if (Settings.ClamavEnabled)
                    Clamav.Start();
                if (Settings.AutoUpdate && (IsUpdateDue() || (Settings.ClamavEnabled && !ClamavManager.HasDatabase && ClamavManager.IsInstalled)))
                    RunUpdate();
            }) { IsBackground = true, Name = "Vigil avvio" }.Start();

            // Pianificatore: ogni 15 minuti controlla se è ora di aggiornare.
            new Thread(() =>
            {
                while (true)
                {
                    Thread.Sleep(TimeSpan.FromMinutes(15));
                    if (Settings.AutoUpdate && IsUpdateDue())
                        RunUpdate();
                }
            }) { IsBackground = true, Name = "Vigil aggiornamenti" }.Start();
        }

        public bool IsUpdateDue()
        {
            long age = FileUtil.NowUnix() - Persisted.LastUpdateUnix;
            return Persisted.LastUpdateUnix == 0 || age >= Settings.UpdateIntervalHours * 3600L;
        }

        public void ReloadSignatures()
        {
            var e = new ScanEngine();
            e.LoadSignatureDir(AppPaths.SignaturesDir);
            engine = e;
            RaiseChanged();
        }

        void Log(string line)
        {
            var h = UpdateLog;
            if (h != null) h(line);
        }

        /// <summary>Aggiorna firme (bloccante). Se un aggiornamento è già in corso non fa nulla.</summary>
        public bool RunUpdate()
        {
            if (Interlocked.CompareExchange(ref updating, 1, 0) != 0)
                return false;
            RaiseChanged();
            bool ok = true;
            try
            {
                Log("Aggiornamento avviato");
                if (Settings.ClamavEnabled)
                {
                    Log("ClamAV: aggiornamento delle firme con freshclam…");
                    if (Clamav.UpdateDatabase(l => Log("ClamAV: " + l)))
                    {
                        Log("ClamAV: firme aggiornate");
                        Clamav.AfterUpdate();
                    }
                    else
                    {
                        ok = false;
                    }
                }
                ReloadSignatures();
                Log(ok ? "Aggiornamento completato" : "Aggiornamento completato con errori");
            }
            catch (Exception e)
            {
                ok = false;
                Log("Errore: " + e.Message);
            }
            finally
            {
                Persisted.LastUpdateUnix = FileUtil.NowUnix();
                Persisted.LastUpdateOk = ok;
                Persisted.Save();
                updating = 0;
                RaiseChanged();
            }
            return ok;
        }

        public void RunUpdateAsync()
        {
            new Thread(() => RunUpdate()) { IsBackground = true, Name = "Vigil aggiornamento" }.Start();
        }

        public void SaveSettings()
        {
            try { Settings.Save(); } catch (Exception) { }
            RaiseChanged();
        }

        /// <summary>Opzioni di scansione correnti, con ClamAV e cache se attivi.</summary>
        public ScanOptions BuildScanOptions()
        {
            var o = Settings.ToScanOptions();
            if (Settings.ClamavEnabled && Clamav.IsReady)
                o.Clamd = Clamav.Client;
            if (Settings.UseCache)
                o.Cache = new ScanCache(AppPaths.CacheFile, Engine.Generation(o, o.Clamd != null ? Clamav.VersionText : null));
            return o;
        }

        public void ClearCache()
        {
            try { File.Delete(AppPaths.CacheFile); } catch (Exception) { }
        }

        public void Shutdown()
        {
            Clamav.Stop();
        }

        /// <summary>Cartelle della scansione rapida: dove di solito arriva e si avvia il malware.</summary>
        public static List<string> QuickScanRoots()
        {
            var roots = new List<string>();
            Action<string> add = p =>
            {
                if (!string.IsNullOrEmpty(p) && Directory.Exists(p) && !roots.Exists(r => string.Equals(r, p, StringComparison.OrdinalIgnoreCase)))
                    roots.Add(p);
            };
            var profile = Environment.GetEnvironmentVariable("USERPROFILE");
            add(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory));
            add(profile != null ? Path.Combine(profile, "Downloads") : null);
            add(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments));
            add(Environment.GetFolderPath(Environment.SpecialFolder.Startup));
            add(Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup));
            add(Path.GetTempPath());
            add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Temp"));
            add(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
            add(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
            return roots;
        }

        public static List<string> FullScanRoots()
        {
            var roots = new List<string>();
            foreach (var d in DriveInfo.GetDrives())
            {
                try
                {
                    if (d.DriveType == DriveType.Fixed && d.IsReady)
                        roots.Add(d.RootDirectory.FullName);
                }
                catch (Exception) { }
            }
            return roots;
        }
    }
}
