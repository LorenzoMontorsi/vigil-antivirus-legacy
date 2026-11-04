using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using Vigil.Engine;

namespace Vigil.App.Services
{
    /// <summary>
    /// Stato condiviso dell'applicazione: impostazioni, motore, quarantena, ClamAV, servizio.
    /// Gli eventi possono arrivare da thread di lavoro: chi aggiorna l'interfaccia
    /// deve passare dal Dispatcher.
    ///
    /// Se il servizio della protezione in tempo reale è installato, ClamAV e aggiornamenti
    /// sono suoi (dati per tutto il PC): l'app usa il suo clamd e gli chiede di aggiornare.
    /// Senza servizio l'app avvia un clamd proprio con dati per utente.
    /// </summary>
    public sealed class AppState
    {
        public static AppState Current { get; private set; }

        public Settings Settings { get; private set; }
        public AppStateFile Persisted { get; private set; }
        public Quarantine Quarantine { get; private set; }
        public ClamavManager Clamav { get; private set; }
        public Realtime Realtime { get; private set; }

        volatile ScanEngine engine = new ScanEngine();
        public ScanEngine Engine { get { return engine; } }

        public event Action Changed;
        public event Action<string> UpdateLog;

        int updating;
        public bool IsUpdating
        {
            get
            {
                var s = Realtime.Status;
                return updating != 0 || (s != null && s.Updating);
            }
        }

        /// <summary>Il servizio è installato e risponde.</summary>
        public bool ServiceMode { get { return Realtime.Available; } }

        AppState()
        {
            Directory.CreateDirectory(AppPaths.DataDir);
            Settings = Settings.Load();
            Persisted = AppStateFile.Load();
            Quarantine = new Quarantine(AppPaths.QuarantineDir);
            Clamav = new ClamavManager(AppPaths.ClamavDir, AppPaths.ClamavDbDir, AppPaths.DataDir, AppPaths.LogDir);
            Clamav.StatusChanged += RaiseChanged;
            Realtime = new Realtime();
            Realtime.Changed += RaiseChanged;
            Realtime.EventReceived += e =>
            {
                if (e.Kind == "update" && e.Detail != null)
                    Log(e.Detail);
            };
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

        /// <summary>Caricamento iniziale (in background): firme locali, servizio e ClamAV.</summary>
        public void StartBackground()
        {
            Realtime.Start();
            new Thread(() =>
            {
                ReloadSignatures();
                // Con il servizio installato ClamAV è suo, anche se in questo momento non risponde
                // (sta partendo): l'app non avvia mai un secondo clamd.
                bool service = ServiceInstalled() || RtProtocol.TryCall(RtRequest.Of("status")) != null;
                if (service)
                {
                    // ClamAV è del servizio: ci si collega appena ha caricato le firme.
                    while (!Clamav.Attach())
                        Thread.Sleep(5000);
                    return;
                }
                if (Settings.ClamavEnabled)
                    Clamav.Start();
                if (Settings.AutoUpdate && (IsUpdateDue() || (Settings.ClamavEnabled && !Clamav.HasDatabase && Clamav.IsInstalled)))
                    RunUpdate();
            }) { IsBackground = true, Name = "Vigil avvio" }.Start();

            // Pianificatore: ogni 15 minuti controlla se è ora di aggiornare (solo senza servizio).
            new Thread(() =>
            {
                while (true)
                {
                    Thread.Sleep(TimeSpan.FromMinutes(15));
                    if (!ServiceMode && Settings.AutoUpdate && IsUpdateDue())
                        RunUpdate();
                }
            }) { IsBackground = true, Name = "Vigil aggiornamenti" }.Start();
        }

        static bool ServiceInstalled()
        {
            try
            {
                return System.ServiceProcess.ServiceController.GetServices().Any(s => s.ServiceName == "VigilLegacy");
            }
            catch (Exception)
            {
                return false;
            }
        }

        public bool IsUpdateDue()
        {
            long age = FileUtil.NowUnix() - Persisted.LastUpdateUnix;
            return Persisted.LastUpdateUnix == 0 || age >= Settings.UpdateIntervalHours * 3600L;
        }

        /// <summary>Ultimo aggiornamento: del servizio se c'è, altrimenti dell'app.</summary>
        public long LastUpdateUnix
        {
            get { var s = Realtime.Status; return s != null ? s.LastUpdateUnix : Persisted.LastUpdateUnix; }
        }

        public bool LastUpdateOk
        {
            get { var s = Realtime.Status; return s != null ? s.LastUpdateOk : Persisted.LastUpdateOk; }
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
            if (ServiceMode)
            {
                // Lo fa il servizio; l'avanzamento arriva come eventi "update".
                var err = Realtime.Command(RtRequest.Of("update"));
                if (err != null) Log("Errore: " + err);
                return err == null;
            }
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
                if (Settings.ClamavEnabled && (Settings.YaraPackage ?? "none") != "none")
                {
                    Log("Regole YARA (" + Settings.YaraPackage + "): download da YARA-Forge…");
                    try
                    {
                        var rules = Feeds.FetchYaraForge(Settings.YaraPackage);
                        int n;
                        var yerr = Clamav.InstallYaraRules(rules, out n);
                        Persisted.Yara = yerr == null ? n + " regole (" + Settings.YaraPackage + ")" : "errore: " + yerr;
                        if (yerr != null) ok = false;
                        Log("Regole YARA: " + Persisted.Yara);
                        Clamav.AfterUpdate();
                    }
                    catch (Exception e)
                    {
                        ok = false;
                        Persisted.Yara = "errore: " + e.Message;
                        Log("Regole YARA: " + Persisted.Yara);
                    }
                }
                else if (Clamav.HasYaraRules)
                {
                    Clamav.RemoveYaraRules();
                    Persisted.Yara = null;
                }
                if (!string.IsNullOrEmpty(Settings.MalwareBazaarKey))
                {
                    Log("MalwareBazaar: download degli hash recenti…");
                    try
                    {
                        Persisted.MalwareBazaar = Feeds.UpdateMalwareBazaar(AppPaths.SignaturesDir, Settings.MalwareBazaarKey);
                        Log("MalwareBazaar: " + Persisted.MalwareBazaar);
                    }
                    catch (Exception e)
                    {
                        ok = false;
                        Persisted.MalwareBazaar = "errore: " + e.Message;
                        Log("MalwareBazaar: " + Persisted.MalwareBazaar);
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

        /// <summary>
        /// Invia le esclusioni al servizio (serve un amministratore: può comparire il consenso UAC).
        /// null se riuscito o se il servizio non c'è.
        /// </summary>
        public string PushExclusionsToService()
        {
            if (!ServiceMode)
                return null;
            return Realtime.Command(new RtRequest { Cmd = "exclusions", Exclusions = Settings.Exclusions });
        }

        /// <summary>Stato di MalwareBazaar: del servizio se c'è, altrimenti dell'app.</summary>
        public string MalwareBazaarStatus
        {
            get { var s = Realtime.Status; return s != null ? s.MalwareBazaar : Persisted.MalwareBazaar; }
        }

        /// <summary>Stato delle regole YARA: del servizio se c'è, altrimenti dell'app.</summary>
        public string YaraStatus
        {
            get { var s = Realtime.Status; return s != null ? s.Yara : Persisted.Yara; }
        }

        /// <summary>Attiva/disattiva l'autodifesa del driver (serve il servizio). null se riuscito.</summary>
        public string SetSelfProtection(bool on)
        {
            if (ServiceMode)
            {
                var err = Realtime.Command(new RtRequest { Cmd = "selfprotect", On = on });
                if (err != null) return err;
            }
            Settings.SelfProtection = on;
            SaveSettings();
            return null;
        }

        /// <summary>Imposta il pacchetto YARA (e lo passa al servizio). null se riuscito.</summary>
        public string SetYaraPackage(string package)
        {
            package = (package ?? "none").Trim();
            if (ServiceMode)
            {
                var err = Realtime.Command(new RtRequest { Cmd = "yara", Package = package });
                if (err != null) return err;
            }
            Settings.YaraPackage = package;
            SaveSettings();
            return null;
        }

        /// <summary>Salva la chiave di MalwareBazaar (e la passa al servizio). null se riuscito.</summary>
        public string SetMalwareBazaarKey(string key)
        {
            key = (key ?? "").Trim();
            if (key.Length > 0 && !Feeds.IsValidKey(key))
                return "chiave non valida";
            if (ServiceMode)
            {
                var err = Realtime.Command(new RtRequest { Cmd = "feeds", Key = key });
                if (err != null) return err;
            }
            Settings.MalwareBazaarKey = key;
            SaveSettings();
            return null;
        }

        /// <summary>Attiva/disattiva lo scudo anti-ransomware (serve il servizio; UAC se richiesto). null se riuscito.</summary>
        public string SetAntiRansomware(bool on)
        {
            if (ServiceMode)
            {
                var err = Realtime.Command(new RtRequest { Cmd = "antiransom", On = on });
                if (err != null) return err;
            }
            Settings.AntiRansomware = on;
            SaveSettings();
            return null;
        }

        /// <summary>Opzioni di scansione correnti, con ClamAV e cache se attivi.</summary>
        public ScanOptions BuildScanOptions()
        {
            var o = Settings.ToScanOptions();
            if ((Settings.ClamavEnabled || ServiceMode) && Clamav.IsReady)
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
            Clamav.Stop(); // spegne clamd solo se l'ha avviato l'app
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
