using System;
using System.IO;
using System.Runtime.Serialization;
using Vigil.Engine;

namespace Vigil.App.Services
{
    /// <summary>Cartelle dei dati. Su XP %APPDATA% è "Documents and Settings\utente\Dati applicazioni".</summary>
    public static class AppPaths
    {
        /// <summary>VIGIL_LEGACY_DATA sposta i dati altrove (sviluppo e test).</summary>
        public static readonly string DataDir = Environment.GetEnvironmentVariable("VIGIL_LEGACY_DATA")
            ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "VigilLegacy");
        public static readonly string AppDir = AppDomain.CurrentDomain.BaseDirectory;

        public static string SettingsFile { get { return Path.Combine(DataDir, "settings.json"); } }
        public static string StateFile { get { return Path.Combine(DataDir, "state.json"); } }
        public static string CacheFile { get { return Path.Combine(DataDir, "cache.bin"); } }
        public static string QuarantineDir { get { return Path.Combine(DataDir, "quarantine"); } }
        public static string SignaturesDir { get { return Path.Combine(DataDir, "signatures"); } }
        public static string ClamavDbDir { get { return Path.Combine(DataDir, "clamav-db"); } }
        public static string LogDir { get { return Path.Combine(DataDir, "logs"); } }
        public static string ClamavDir { get { return Path.Combine(AppDir, "clamav"); } }
    }

    [DataContract]
    public sealed class Settings
    {
        [DataMember(Name = "heuristics")] public bool Heuristics = true;
        [DataMember(Name = "scan_archives")] public bool ScanArchives = true;
        [DataMember(Name = "trust_microsoft")] public bool TrustMicrosoft = true;
        [DataMember(Name = "use_cache")] public bool UseCache = true;
        [DataMember(Name = "auto_quarantine")] public bool AutoQuarantine = false;
        [DataMember(Name = "max_file_size_mb")] public int MaxFileSizeMb = 64;

        /// <summary>Motore ClamAV (clamd). Con 512 MB di RAM o meno conviene spegnerlo.</summary>
        [DataMember(Name = "clamav_enabled")] public bool ClamavEnabled = true;

        /// <summary>Scudo anti-ransomware del servizio (file-esca + rilevamento delle ondate).</summary>
        [DataMember(Name = "anti_ransomware")] public bool AntiRansomware = true;

        /// <summary>Regole YARA caricate in ClamAV: "none" / "core" / "extended".</summary>
        [DataMember(Name = "yara_package")] public string YaraPackage = "none";

        [DataMember(Name = "auto_update")] public bool AutoUpdate = true;
        [DataMember(Name = "update_interval_hours")] public int UpdateIntervalHours = 4;
        [DataMember(Name = "exclusions")] public Exclusions Exclusions = new Exclusions();

        /// <summary>Auth-Key gratuita di abuse.ch per MalwareBazaar (vuota = disattivato).</summary>
        [DataMember(Name = "malwarebazaar_key")] public string MalwareBazaarKey = "";

        /// <summary>Avvia Vigil (nascosto nell'area di notifica) all'accesso a Windows.</summary>
        [DataMember(Name = "start_at_login")] public bool StartAtLogin = true;

        /// <summary>Voce "Analizza con Vigil" nel menu del tasto destro di Esplora risorse.</summary>
        [DataMember(Name = "context_menu")] public bool ContextMenu = true;

        [OnDeserializing]
        void Defaults(StreamingContext _)
        {
            // DataContractJsonSerializer non esegue gli inizializzatori: valori predefiniti
            // per i campi assenti nei file di versioni precedenti.
            Heuristics = ScanArchives = TrustMicrosoft = UseCache = ClamavEnabled = AutoUpdate = StartAtLogin = ContextMenu = true;
            AntiRansomware = true;
            YaraPackage = "none";
            MaxFileSizeMb = 64;
            UpdateIntervalHours = 4;
            Exclusions = new Exclusions();
        }

        public static Settings Load()
        {
            var s = Json.Load<Settings>(AppPaths.SettingsFile) ?? new Settings();
            if (s.Exclusions == null) s.Exclusions = new Exclusions();
            s.MaxFileSizeMb = Math.Max(1, Math.Min(1024, s.MaxFileSizeMb));
            s.UpdateIntervalHours = Math.Max(1, Math.Min(168, s.UpdateIntervalHours));
            return s;
        }

        public void Save()
        {
            Json.Save(AppPaths.SettingsFile, this);
        }

        public ScanOptions ToScanOptions()
        {
            return new ScanOptions
            {
                Heuristics = Heuristics,
                ScanArchives = ScanArchives,
                TrustMicrosoft = TrustMicrosoft,
                MaxFileSize = MaxFileSizeMb * 1024L * 1024,
                Exclusions = Exclusions.Clone(),
            };
        }
    }

    /// <summary>Informazioni da ricordare tra un avvio e l'altro.</summary>
    [DataContract]
    public sealed class AppStateFile
    {
        [DataMember(Name = "last_scan_unix")] public long LastScanUnix;
        [DataMember(Name = "last_scan_kind")] public string LastScanKind;
        [DataMember(Name = "last_scan_threats")] public long LastScanThreats;
        [DataMember(Name = "last_update_unix")] public long LastUpdateUnix;
        [DataMember(Name = "last_update_ok")] public bool LastUpdateOk;
        [DataMember(Name = "malwarebazaar")] public string MalwareBazaar;
        [DataMember(Name = "yara")] public string Yara;

        public static AppStateFile Load()
        {
            return Json.Load<AppStateFile>(AppPaths.StateFile) ?? new AppStateFile();
        }

        public void Save()
        {
            try { Json.Save(AppPaths.StateFile, this); } catch (Exception) { }
        }
    }
}
