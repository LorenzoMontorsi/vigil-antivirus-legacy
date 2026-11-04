using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Runtime.Serialization;
using System.Security.Principal;
using System.Text;

namespace Vigil.Engine
{
    /// <summary>
    /// Protocollo tra l'app e il servizio della protezione in tempo reale.
    /// Una connessione = una richiesta e una risposta, entrambe una riga JSON (UTF-8).
    /// </summary>
    public static class RtProtocol
    {
        public const string PipeName = "VigilLegacy.Service";

        /// <summary>Invia una richiesta al servizio. Eccezione se non è in esecuzione o non risponde.</summary>
        public static RtResponse Call(RtRequest req, int timeoutMs = 3000)
        {
            // Solo i diritti concessi agli utenti dalla pipe del servizio: chiedere l'accesso "generico"
            // in scrittura includerebbe CreateNewInstance, che è negato, e la connessione fallirebbe.
            // Identification: il servizio può verificare chi chiama (amministratore o no), non agire per suo conto.
            using (var c = new NamedPipeClientStream(".", PipeName,
                PipeAccessRights.ReadData | PipeAccessRights.WriteData | PipeAccessRights.ReadAttributes | PipeAccessRights.Synchronize,
                PipeOptions.None, TokenImpersonationLevel.Identification, System.IO.HandleInheritability.None))
            {
                c.Connect(timeoutMs);
                WriteLine(c, Json.Serialize(req));
                var line = ReadLine(c);
                if (line == null)
                    throw new IOException("il servizio non ha risposto");
                return Json.Deserialize<RtResponse>(line);
            }
        }

        /// <summary>Come <see cref="Call"/>, ma null se il servizio non c'è.</summary>
        public static RtResponse TryCall(RtRequest req, int timeoutMs = 1500)
        {
            try { return Call(req, timeoutMs); }
            catch (Exception) { return null; }
        }

        public static void WriteLine(Stream s, string text)
        {
            var b = Encoding.UTF8.GetBytes(text.Replace("\n", " ") + "\n");
            s.Write(b, 0, b.Length);
            s.Flush();
        }

        /// <summary>Legge fino a '\n' (massimo 4 MB, contro client malevoli).</summary>
        public static string ReadLine(Stream s)
        {
            var ms = new MemoryStream();
            int b;
            while ((b = s.ReadByte()) >= 0)
            {
                if (b == '\n')
                    return Encoding.UTF8.GetString(ms.ToArray());
                ms.WriteByte((byte)b);
                if (ms.Length > 4 * 1024 * 1024)
                    throw new IOException("messaggio troppo lungo");
            }
            return ms.Length > 0 ? Encoding.UTF8.GetString(ms.ToArray()) : null;
        }
    }

    [DataContract]
    public sealed class RtRequest
    {
        /// <summary>status, events, pause, resume, update, exclusions, quarantine_list, quarantine_restore, quarantine_delete, rescan.</summary>
        [DataMember(Name = "cmd")] public string Cmd;

        /// <summary>pause: minuti (0 = fino al riavvio).</summary>
        [DataMember(Name = "minutes")] public int Minutes;

        /// <summary>events: restituisce gli eventi con id maggiore.</summary>
        [DataMember(Name = "since")] public long Since;

        /// <summary>quarantine_restore / quarantine_delete.</summary>
        [DataMember(Name = "id")] public string Id;

        [DataMember(Name = "exclusions")] public Exclusions Exclusions;
        /// <summary>Per "feeds": Auth-Key di MalwareBazaar (vuota = disattivato).</summary>
        [DataMember(Name = "key")] public string Key;

        public static RtRequest Of(string cmd)
        {
            return new RtRequest { Cmd = cmd };
        }
    }

    [DataContract]
    public sealed class RtStatus
    {
        [DataMember(Name = "version")] public string Version;
        [DataMember(Name = "active")] public bool Active;
        [DataMember(Name = "paused")] public bool Paused;
        /// <summary>Unix; 0 = sospesa fino al riavvio.</summary>
        [DataMember(Name = "paused_until")] public long PausedUntil;
        [DataMember(Name = "clamav")] public string Clamav;
        [DataMember(Name = "clamav_detail")] public string ClamavDetail;
        [DataMember(Name = "clamav_version")] public string ClamavVersion;
        [DataMember(Name = "files_scanned")] public long FilesScanned;
        [DataMember(Name = "processes_checked")] public long ProcessesChecked;
        [DataMember(Name = "threats")] public long Threats;
        [DataMember(Name = "signatures")] public int Signatures;
        [DataMember(Name = "updating")] public bool Updating;
        [DataMember(Name = "last_update_unix")] public long LastUpdateUnix;
        [DataMember(Name = "last_update_ok")] public bool LastUpdateOk;
        /// <summary>Monitoraggio dei processi disponibile (WMI).</summary>
        [DataMember(Name = "process_monitor")] public bool ProcessMonitor;
        [DataMember(Name = "watched_drives")] public List<string> WatchedDrives;
        [DataMember(Name = "quarantined")] public int Quarantined;
        [DataMember(Name = "malwarebazaar")] public string MalwareBazaar;
    }

    [DataContract]
    public sealed class RtEvent
    {
        [DataMember(Name = "id")] public long Id;
        [DataMember(Name = "time")] public long Time;
        /// <summary>file, process, update.</summary>
        [DataMember(Name = "kind")] public string Kind;
        [DataMember(Name = "path")] public string Path;
        [DataMember(Name = "threat")] public string Threat;
        /// <summary>quarantined, killed, failed, suspicious, info.</summary>
        [DataMember(Name = "action")] public string Action;
        [DataMember(Name = "detail")] public string Detail;
        [DataMember(Name = "quarantine_id")] public string QuarantineId;
    }

    [DataContract]
    public sealed class RtResponse
    {
        [DataMember(Name = "ok")] public bool Ok;
        [DataMember(Name = "error")] public string Error;
        [DataMember(Name = "status")] public RtStatus Status;
        [DataMember(Name = "events")] public List<RtEvent> Events;
        [DataMember(Name = "items")] public List<QuarantineItem> Items;

        public static RtResponse Fail(string error)
        {
            return new RtResponse { Ok = false, Error = error };
        }
    }
}
