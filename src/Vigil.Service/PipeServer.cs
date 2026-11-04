using System;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using Vigil.Engine;

namespace Vigil.Service
{
    /// <summary>
    /// Pipe dei comandi per l'app. Tutti gli utenti autenticati possono leggere lo stato e gli eventi;
    /// sospendere la protezione, cambiare le esclusioni e ripristinare dalla quarantena richiedono
    /// un amministratore (su Vista e successivi: con privilegi elevati, cioè dopo il consenso UAC).
    /// </summary>
    sealed class PipeServer
    {
        const int Instances = 4;
        readonly ProtectionCore core;
        volatile bool stopping;

        public PipeServer(ProtectionCore core)
        {
            this.core = core;
        }

        public void Start()
        {
            for (int i = 0; i < Instances; i++)
                new Thread(Loop) { IsBackground = true, Name = "Vigil pipe" }.Start();
        }

        public void Stop()
        {
            stopping = true;
        }

        static PipeSecurity Security()
        {
            var sec = new PipeSecurity();
            // Gli utenti possono connettersi, non creare istanze della pipe (niente "pipe squatting").
            sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null),
                PipeAccessRights.ReadData | PipeAccessRights.WriteData | PipeAccessRights.ReadAttributes | PipeAccessRights.Synchronize, AccessControlType.Allow));
            sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
            sec.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
            return sec;
        }

        void Loop()
        {
            while (!stopping)
            {
                try
                {
                    using (var s = new NamedPipeServerStream(RtProtocol.PipeName, PipeDirection.InOut, Instances, PipeTransmissionMode.Byte, PipeOptions.None, 4096, 4096, Security()))
                    {
                        s.WaitForConnection();
                        var line = RtProtocol.ReadLine(s);
                        if (line == null)
                            continue;
                        RtResponse resp;
                        try
                        {
                            var req = Json.Deserialize<RtRequest>(line);
                            bool admin = false;
                            s.RunAsClient(() => admin = IsElevatedAdmin());
                            resp = Handle(req, admin);
                        }
                        catch (Exception e)
                        {
                            resp = RtResponse.Fail(e.Message);
                        }
                        RtProtocol.WriteLine(s, Json.Serialize(resp));
                        s.WaitForPipeDrain();
                    }
                }
                catch (Exception)
                {
                    Thread.Sleep(200);
                }
            }
        }

        /// <summary>Durante RunAsClient l'identità corrente è quella del client.</summary>
        static bool IsElevatedAdmin()
        {
            try
            {
                using (var id = WindowsIdentity.GetCurrent(true))
                    return id != null && new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch (Exception)
            {
                return false;
            }
        }

        RtResponse Handle(RtRequest req, bool admin)
        {
            var ok = new RtResponse { Ok = true };
            switch (req.Cmd)
            {
                case "status":
                    ok.Status = core.Status();
                    return ok;
                case "events":
                    ok.Status = core.Status();
                    ok.Events = req.Since < 0 ? new System.Collections.Generic.List<RtEvent>() : core.EventsSince(req.Since);
                    if (req.Since < 0)
                        ok.Events.Add(new RtEvent { Id = core.LastEventId, Kind = "cursor" });
                    return ok;
                case "update":
                    core.RunUpdateAsync();
                    return ok;
                case "quarantine_list":
                    ok.Items = core.Quarantine.List();
                    return ok;
            }
            if (!admin)
                return RtResponse.Fail("admin_required");
            switch (req.Cmd)
            {
                case "pause":
                    core.Pause(req.Minutes);
                    break;
                case "resume":
                    core.Resume();
                    break;
                case "exclusions":
                    core.Settings.Exclusions = req.Exclusions ?? new Exclusions();
                    core.SaveSettings();
                    core.Emit("info", null, null, "Esclusioni aggiornate (" + core.Settings.Exclusions.Paths.Count + " percorsi, " + core.Settings.Exclusions.Extensions.Count + " estensioni)", null);
                    break;
                case "quarantine_restore":
                    {
                        var dest = core.Quarantine.Restore(req.Id);
                        // Ripristinato da un amministratore: da non segnalare di nuovo.
                        if (!core.Settings.Exclusions.Paths.Contains(dest))
                            core.Settings.Exclusions.Paths.Add(dest);
                        core.SaveSettings();
                        core.Emit("info", dest, null, "Ripristinato dalla quarantena ed escluso", null);
                        break;
                    }
                case "quarantine_delete":
                    core.Quarantine.Delete(req.Id);
                    break;
                case "feeds":
                    {
                        var key = (req.Key ?? "").Trim();
                        if (key.Length > 0 && !Feeds.IsValidKey(key))
                            return RtResponse.Fail("chiave non valida");
                        bool changed = key != (core.Settings.MalwareBazaarKey ?? "");
                        core.Settings.MalwareBazaarKey = key;
                        if (changed) core.Settings.MalwareBazaar = null;
                        core.SaveSettings();
                        core.Emit("info", null, null, key.Length > 0 ? "MalwareBazaar attivato" : "MalwareBazaar disattivato", null);
                        if (changed && key.Length > 0)
                            core.RunUpdateAsync();
                        break;
                    }
                default:
                    return RtResponse.Fail("comando sconosciuto: " + req.Cmd);
            }
            ok.Status = core.Status();
            return ok;
        }
    }
}
