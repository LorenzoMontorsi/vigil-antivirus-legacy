# Vigil Legacy

Antivirus open source per **Windows XP, Vista e 7** (e successivi), scritto in **C# / WPF su .NET Framework 4.0**.

È il fratello "legacy" di [Vigil](https://github.com/LorenzoMontorsi/vigil-antivirus) (Rust + Tauri): stesse idee, stesso aspetto, ma pensato per i sistemi che i prodotti moderni hanno abbandonato. Un po' più lento? Pazienza: l'importante è che giri.

> ⚠️ **Progetto sperimentale**, in sviluppo. Contributi benvenuti: il sorgente è tutto qui.

## Stato

| Funzione | Stato |
|---|---|
| Motore: hash SHA-256, EICAR, archivi ZIP annidati (anti zip-bomb), euristica PE | ✅ |
| Classificazione delle minacce dai nomi delle firme (es. `Win.Trojan.Agent-123-0` → `Trojan:Win/Agent`, «Trojan · Windows · famiglia Agent») | ✅ |
| Verifica firme Authenticode (anche da catalogo, SHA-1 su XP / SHA-256 da Windows 8) | ✅ |
| Cache delle scansioni, esclusioni per percorso ed estensione | ✅ |
| Quarantena cifrata (AES-256 + HMAC-SHA256) con ripristino | ✅ |
| Client per ClamAV (`clamd`, comando INSTREAM) | ✅ |
| Interfaccia WPF (tema scuro "neon stripes" come Vigil): panoramica, scansione rapida/completa/personalizzata, quarantena, impostazioni, esclusioni | ✅ |
| ClamAV **legacy** incluso ([port win32 di Gianluigi Tiesi / ClamWin](https://oss.netfarm.it/clamav/), gira da XP): clamd + freshclam gestiti da Vigil | ✅ |
| Aggiornamento automatico periodico delle firme (intervallo configurabile) | ✅ |
| Icona nell'area di notifica con menu, avvio automatico all'accesso (nascosto) | ✅ |
| Avvisi in basso a destra con azioni (Metti in quarantena, Vedi i risultati, Ignora) | ✅ |
| «Analizza con Vigil» nel menu del tasto destro (file, cartelle, unità; selezioni multiple in un'unica scansione) | ✅ |
| Protezione in tempo reale: servizio `VigilLegacy` (SYSTEM) che analizza i file nuovi/modificati su tutti i dischi fissi e i programmi appena avviati (WMI), con quarantena e terminazione automatiche | ✅ provata in VM |
| Sospensione della protezione dal menu dell'icona (15 min, 1 h, 4 h, fino al riavvio), riservata agli amministratori | ✅ |
| Quarantena di sistema protetta (solo SYSTEM e amministratori), visibile e gestibile dall'app | ✅ |
| Installer unico (`VigilLegacySetup.exe`): installazione guidata o silenziosa, servizio, collegamenti, «Programmi e funzionalità», disinstallazione | ✅ provato in VM |

## Requisiti

- Windows XP SP3 o successivi (32 o 64 bit).
- .NET Framework 4.0 completo (il "Client Profile" non basta). Su Windows 7 e successivi di solito c'è già una 4.x;
  su XP va installato a parte (`dotNetFx40_Full_x86_x64.exe` di Microsoft).
- Per ClamAV con le firme complete: circa 1 GB di RAM libera. Su PC con meno memoria si può spegnere ClamAV:
  restano le firme di Vigil, l'euristica e la protezione in tempo reale.

## Installare

`VigilLegacySetup-<versione>.exe` (va eseguito da amministratore) installa tutto in `Program Files\Vigil Legacy`:
app, servizio della protezione in tempo reale e ClamAV legacy. Alla prima esecuzione il servizio scarica
le firme di ClamAV (circa 300 MB).

| Comando | Effetto |
|---|---|
| `VigilLegacySetup.exe` | installazione guidata |
| `VigilLegacySetup.exe /silent` | installazione senza finestre, opzioni predefinite (`/noservice` per non installare il servizio) |
| `VigilLegacySetup.exe /uninstall` | disinstallazione (anche da «Programmi e funzionalità») |
| `VigilLegacySetup.exe /uninstall /silent /removedata` | disinstallazione silenziosa, eliminando anche firme, quarantena e impostazioni |

## Compilare

Serve il .NET SDK moderno (8 o successivo) su Windows: compila per `net40` senza bisogno di Visual Studio 2010.

```powershell
.\scripts\fetch-clamav.ps1   # ClamAV legacy (versione fissata, SHA-256 verificato) in third_party\clamav
.\scripts\build-dist.ps1     # Release in dist\VigilLegacy e installer dist\VigilLegacySetup-<versione>.exe
dotnet build
dotnet test      # i test girano su .NET 4.8, il codice resta compatibile con 4.0
```

Regole per chi contribuisce: C# recente va bene, ma solo ciò che il compilatore traduce da sé.
**Niente** `async`/`await`, `Task.Run`, `ZipArchive`, `AesCryptoServiceProvider`, `HttpClient`: in .NET 4.0 o su XP non esistono.

## Protezione in tempo reale: come funziona (e i suoi limiti)

Vigil moderno usa un minifilter kernel; su XP un driver richiederebbe firme e strumenti di un'altra epoca.
Vigil Legacy usa invece un **servizio** (`VigilLegacySvc.exe`, account SYSTEM):

- **file**: `FileSystemWatcher` su ogni disco fisso; quando un file pericoloso per tipo (eseguibili, script, documenti
  con macro, archivi…) o qualsiasi eseguibile (intestazione `MZ`) viene scritto, il servizio aspetta che sia chiuso,
  lo analizza e, se infetto, lo mette in quarantena;
- **programmi**: evento WMI `Win32_ProcessStartTrace`; l'eseguibile di ogni processo avviato viene analizzato e,
  se infetto, il processo viene terminato e il file isolato.

Il limite onesto: il controllo avviene **subito dopo** la scrittura o l'avvio, non prima. Un programma infetto resta in
esecuzione per il tempo dell'analisi (di norma pochi millisecondi, grazie alla cache).

Il servizio gestisce anche ClamAV e gli aggiornamenti per tutto il PC; l'app comunica con lui tramite la named pipe
`\\.\pipe\VigilLegacy.Service`. Sospendere la protezione, cambiare le esclusioni e ripristinare dalla quarantena
richiedono un amministratore (su Vista e successivi l'app chiede il consenso UAC).

## ClamAV su XP

Il ClamAV ufficiale non gira più su XP. Vigil Legacy usa il port win32 "legacy" di Gianluigi Tiesi
(progetto ClamWin, sorgenti su [github.com/clamwin/clamav-win32](https://github.com/clamwin/clamav-win32)),
che include OpenSSL e curl recenti: freshclam scarica le firme ufficiali anche dove il TLS di Windows XP non basta.
Le firme complete occupano circa 1 GB di RAM: su PC con poca memoria ClamAV si può spegnere dalle impostazioni.

Struttura:

```
src/Vigil.Engine    motore (libreria net40): hash, ZIP, euristica PE, Authenticode, quarantena, client clamd, protocollo col servizio
src/Vigil.App       app WPF (VigilLegacy.exe)
src/Vigil.Service   servizio della protezione in tempo reale (VigilLegacySvc.exe)
src/Vigil.Setup     programma di installazione (un solo .exe con i file dentro)
tests/              test del motore (NUnit) e script di prova nella VM
scripts/            download di ClamAV, icona, build della distribuzione
```

## Licenza

GPL-3.0-or-later (vedi [LICENSE](LICENSE)).
