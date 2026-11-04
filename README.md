# Vigil Legacy

Antivirus open source per **Windows XP, Vista e 7** (e successivi), scritto in **C# / WPF su .NET Framework 4.0**.

È il fratello "legacy" di [Vigil](https://github.com/LorenzoMontorsi/vigil-antivirus) (Rust + Tauri): stesse idee, stesso aspetto, ma pensato per i sistemi che i prodotti moderni hanno abbandonato. Un po' più lento? Pazienza: l'importante è che giri.

> ⚠️ **Progetto sperimentale**, in sviluppo. Contributi benvenuti: il sorgente è tutto qui.

## Stato

| Funzione | Stato |
|---|---|
| Motore: hash SHA-256, EICAR, archivi ZIP annidati (anti zip-bomb), euristica PE | ✅ |
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
| Installer per XP/7 | 🛠️ da fare |

## Requisiti

- Windows XP SP3 o successivi, .NET Framework 4.0 (Client Profile non basta: serve il Framework completo).

## Compilare

Serve il .NET SDK moderno (8 o successivo) su Windows: compila per `net40` senza bisogno di Visual Studio 2010.

```powershell
.\scripts\fetch-clamav.ps1   # ClamAV legacy (versione fissata, SHA-256 verificato) in third_party\clamav
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
`\.\pipe\VigilLegacy.Service`. Sospendere la protezione, cambiare le esclusioni e ripristinare dalla quarantena
richiedono un amministratore (su Vista e successivi l'app chiede il consenso UAC).

## ClamAV su XP

Il ClamAV ufficiale non gira più su XP. Vigil Legacy usa il port win32 "legacy" di Gianluigi Tiesi
(progetto ClamWin, sorgenti su [github.com/clamwin/clamav-win32](https://github.com/clamwin/clamav-win32)),
che include OpenSSL e curl recenti: freshclam scarica le firme ufficiali anche dove il TLS di Windows XP non basta.
Le firme complete occupano circa 1 GB di RAM: su PC con poca memoria ClamAV si può spegnere dalle impostazioni.

## Licenza

GPL-3.0-or-later (vedi [LICENSE](LICENSE)).
