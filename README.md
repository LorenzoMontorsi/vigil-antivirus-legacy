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
| Icona nell'area di notifica, avvisi, menu "Analizza con Vigil" | 🛠️ da fare |
| Protezione in tempo reale (servizio) | 🛠️ da fare |
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

## ClamAV su XP

Il ClamAV ufficiale non gira più su XP. Vigil Legacy usa il port win32 "legacy" di Gianluigi Tiesi
(progetto ClamWin, sorgenti su [github.com/clamwin/clamav-win32](https://github.com/clamwin/clamav-win32)),
che include OpenSSL e curl recenti: freshclam scarica le firme ufficiali anche dove il TLS di Windows XP non basta.
Le firme complete occupano circa 1 GB di RAM: su PC con poca memoria ClamAV si può spegnere dalle impostazioni.

## Licenza

GPL-3.0-or-later (vedi [LICENSE](LICENSE)).
