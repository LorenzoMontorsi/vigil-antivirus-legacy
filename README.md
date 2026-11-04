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
| Interfaccia WPF | 🛠️ in corso |

## Requisiti

- Windows XP SP3 o successivi, .NET Framework 4.0 (Client Profile non basta: serve il Framework completo).

## Compilare

Serve il .NET SDK moderno (8 o successivo) su Windows: compila per `net40` senza bisogno di Visual Studio 2010.

```powershell
dotnet build
dotnet test      # i test girano su .NET 4.8, il codice resta compatibile con 4.0
```

Regole per chi contribuisce: C# recente va bene, ma solo ciò che il compilatore traduce da sé.
**Niente** `async`/`await`, `Task.Run`, `ZipArchive`, `AesCryptoServiceProvider`, `HttpClient`: in .NET 4.0 o su XP non esistono.

## Licenza

GPL-3.0-or-later (vedi [LICENSE](LICENSE)).
