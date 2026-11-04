@echo off
rem ============================================================================
rem  Abilita l'autodifesa a livello di driver sui Windows a 64 bit.
rem
rem  Windows a 64 bit carica solo driver firmati. Il driver di Vigil e' firmato
rem  con un certificato di PROVA: questo script lo rende fidato e mette il sistema
rem  in "test-signing", l'unico modo per caricare un driver autofirmato senza un
rem  certificato a pagamento. Sui sistemi a 32 bit NON serve: il driver si carica
rem  da solo.
rem
rem  Da eseguire UNA VOLTA, come amministratore. Poi riavviare il PC.
rem ============================================================================

net session >nul 2>&1
if errorlevel 1 (
  echo Esegui questo script come amministratore ^(tasto destro ^> Esegui come amministratore^).
  pause
  exit /b 1
)

echo Rendo fidato il certificato di prova del driver...
"%~dp0VigilLegacySvc.exe" --trust-cert "%~dp0VigilLegacyTest.cer"

echo Attivo la modalita' test-signing...
bcdedit /set testsigning on

echo.
echo Fatto. RIAVVIA il computer per attivare l'autodifesa del driver.
echo (In basso a destra comparira' la scritta "Modalita' test": e' normale.)
echo Per annullare: bcdedit /set testsigning off
echo.
pause
