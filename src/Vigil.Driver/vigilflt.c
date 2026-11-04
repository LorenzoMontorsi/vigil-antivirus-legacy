/*
 * vigilflt.sys - minifilter di autodifesa per Vigil Legacy
 *
 * Protegge la cartella del programma (Program Files\Vigil Legacy): nega scrittura, cancellazione,
 * rinomina e sovrascrittura dei file che vi si trovano, così un malware - o un amministratore -
 * non puo' rimuovere o sostituire l'antivirus mentre e' in esecuzione. Le aperture in sola lettura
 * ed esecuzione restano permesse (il servizio deve poter avviare i propri .exe).
 *
 * Senza stato in user mode: la cartella si riconosce dal nome ("\Vigil Legacy\") nel percorso
 * normalizzato del file, quindi vale su qualsiasi disco e non serve configurazione. Durante
 * l'installazione e la disinstallazione il driver viene scaricato (fltmc unload), così i file
 * possono essere scritti o rimossi.
 *
 * Compilazione: WDK 7.1.0 (build.exe), ambiente "x86 Free/Checked WXP" per Windows XP.
 * Gira su Windows XP SP3 e successivi a 32 bit (FltMgr presente da XP SP2). Per i sistemi a 64 bit
 * va ricompilato a 64 bit e, fuori dalla modalita' test-signing, firmato.
 *
 * Nota: niente annotazioni SAL "_In_/_Inout_" (il WDK 7.1 usa la SAL vecchia, "__in/__inout").
 */

#include <fltKernel.h>

/* Segmento di percorso che identifica la cartella protetta (confronto senza distinzione di maiuscole). */
static const WCHAR *const gProtectedSegments[] = {
    L"\\VIGIL LEGACY\\"
};

static PFLT_FILTER gFilter = NULL;

/* ---- utilita' ---- */

/* Confronto case-insensitive di un segmento dentro una stringa larga (come un wcsstr senza maiuscole). */
static BOOLEAN ContainsSegment(PCUNICODE_STRING name)
{
    USHORT i, j, s;
    USHORT nameChars = (USHORT)(name->Length / sizeof(WCHAR));

    for (s = 0; s < RTL_NUMBER_OF(gProtectedSegments); s++) {
        const WCHAR *seg = gProtectedSegments[s];
        USHORT segLen = 0;
        while (seg[segLen] != L'\0') segLen++;
        if (segLen == 0 || nameChars < segLen) continue;

        for (i = 0; i + segLen <= nameChars; i++) {
            BOOLEAN match = TRUE;
            for (j = 0; j < segLen; j++) {
                if (RtlUpcaseUnicodeChar(name->Buffer[i + j]) != RtlUpcaseUnicodeChar(seg[j])) {
                    match = FALSE;
                    break;
                }
            }
            if (match) return TRUE;
        }
    }
    return FALSE;
}

/* Vero se il file dell'operazione si trova nella cartella protetta. */
static BOOLEAN IsProtected(PFLT_CALLBACK_DATA Data)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;
    BOOLEAN result = FALSE;

    status = FltGetFileNameInformation(
        Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status)) {
        /* In pre-create il nome normalizzato puo' non essere ancora disponibile: non blocchiamo
         * (le scritture e le cancellazioni successive avvengono su file aperti e vengono comunque viste). */
        return FALSE;
    }

    (void)FltParseFileNameInformation(nameInfo);
    result = ContainsSegment(&nameInfo->Name);
    FltReleaseFileNameInformation(nameInfo);
    return result;
}

static FLT_PREOP_CALLBACK_STATUS Deny(PFLT_CALLBACK_DATA Data)
{
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

/* ---- callback ---- */

static FLT_PREOP_CALLBACK_STATUS PreCreate(
    PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext)
{
    ACCESS_MASK desired;
    ULONG options, disposition;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->RequestorMode == KernelMode)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    desired = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    options = Data->Iopb->Parameters.Create.Options;
    disposition = (options >> 24) & 0x000000ff;

    /* Interessano solo le aperture che possono modificare o eliminare. */
    if (!(desired & (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | WRITE_OWNER)) &&
        !(options & FILE_DELETE_ON_CLOSE) &&
        disposition != FILE_SUPERSEDE && disposition != FILE_OVERWRITE && disposition != FILE_OVERWRITE_IF)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (IsProtected(Data))
        return Deny(Data);

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static FLT_PREOP_CALLBACK_STATUS PreWrite(
    PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->RequestorMode == KernelMode)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (IsProtected(Data))
        return Deny(Data);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static FLT_PREOP_CALLBACK_STATUS PreSetInfo(
    PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext)
{
    FILE_INFORMATION_CLASS fic;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data->RequestorMode == KernelMode)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    fic = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    /* Cancellazione (FileDispositionInformation = 13, Ex = 64) e rinomina (FileRenameInformation = 10, Ex = 65). */
    if (fic != FileDispositionInformation && fic != FileRenameInformation &&
        (int)fic != 64 && (int)fic != 65)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;

    if (IsProtected(Data))
        return Deny(Data);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static const FLT_OPERATION_REGISTRATION gCallbacks[] = {
    { IRP_MJ_CREATE,          0, PreCreate,  NULL },
    { IRP_MJ_WRITE,           0, PreWrite,   NULL },
    { IRP_MJ_SET_INFORMATION, 0, PreSetInfo, NULL },
    { IRP_MJ_OPERATION_END }
};

static NTSTATUS Unload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    if (gFilter) {
        FltUnregisterFilter(gFilter);
        gFilter = NULL;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS InstanceSetup(
    PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_SETUP_FLAGS Flags,
    DEVICE_TYPE VolumeDeviceType, FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);
    /* Solo sui dischi (niente rete/CD): la cartella del programma e' su disco fisso. */
    if (VolumeDeviceType != FILE_DEVICE_DISK_FILE_SYSTEM)
        return STATUS_FLT_DO_NOT_ATTACH;
    return STATUS_SUCCESS;
}

/* Attenzione: su XP la FLT_REGISTRATION ha 13 campi (le versioni Longhorn+ ne hanno di piu'). */
static const FLT_REGISTRATION gRegistration = {
    sizeof(FLT_REGISTRATION),       /* Size */
    FLT_REGISTRATION_VERSION,       /* Version */
    0,                              /* Flags */
    NULL,                           /* ContextRegistration */
    gCallbacks,                     /* OperationRegistration */
    Unload,                         /* FilterUnloadCallback */
    InstanceSetup,                  /* InstanceSetupCallback */
    NULL,                           /* InstanceQueryTeardownCallback */
    NULL,                           /* InstanceTeardownStartCallback */
    NULL,                           /* InstanceTeardownCompleteCallback */
    NULL,                           /* GenerateFileNameCallback */
    NULL,                           /* NormalizeNameComponentCallback */
    NULL                            /* NormalizeContextCleanupCallback */
};

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    status = FltRegisterFilter(DriverObject, &gRegistration, &gFilter);
    if (!NT_SUCCESS(status))
        return status;

    status = FltStartFiltering(gFilter);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gFilter);
        gFilter = NULL;
    }
    return status;
}
