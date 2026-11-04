using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;

namespace Vigil.Engine
{
    /// <summary>
    /// Verifica delle firme Authenticode tramite WinVerifyTrust.
    /// Gestisce sia la firma incorporata nel file sia quella tramite catalogo (.cat),
    /// che è il caso della maggior parte dei file di sistema di Windows.
    /// Il controllo di revoca usa solo la cache locale: nessuna richiesta di rete.
    /// Su XP esiste solo l'API dei cataloghi SHA-1; da Windows 8 si prova anche SHA-256.
    /// </summary>
    public static class Trust
    {
        /// <summary>Firmatari considerati affidabili per saltare i controlli più costosi.</summary>
        public static bool IsMicrosoft(string signer)
        {
            return signer != null && signer.StartsWith("Microsoft ", StringComparison.Ordinal);
        }

        /// <summary>Nome del firmatario se il file ha una firma valida che risale a una CA fidata.</summary>
        public static string Signer(string path)
        {
            try
            {
                if (VerifyEmbedded(path))
                    return SubjectOf(path);
                var catalog = VerifyCatalog(path);
                return catalog != null ? SubjectOf(catalog) : null;
            }
            catch (Exception)
            {
                return null;
            }
        }

        static string SubjectOf(string signedFile)
        {
            try
            {
                // In .NET 4.0 i certificati non sono IDisposable: niente using.
                var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(signedFile));
                return cert.GetNameInfo(X509NameType.SimpleName, false);
            }
            catch (Exception)
            {
                return null;
            }
        }

        static bool VerifyEmbedded(string path)
        {
            var file = new WINTRUST_FILE_INFO { cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)), pcwszFilePath = path };
            IntPtr pFile = Marshal.AllocHGlobal(Marshal.SizeOf(file));
            try
            {
                Marshal.StructureToPtr(file, pFile, false);
                return Verify(WTD_CHOICE_FILE, pFile);
            }
            finally
            {
                Marshal.DestroyStructure(pFile, typeof(WINTRUST_FILE_INFO));
                Marshal.FreeHGlobal(pFile);
            }
        }

        /// <summary>Percorso del catalogo che firma il file, se la firma è valida.</summary>
        static string VerifyCatalog(string path)
        {
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                var h = fs.SafeFileHandle;
                // I cataloghi moderni usano SHA-256 (solo Windows 8+), quelli più vecchi SHA-1.
                return VerifyCatalogWith(h, path, "SHA256") ?? VerifyCatalogWith(h, path, null);
            }
        }

        static string VerifyCatalogWith(SafeFileHandle file, string path, string alg)
        {
            IntPtr admin;
            try
            {
                bool ok = alg != null
                    ? CryptCATAdminAcquireContext2(out admin, IntPtr.Zero, alg, IntPtr.Zero, 0)
                    : CryptCATAdminAcquireContext(out admin, IntPtr.Zero, 0);
                if (!ok)
                    return null;
            }
            catch (EntryPointNotFoundException)
            {
                return null; // Windows XP/Vista/7: niente API SHA-256
            }
            try
            {
                var hash = new byte[64];
                uint len = (uint)hash.Length;
                bool hashed = alg != null
                    ? CryptCATAdminCalcHashFromFileHandle2(admin, file, ref len, hash, 0)
                    : CryptCATAdminCalcHashFromFileHandle(file, ref len, hash, 0);
                if (!hashed)
                    return null;
                IntPtr prev = IntPtr.Zero;
                IntPtr cat = CryptCATAdminEnumCatalogFromHash(admin, hash, len, 0, ref prev);
                if (cat == IntPtr.Zero)
                    return null;
                try
                {
                    var info = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf(typeof(CATALOG_INFO)) };
                    if (!CryptCATCatalogInfoFromContext(cat, ref info, 0))
                        return null;
                    var tag = new System.Text.StringBuilder();
                    for (int i = 0; i < len; i++)
                        tag.Append(hash[i].ToString("X2"));
                    IntPtr pHash = Marshal.AllocHGlobal((int)len);
                    Marshal.Copy(hash, 0, pHash, (int)len);
                    var ci = new WINTRUST_CATALOG_INFO
                    {
                        cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_CATALOG_INFO)),
                        pcwszCatalogFilePath = info.wszCatalogFile,
                        pcwszMemberTag = tag.ToString(),
                        pcwszMemberFilePath = path,
                        hMemberFile = file.DangerousGetHandle(),
                        pbCalculatedFileHash = pHash,
                        cbCalculatedFileHash = len,
                        hCatAdmin = admin,
                    };
                    IntPtr pCi = Marshal.AllocHGlobal(Marshal.SizeOf(ci));
                    try
                    {
                        Marshal.StructureToPtr(ci, pCi, false);
                        return Verify(WTD_CHOICE_CATALOG, pCi) ? info.wszCatalogFile : null;
                    }
                    finally
                    {
                        Marshal.DestroyStructure(pCi, typeof(WINTRUST_CATALOG_INFO));
                        Marshal.FreeHGlobal(pCi);
                        Marshal.FreeHGlobal(pHash);
                    }
                }
                finally
                {
                    CryptCATAdminReleaseCatalogContext(admin, cat, 0);
                }
            }
            finally
            {
                CryptCATAdminReleaseContext(admin, 0);
            }
        }

        static bool Verify(uint unionChoice, IntPtr info)
        {
            var action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA)),
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_NONE,
                dwUnionChoice = unionChoice,
                pInfo = info,
                dwStateAction = WTD_STATEACTION_VERIFY,
                dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL,
            };
            int r = WinVerifyTrust(new IntPtr(-1), ref action, ref data);
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(new IntPtr(-1), ref action, ref data);
            return r == 0;
        }

        // ---- interop ----

        static Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
        const uint WTD_UI_NONE = 2, WTD_REVOKE_NONE = 0, WTD_CHOICE_FILE = 1, WTD_CHOICE_CATALOG = 2;
        const uint WTD_STATEACTION_VERIFY = 1, WTD_STATEACTION_CLOSE = 2, WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct WINTRUST_CATALOG_INFO
        {
            public uint cbStruct;
            public uint dwCatalogVersion;
            public string pcwszCatalogFilePath;
            public string pcwszMemberTag;
            public string pcwszMemberFilePath;
            public IntPtr hMemberFile;
            public IntPtr pbCalculatedFileHash;
            public uint cbCalculatedFileHash;
            public IntPtr pcCatalogContext;
            public IntPtr hCatAdmin; // Windows 8+: ignorato dalle versioni precedenti
        }

        // Senza pSignatureSettings (Windows 8+): la dimensione "vecchia" va bene ovunque, XP compreso.
        [StructLayout(LayoutKind.Sequential)]
        struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pInfo;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct CATALOG_INFO
        {
            public uint cbStruct;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string wszCatalogFile;
        }

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
        static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WINTRUST_DATA data);

        [DllImport("wintrust.dll", SetLastError = true)]
        static extern bool CryptCATAdminAcquireContext(out IntPtr admin, IntPtr subsystem, uint flags);

        [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CryptCATAdminAcquireContext2(out IntPtr admin, IntPtr subsystem, string hashAlgorithm, IntPtr strongHashPolicy, uint flags);

        [DllImport("wintrust.dll", SetLastError = true)]
        static extern bool CryptCATAdminCalcHashFromFileHandle(SafeFileHandle file, ref uint hashLen, byte[] hash, uint flags);

        [DllImport("wintrust.dll", SetLastError = true)]
        static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr admin, SafeFileHandle file, ref uint hashLen, byte[] hash, uint flags);

        [DllImport("wintrust.dll", SetLastError = true)]
        static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr admin, byte[] hash, uint hashLen, uint flags, ref IntPtr prevCatInfo);

        [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CryptCATCatalogInfoFromContext(IntPtr catInfo, ref CATALOG_INFO info, uint flags);

        [DllImport("wintrust.dll")]
        static extern bool CryptCATAdminReleaseCatalogContext(IntPtr admin, IntPtr catInfo, uint flags);

        [DllImport("wintrust.dll")]
        static extern bool CryptCATAdminReleaseContext(IntPtr admin, uint flags);
    }
}
