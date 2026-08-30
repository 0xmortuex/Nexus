using System.Runtime.InteropServices;

namespace Nexus.App.Interop.Security;

/// <summary>
/// Raw WinVerifyTrust declarations. Nothing outside this folder calls these
/// directly — <see cref="AuthenticodeVerifier"/> wraps them with error handling.
/// </summary>
internal static class WinTrustNative
{
    internal static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
        new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    // ---- WINTRUST_DATA.dwUIChoice ----
    internal const uint WTD_UI_NONE = 2;

    // ---- WINTRUST_DATA.fdwRevocationChecks ----
    internal const uint WTD_REVOKE_NONE = 0;
    internal const uint WTD_REVOKE_WHOLECHAIN = 1;

    /// <summary>
    /// Identifies the catalog subsystem. Named for driver verification, but it is
    /// the context every catalog lookup uses, drivers or not.
    /// </summary>
    internal static readonly Guid DRIVER_ACTION_VERIFY =
        new("F750E6C3-38EE-11d1-85E5-00C04FC295EE");

    // ---- WINTRUST_DATA.dwUnionChoice ----
    internal const uint WTD_CHOICE_FILE = 1;
    internal const uint WTD_CHOICE_CATALOG = 2;

    // ---- WINTRUST_DATA.dwStateAction ----
    internal const uint WTD_STATEACTION_VERIFY = 1;
    internal const uint WTD_STATEACTION_CLOSE = 2;

    // ---- WINTRUST_DATA.dwProvFlags ----
    internal const uint WTD_SAFER_FLAG = 0x100;
    internal const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000;

    // ---- Return codes from WinVerifyTrust ----
    internal const int ERROR_SUCCESS = 0;
    internal const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);
    internal const int TRUST_E_BAD_DIGEST = unchecked((int)0x80096010);
    internal const int TRUST_E_PROVIDER_UNKNOWN = unchecked((int)0x800B0001);
    internal const int TRUST_E_SUBJECT_FORM_UNKNOWN = unchecked((int)0x800B0003);
    internal const int TRUST_E_SUBJECT_NOT_TRUSTED = unchecked((int)0x800B0004);
    internal const int TRUST_E_EXPLICIT_DISTRUST = unchecked((int)0x800B0111);
    internal const int CERT_E_EXPIRED = unchecked((int)0x800B0101);
    internal const int CERT_E_UNTRUSTEDROOT = unchecked((int)0x800B0109);
    internal const int CERT_E_CHAINING = unchecked((int)0x800B010A);
    internal const int CERT_E_REVOKED = unchecked((int)0x800B010C);
    internal const int CRYPT_E_SECURITY_SETTINGS = unchecked((int)0x80092026);
    internal const int CRYPT_E_FILE_ERROR = unchecked((int)0x80092003);

    [StructLayout(LayoutKind.Sequential)]
    internal struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    /// <summary>
    /// Describes a file being verified against a catalog rather than against a
    /// signature embedded in itself.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct WINTRUST_CATALOG_INFO
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszCatalogFilePath;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszMemberTag;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    internal const int MAX_PATH = 260;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct CATALOG_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
        public string wszCatalogFile;
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    internal static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

    // ---- Catalog lookup ----

    [DllImport("wintrust.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptCATAdminAcquireContext(
        out IntPtr phCatAdmin, ref Guid pgSubsystem, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptCATAdminCalcHashFromFileHandle(
        IntPtr hFile, ref uint pcbHash, byte[]? pbHash, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true, ExactSpelling = true)]
    internal static extern IntPtr CryptCATAdminEnumCatalogFromHash(
        IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint dwFlags, ref IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptCATAdminReleaseCatalogContext(
        IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptCATCatalogInfoFromContext(
        IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);
}
