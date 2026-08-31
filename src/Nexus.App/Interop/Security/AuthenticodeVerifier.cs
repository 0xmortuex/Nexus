using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Nexus.Core.Logging;
using Nexus.Core.Security;

namespace Nexus.App.Interop.Security;

/// <summary>What Windows thinks of a file's signature.</summary>
public enum SignatureState
{
    /// <summary>No embedded signature and no catalog entry.</summary>
    Unsigned,

    /// <summary>Signed, and the whole chain verifies against a trusted root.</summary>
    Valid,

    /// <summary>Signed, but the bytes no longer match the signature — the file was
    /// modified after it was signed.</summary>
    Tampered,

    /// <summary>Chains to a root this machine does not trust (including self-signed).</summary>
    UntrustedRoot,

    /// <summary>The signing certificate has expired and there is no valid countersignature.</summary>
    Expired,

    /// <summary>The signing certificate was revoked by its issuer.</summary>
    Revoked,

    /// <summary>Explicitly distrusted on this machine.</summary>
    Distrusted,

    /// <summary>The file could not be read or the check could not run.</summary>
    Unknown,
}

/// <summary>The full signing picture for one file.</summary>
public sealed record SignatureInfo
{
    public required SignatureState State { get; init; }

    /// <summary>Common name of the signer, e.g. "Valve Corp.".</summary>
    public string? SignerName { get; init; }

    public string? IssuerName { get; init; }

    /// <summary>True when the signer is Microsoft. Treated as the strongest
    /// exoneration Sentinel offers, because it covers most of the OS.</summary>
    public bool IsMicrosoft { get; init; }

    public DateTimeOffset? NotAfter { get; init; }

    public static SignatureInfo Unknown => new() { State = SignatureState.Unknown };
}

/// <summary>
/// Verifies Authenticode signatures via WinVerifyTrust, and translates the result
/// into signals.
///
/// The weighting here is deliberately asymmetric, because the two failure modes are
/// not equivalent:
///
/// - <b>Unsigned</b> is weak evidence at most. Certificates cost money; most indie
///   software, most build output, and most of this user's own tools are unsigned.
///   Treating "unsigned" as "suspicious" is how security tools become noise.
/// - <b>Tampered</b> is strong evidence. Someone signed this file and then the bytes
///   changed. There is no innocent version of that.
/// </summary>
public sealed class AuthenticodeVerifier
{
    private readonly ActivityLog _log;
    private readonly bool _checkRevocation;

    /// <summary>
    /// The catalog context, one per thread, acquired on that thread's first use.
    ///
    /// Acquiring it per file is pure overhead — measured at 7.1ms against 5.2ms
    /// reused, over 120 System32 binaries — because the handle is onto the machine's
    /// catalog store, which does not change between two files.
    ///
    /// It is per-thread rather than shared because sharing one across threads is not
    /// safe, and the way it fails is quiet: verifying 200 drivers on eight threads
    /// returned Unsigned for two files that verify as Valid on one thread. A
    /// signature check that intermittently says "unsigned" about a signed Windows
    /// driver manufactures exactly the false positives this whole module exists to
    /// avoid, so the caching had to become thread-local rather than shared.
    ///
    /// Bounded by the number of scanning threads, and released on
    /// <see cref="ReleaseCatalogContexts"/> at shutdown.
    /// </summary>
    private static readonly ThreadLocal<IntPtr> _catalogAdmin = new(trackAllValues: true);

    private static bool _catalogUnavailable;

    /// <param name="checkRevocation">Revocation checking is accurate but reaches the
    /// network and can stall for seconds on a captive portal. Off by default, so a
    /// background scan never blocks on someone else's OCSP responder.</param>
    public AuthenticodeVerifier(ActivityLog log, bool checkRevocation = false)
    {
        _log = log;
        _checkRevocation = checkRevocation;
    }

    public SignatureInfo Verify(string filePath)
    {
        if (!OperatingSystem.IsWindows())
            return SignatureInfo.Unknown;

        if (!File.Exists(filePath))
            return SignatureInfo.Unknown;

        var state = RunWinVerifyTrust(filePath);

        // "Signed, but the bytes no longer match" is the single heaviest thing this
        // class can say: it scores 35 on its own, which is enough to raise an alert
        // with no other evidence at all. It is worth being sure.
        //
        // On a real machine three Microsoft-signed Windows printer scripts were
        // reported as tampered, and could not be reproduced afterwards on any
        // subsequent check, elevated or not. Whatever the cause -- a file being
        // rewritten by an update mid-read is the likeliest -- a verdict that
        // accusatory should not rest on a single reading. A second look costs
        // milliseconds and only happens on the rare path.
        if (state == SignatureState.Tampered)
        {
            var second = RunWinVerifyTrust(filePath);

            if (second != SignatureState.Tampered)
            {
                _log.Info("Sentinel",
                    $"{Path.GetFileName(filePath)} looked modified on the first check and did not on " +
                    $"the second, so it is being reported as {second} rather than tampered with.");

                state = second;
            }
        }

        string? catalogPath = null;

        // Most of Windows carries no signature of its own. System files are signed in
        // bulk through catalog (.cat) files, and asking WinVerifyTrust about the file
        // alone returns "no signature" for notepad.exe, svchost.exe and explorer.exe
        // alike. Without this fallback the strongest exoneration Nexus has —
        // "signed by Microsoft" — never fires for the operating system, and every
        // full scan reports thousands of Windows files as unsigned.
        if (state == SignatureState.Unsigned)
        {
            var (catalogState, foundIn) = VerifyThroughCatalog(filePath);
            if (catalogState != SignatureState.Unsigned)
            {
                state = catalogState;
                catalogPath = foundIn;
            }
        }

        var (signer, issuer, notAfter) = catalogPath is null
            ? ReadCertificate(filePath)
            : ReadCertificate(catalogPath);

        return new SignatureInfo
        {
            State = state,
            SignerName = signer,
            IssuerName = issuer,
            NotAfter = notAfter,
            IsMicrosoft = state == SignatureState.Valid && LooksLikeMicrosoft(signer),
        };
    }

    private SignatureState RunWinVerifyTrust(string filePath)
    {
        var fileInfo = new WinTrustNative.WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WinTrustNative.WINTRUST_FILE_INFO>(),
            pcwszFilePath = filePath,
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero,
        };

        IntPtr fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf(fileInfo));
        try
        {
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, fDeleteOld: false);

            var data = new WINTRUST_DATA_Builder(fileInfoPtr, _checkRevocation).Build();
            var action = WinTrustNative.WINTRUST_ACTION_GENERIC_VERIFY_V2;

            int result = WinTrustNative.WinVerifyTrust(IntPtr.Zero, ref action, ref data);

            // The verify call allocates state that must be released with a second
            // call, whatever the first one returned.
            data.dwStateAction = WinTrustNative.WTD_STATEACTION_CLOSE;
            WinTrustNative.WinVerifyTrust(IntPtr.Zero, ref action, ref data);

            return Map(result);
        }
        catch (Exception ex) when (ex is SEHException or EntryPointNotFoundException or DllNotFoundException)
        {
            _log.Warn("Sentinel", $"Signature check failed for {Path.GetFileName(filePath)}: {ex.Message}");
            return SignatureState.Unknown;
        }
        finally
        {
            Marshal.DestroyStructure<WinTrustNative.WINTRUST_FILE_INFO>(fileInfoPtr);
            Marshal.FreeHGlobal(fileInfoPtr);
        }
    }

    /// <summary>
    /// Look the file's hash up in the system catalogs and, if it is a member of one,
    /// verify it against that catalog.
    ///
    /// Returns the catalog's path as well, because the signer has to be read from the
    /// .cat file — the file itself contains no certificate to read.
    /// </summary>
    private (SignatureState State, string? CatalogPath) VerifyThroughCatalog(string filePath)
    {
        IntPtr catalogAdmin = IntPtr.Zero;
        IntPtr catalogContext = IntPtr.Zero;
        FileStream? file = null;

        try
        {
            catalogAdmin = AcquireCatalogContext();
            if (catalogAdmin == IntPtr.Zero)
                return (SignatureState.Unsigned, null);

            file = new FileStream(filePath, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            IntPtr handle = file.SafeFileHandle.DangerousGetHandle();

            // Ask for the hash length first, then for the hash itself.
            uint hashLength = 0;
            WinTrustNative.CryptCATAdminCalcHashFromFileHandle(handle, ref hashLength, null, 0);
            if (hashLength == 0)
                return (SignatureState.Unsigned, null);

            var hash = new byte[hashLength];
            if (!WinTrustNative.CryptCATAdminCalcHashFromFileHandle(handle, ref hashLength, hash, 0))
                return (SignatureState.Unsigned, null);

            IntPtr previous = IntPtr.Zero;
            catalogContext = WinTrustNative.CryptCATAdminEnumCatalogFromHash(
                catalogAdmin, hash, hashLength, 0, ref previous);

            // Not a member of any catalog. Genuinely unsigned, as far as Windows knows.
            if (catalogContext == IntPtr.Zero)
                return (SignatureState.Unsigned, null);

            var info = new WinTrustNative.CATALOG_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustNative.CATALOG_INFO>(),
                wszCatalogFile = "",
            };

            if (!WinTrustNative.CryptCATCatalogInfoFromContext(catalogContext, ref info, 0))
                return (SignatureState.Unsigned, null);

            return (RunCatalogVerify(filePath, info.wszCatalogFile, hash), info.wszCatalogFile);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                                      or SEHException or EntryPointNotFoundException or DllNotFoundException)
        {
            return (SignatureState.Unsigned, null);
        }
        finally
        {
            file?.Dispose();

            // The per-file catalog context is released; the admin context is shared
            // and lives for the process.
            if (catalogContext != IntPtr.Zero && catalogAdmin != IntPtr.Zero)
                WinTrustNative.CryptCATAdminReleaseCatalogContext(catalogAdmin, catalogContext, 0);
        }
    }

    /// <summary>
    /// The shared catalog context, created on first use.
    ///
    /// Returns zero when catalogs are unavailable on this machine, and remembers that
    /// so every later file skips the attempt instead of paying for it again.
    /// </summary>
    private static IntPtr AcquireCatalogContext()
    {
        if (_catalogUnavailable)
            return IntPtr.Zero;

        if (_catalogAdmin.Value != IntPtr.Zero)
            return _catalogAdmin.Value;

        var subsystem = WinTrustNative.DRIVER_ACTION_VERIFY;

        if (WinTrustNative.CryptCATAdminAcquireContext(out var admin, ref subsystem, 0)
            && admin != IntPtr.Zero)
        {
            _catalogAdmin.Value = admin;
            return admin;
        }

        // Catalogs are unavailable on this machine at all; remember it so every later
        // file skips the attempt rather than paying for it again.
        _catalogUnavailable = true;
        return IntPtr.Zero;
    }

    /// <summary>
    /// Release every thread's catalog context. Called once at shutdown; these are
    /// handles onto a machine resource and there is no reason to leave them to the
    /// process teardown.
    /// </summary>
    public static void ReleaseCatalogContexts()
    {
        foreach (var admin in _catalogAdmin.Values)
        {
            if (admin != IntPtr.Zero)
                WinTrustNative.CryptCATAdminReleaseContext(admin, 0);
        }
    }

    /// <summary>Verify one file against one catalog. The member tag is the file's
    /// hash as an uppercase hex string; that is the form the catalog indexes by.</summary>
    private SignatureState RunCatalogVerify(string filePath, string catalogPath, byte[] hash)
    {
        IntPtr hashBuffer = Marshal.AllocHGlobal(hash.Length);
        IntPtr catalogInfoPtr = IntPtr.Zero;

        try
        {
            Marshal.Copy(hash, 0, hashBuffer, hash.Length);

            var catalogInfo = new WinTrustNative.WINTRUST_CATALOG_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustNative.WINTRUST_CATALOG_INFO>(),
                dwCatalogVersion = 0,
                pcwszCatalogFilePath = catalogPath,
                pcwszMemberTag = Convert.ToHexString(hash),
                pcwszMemberFilePath = filePath,
                hMemberFile = IntPtr.Zero,
                pbCalculatedFileHash = hashBuffer,
                cbCalculatedFileHash = (uint)hash.Length,
                pcCatalogContext = IntPtr.Zero,
                hCatAdmin = IntPtr.Zero,
            };

            catalogInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf(catalogInfo));
            Marshal.StructureToPtr(catalogInfo, catalogInfoPtr, fDeleteOld: false);

            var data = new WinTrustNative.WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustNative.WINTRUST_DATA>(),
                dwUIChoice = WinTrustNative.WTD_UI_NONE,
                fdwRevocationChecks = _checkRevocation
                    ? WinTrustNative.WTD_REVOKE_WHOLECHAIN
                    : WinTrustNative.WTD_REVOKE_NONE,
                dwUnionChoice = WinTrustNative.WTD_CHOICE_CATALOG,
                pFile = catalogInfoPtr,
                dwStateAction = WinTrustNative.WTD_STATEACTION_VERIFY,
                dwProvFlags = WinTrustNative.WTD_CACHE_ONLY_URL_RETRIEVAL,
            };

            var action = WinTrustNative.WINTRUST_ACTION_GENERIC_VERIFY_V2;
            int result = WinTrustNative.WinVerifyTrust(IntPtr.Zero, ref action, ref data);

            data.dwStateAction = WinTrustNative.WTD_STATEACTION_CLOSE;
            WinTrustNative.WinVerifyTrust(IntPtr.Zero, ref action, ref data);

            return Map(result);
        }
        catch (Exception ex) when (ex is SEHException or EntryPointNotFoundException or DllNotFoundException)
        {
            _log.Warn("Sentinel", $"Catalog check failed for {Path.GetFileName(filePath)}: {ex.Message}");
            return SignatureState.Unsigned;
        }
        finally
        {
            if (catalogInfoPtr != IntPtr.Zero)
            {
                Marshal.DestroyStructure<WinTrustNative.WINTRUST_CATALOG_INFO>(catalogInfoPtr);
                Marshal.FreeHGlobal(catalogInfoPtr);
            }

            Marshal.FreeHGlobal(hashBuffer);
        }
    }

    private static SignatureState Map(int hresult) => hresult switch
    {
        WinTrustNative.ERROR_SUCCESS => SignatureState.Valid,
        WinTrustNative.TRUST_E_NOSIGNATURE => SignatureState.Unsigned,
        WinTrustNative.TRUST_E_SUBJECT_FORM_UNKNOWN => SignatureState.Unsigned,
        WinTrustNative.TRUST_E_PROVIDER_UNKNOWN => SignatureState.Unsigned,
        WinTrustNative.TRUST_E_BAD_DIGEST => SignatureState.Tampered,
        WinTrustNative.CERT_E_EXPIRED => SignatureState.Expired,
        WinTrustNative.CERT_E_UNTRUSTEDROOT => SignatureState.UntrustedRoot,
        WinTrustNative.CERT_E_CHAINING => SignatureState.UntrustedRoot,
        WinTrustNative.TRUST_E_SUBJECT_NOT_TRUSTED => SignatureState.UntrustedRoot,
        WinTrustNative.CERT_E_REVOKED => SignatureState.Revoked,
        WinTrustNative.TRUST_E_EXPLICIT_DISTRUST => SignatureState.Distrusted,
        _ => SignatureState.Unknown,
    };

    private (string? Signer, string? Issuer, DateTimeOffset? NotAfter) ReadCertificate(string filePath)
    {
        try
        {
            // Reads the Authenticode signer out of the file; throws for unsigned files.
            using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(filePath));
            return (
                certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false),
                certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: true),
                new DateTimeOffset(certificate.NotAfter.ToUniversalTime(), TimeSpan.Zero));
        }
        catch (Exception ex) when (ex is CryptographicException or IOException or UnauthorizedAccessException)
        {
            // Unsigned files land here; that is not worth logging.
            return (null, null, null);
        }
    }

    private static bool LooksLikeMicrosoft(string? signerName) =>
        signerName is not null
        && (signerName.StartsWith("Microsoft ", StringComparison.OrdinalIgnoreCase)
            || signerName.Equals("Microsoft Corporation", StringComparison.OrdinalIgnoreCase)
            || signerName.Equals("Microsoft Windows", StringComparison.OrdinalIgnoreCase)
            || signerName.Equals("Microsoft Windows Publisher", StringComparison.OrdinalIgnoreCase));

    /// <summary>Translate a signing result into evidence for the verdict engine.</summary>
    public static IReadOnlyList<SecuritySignal> ToSignals(SignatureInfo info)
    {
        const SignalSource source = SignalSource.CodeSignature;

        return info.State switch
        {
            SignatureState.Valid when info.IsMicrosoft =>
            [
                new SecuritySignal(source, SignalWeight.Strong, "sig-microsoft",
                    $"Signed by {info.SignerName}, and the signature is valid.", Exonerating: true),
            ],

            SignatureState.Valid =>
            [
                new SecuritySignal(source, SignalWeight.Moderate, "sig-valid",
                    $"Signed by {info.SignerName ?? "a known publisher"}, and the signature is valid.",
                    Exonerating: true),
            ],

            SignatureState.Tampered =>
            [
                new SecuritySignal(source, SignalWeight.Strong, "sig-tampered",
                    "This file carries a signature, but its contents no longer match it. " +
                    "Someone changed the file after it was signed."),
            ],

            SignatureState.Revoked =>
            [
                new SecuritySignal(source, SignalWeight.Strong, "sig-revoked",
                    $"The certificate used to sign this file was revoked by {info.IssuerName ?? "its issuer"}."),
            ],

            SignatureState.Distrusted =>
            [
                new SecuritySignal(source, SignalWeight.Strong, "sig-distrusted",
                    "This publisher is explicitly distrusted on this machine."),
            ],

            SignatureState.UntrustedRoot =>
            [
                new SecuritySignal(source, SignalWeight.Weak, "sig-untrusted-root",
                    "Signed, but by a certificate this machine does not trust — typically a " +
                    "self-signed or internal certificate."),
            ],

            SignatureState.Expired =>
            [
                new SecuritySignal(source, SignalWeight.Informational, "sig-expired",
                    $"Signed, but the certificate expired on {info.NotAfter:d}. Old software " +
                    "does this routinely and it is not itself a problem."),
            ],

            SignatureState.Unsigned =>
            [
                new SecuritySignal(source, SignalWeight.Weak, "sig-unsigned",
                    "No digital signature. Most small and open-source tools are unsigned, so " +
                    "this alone says very little."),
            ],

            _ => [],
        };
    }
}

/// <summary>Builds the WINTRUST_DATA blob; separated only to keep the verifier readable.</summary>
file sealed class WINTRUST_DATA_Builder
{
    private readonly IntPtr _fileInfo;
    private readonly bool _checkRevocation;

    public WINTRUST_DATA_Builder(IntPtr fileInfo, bool checkRevocation)
    {
        _fileInfo = fileInfo;
        _checkRevocation = checkRevocation;
    }

    public WinTrustNative.WINTRUST_DATA Build() => new()
    {
        cbStruct = (uint)Marshal.SizeOf<WinTrustNative.WINTRUST_DATA>(),
        pPolicyCallbackData = IntPtr.Zero,
        pSIPClientData = IntPtr.Zero,
        dwUIChoice = WinTrustNative.WTD_UI_NONE,
        fdwRevocationChecks = _checkRevocation
            ? WinTrustNative.WTD_REVOKE_WHOLECHAIN
            : WinTrustNative.WTD_REVOKE_NONE,
        dwUnionChoice = WinTrustNative.WTD_CHOICE_FILE,
        pFile = _fileInfo,
        dwStateAction = WinTrustNative.WTD_STATEACTION_VERIFY,
        hWVTStateData = IntPtr.Zero,
        pwszURLReference = IntPtr.Zero,
        // Never fetch a CRL over the network during a scan.
        dwProvFlags = WinTrustNative.WTD_CACHE_ONLY_URL_RETRIEVAL,
        dwUIContext = 0,
        pSignatureSettings = IntPtr.Zero,
    };
}
