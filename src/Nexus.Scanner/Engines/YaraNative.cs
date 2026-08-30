using System.Runtime.InteropServices;

namespace Nexus.Scanner.Engines;

/// <summary>
/// Raw bindings to the YARA-X C API (<c>yara_x_capi</c>).
///
/// Bound directly rather than through one of the community wrapper packages. In a
/// security tool the supply chain is part of the threat model, and every wrapper is
/// an extra party whose build you are trusting inside the process that parses
/// hostile files. The C API here is small and stable enough that binding it directly
/// removes that link entirely — the only third-party artifact is VirusTotal's own
/// released DLL.
///
/// Nothing outside <see cref="YaraEngine"/> calls these.
/// </summary>
internal static class YaraNative
{
    internal const string Library = "yara_x_capi";

    /// <summary>Return codes, in the order the header declares them.</summary>
    internal enum YrxResult
    {
        Success = 0,
        SyntaxError = 1,
        VariableError = 2,
        ScanError = 3,
        ScanTimeout = 4,
        InvalidArgument = 5,
        InvalidUtf8 = 6,
        InvalidState = 7,
        SerializationError = 8,
        NoMetadata = 9,
        NotSupported = 10,
    }

    /// <summary>Invoked once per matching rule during a scan.</summary>
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    internal delegate void RuleCallback(IntPtr rule, IntPtr userData);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern YrxResult yrx_compile(
        [MarshalAs(UnmanagedType.LPUTF8Str)] string source, out IntPtr rules);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void yrx_rules_destroy(IntPtr rules);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern YrxResult yrx_scanner_create(IntPtr rules, out IntPtr scanner);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void yrx_scanner_destroy(IntPtr scanner);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern YrxResult yrx_scanner_set_timeout(IntPtr scanner, ulong seconds);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern YrxResult yrx_scanner_on_matching_rule(
        IntPtr scanner, RuleCallback callback, IntPtr userData);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern YrxResult yrx_scanner_scan(IntPtr scanner, byte[] data, nuint length);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern YrxResult yrx_rule_identifier(IntPtr rule, out IntPtr identifier, out nuint length);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr yrx_last_error();

    /// <summary>The library's description of the last failure, or a fallback.</summary>
    internal static string LastError()
    {
        try
        {
            var pointer = yrx_last_error();
            return pointer == IntPtr.Zero
                ? "no further detail"
                : Marshal.PtrToStringUTF8(pointer) ?? "no further detail";
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return "no further detail";
        }
    }

    /// <summary>Read a rule's identifier, which the library hands back as a
    /// non-null-terminated pointer and length.</summary>
    internal static string RuleIdentifier(IntPtr rule)
    {
        if (yrx_rule_identifier(rule, out var pointer, out var length) != YrxResult.Success
            || pointer == IntPtr.Zero
            || length == 0)
        {
            return "unnamed-rule";
        }

        return Marshal.PtrToStringUTF8(pointer, (int)length);
    }

    /// <summary>True when the native library is present and loadable.</summary>
    internal static bool IsPresent()
    {
        try
        {
            // Any cheap call proves the DLL resolved and the entry points match.
            yrx_last_error();
            return true;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException
                                       or BadImageFormatException)
        {
            return false;
        }
    }
}
