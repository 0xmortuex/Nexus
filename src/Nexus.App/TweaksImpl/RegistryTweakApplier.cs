using System.Globalization;
using Microsoft.Win32;
using Nexus.Core.Tweaks;

namespace Nexus.App.TweaksImpl;

/// <summary>
/// The only class that writes tweak registry values. Captures originals (including
/// "did not exist"), applies ops, restores captures. Missing keys/values are
/// treated as "not applicable", never as errors.
/// </summary>
public sealed class RegistryTweakApplier
{
    /// <summary>Read the current value of every op target, for undo and for
    /// is-applied detection.</summary>
    public IReadOnlyList<CapturedValue> Capture(IEnumerable<RegistryOp> ops)
    {
        var captured = new List<CapturedValue>();
        foreach (var op in ops)
        {
            var (root, subKey) = Split(op.KeyPath);
            using var key = root?.OpenSubKey(subKey, writable: false);
            var value = key?.GetValue(op.ValueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            if (value is null)
            {
                captured.Add(new CapturedValue(op.KeyPath, op.ValueName, null, null, Existed: false));
            }
            else
            {
                var kind = key!.GetValueKind(op.ValueName);
                captured.Add(new CapturedValue(op.KeyPath, op.ValueName,
                    KindToString(kind), ValueToString(value, kind), Existed: true));
            }
        }
        return captured;
    }

    public void Apply(IEnumerable<RegistryOp> ops)
    {
        foreach (var op in ops)
        {
            var (root, subKey) = Split(op.KeyPath);
            if (root is null)
                continue;

            using var key = root.CreateSubKey(subKey, writable: true);
            if (op.Value is null)
            {
                key.DeleteValue(op.ValueName, throwOnMissingValue: false);
            }
            else if (op.Kind == "dword")
            {
                key.SetValue(op.ValueName, unchecked((int)ParseUInt(op.Value)), RegistryValueKind.DWord);
            }
            else
            {
                key.SetValue(op.ValueName, op.Value, RegistryValueKind.String);
            }
        }
    }

    /// <summary>Put every captured location back exactly as it was.</summary>
    public void Restore(IEnumerable<CapturedValue> originals)
    {
        foreach (var original in originals)
        {
            var (root, subKey) = Split(original.KeyPath);
            if (root is null)
                continue;

            using var key = root.CreateSubKey(subKey, writable: true);
            if (!original.Existed)
            {
                key.DeleteValue(original.ValueName, throwOnMissingValue: false);
            }
            else if (original.Kind == "dword")
            {
                key.SetValue(original.ValueName, unchecked((int)ParseUInt(original.Value!)), RegistryValueKind.DWord);
            }
            else if (original.Kind == "qword")
            {
                key.SetValue(original.ValueName, (long)ulong.Parse(original.Value!, CultureInfo.InvariantCulture), RegistryValueKind.QWord);
            }
            else
            {
                key.SetValue(original.ValueName, original.Value ?? "", RegistryValueKind.String);
            }
        }
    }

    /// <summary>True when every op's current value already equals its target.</summary>
    public bool IsApplied(IEnumerable<RegistryOp> ops)
    {
        foreach (var op in ops)
        {
            var (root, subKey) = Split(op.KeyPath);
            using var key = root?.OpenSubKey(subKey, writable: false);
            var value = key?.GetValue(op.ValueName);
            if (op.Value is null)
            {
                if (value is not null)
                    return false;
                continue;
            }
            if (value is null)
                return false;

            var current = op.Kind == "dword" && value is int i
                ? unchecked((uint)i).ToString(CultureInfo.InvariantCulture)
                : value.ToString() ?? "";
            var target = op.Kind == "dword"
                ? ParseUInt(op.Value).ToString(CultureInfo.InvariantCulture)
                : op.Value;
            if (!string.Equals(current, target, StringComparison.OrdinalIgnoreCase))
                return false;
        }
        return true;
    }

    /// <summary>Interface GUID subkeys under Tcpip\Parameters\Interfaces (Nagle).</summary>
    public IReadOnlyList<string> EnumerateTcpInterfaceGuids()
    {
        using var key = Registry.LocalMachine.OpenSubKey(
            @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces");
        return key?.GetSubKeyNames() ?? [];
    }

    internal static uint ParseUInt(string text)
        => text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? uint.Parse(text[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture)
            : uint.Parse(text, CultureInfo.InvariantCulture);

    private static string KindToString(RegistryValueKind kind) => kind switch
    {
        RegistryValueKind.DWord => "dword",
        RegistryValueKind.QWord => "qword",
        _ => "string",
    };

    private static string ValueToString(object value, RegistryValueKind kind) => kind switch
    {
        RegistryValueKind.DWord => unchecked((uint)(int)value).ToString(CultureInfo.InvariantCulture),
        RegistryValueKind.QWord => unchecked((ulong)(long)value).ToString(CultureInfo.InvariantCulture),
        _ => value.ToString() ?? "",
    };

    private static (RegistryKey? Root, string SubKey) Split(string keyPath)
    {
        int separator = keyPath.IndexOf('\\');
        if (separator < 0)
            return (null, "");
        var subKey = keyPath[(separator + 1)..];
        return keyPath[..separator].ToUpperInvariant() switch
        {
            "HKEY_LOCAL_MACHINE" or "HKLM" => (Registry.LocalMachine, subKey),
            "HKEY_CURRENT_USER" or "HKCU" => (Registry.CurrentUser, subKey),
            "HKEY_USERS" => (Registry.Users, subKey),
            _ => (null, ""),
        };
    }
}
