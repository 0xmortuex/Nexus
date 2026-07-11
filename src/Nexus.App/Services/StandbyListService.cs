using System.ComponentModel;
using Nexus.App.Interop;
using Nexus.Core.Logging;
using Nexus.Core.Models;
using Nexus.Core.Persistence;

namespace Nexus.App.Services;

/// <summary>
/// Purges the standby (cached) memory list via NtSetSystemInformation — the same
/// mechanism as ISLC / Hone's RAM cleaner. Requires SeProfileSingleProcessPrivilege,
/// which the admin token has but must be explicitly enabled.
/// Honest note baked into the UI: Windows reuses standby pages on demand anyway;
/// purging helps mainly against the "standby list bloat" stutter on some systems.
/// </summary>
public sealed class StandbyListService : IDisposable
{
    private readonly ActivityLog _log;
    private readonly SettingsService _settings;
    private readonly ProBalanceService _snapshots;
    private bool _privilegeEnabled;
    private DateTimeOffset _lastAutoPurge = DateTimeOffset.MinValue;

    public StandbyListService(ActivityLog log, SettingsService settings, ProBalanceService snapshots)
    {
        _log = log;
        _settings = settings;
        _snapshots = snapshots;
    }

    public void Start() => _snapshots.SnapshotTaken += OnSnapshot;

    public bool TryPurge(out string? error)
    {
        error = null;
        try
        {
            if (!EnablePrivilege())
            {
                error = "could not enable SeProfileSingleProcessPrivilege";
                return false;
            }

            int command = NativeMethods.MemoryPurgeStandbyList;
            int status = NativeMethods.NtSetSystemInformation(
                NativeMethods.SystemMemoryListInformationClass, ref command, sizeof(int));
            if (status != 0)
            {
                error = $"NtSetSystemInformation failed with NTSTATUS 0x{status:X8}";
                return false;
            }

            _log.Info("Memory", "Purged the standby memory list.");
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private void OnSnapshot(SystemSnapshot snapshot)
    {
        var options = _settings.Current.Memory;
        if (!options.AutoPurgeStandby)
            return;

        long thresholdBytes = (long)options.FreeMemoryThresholdMb * 1024 * 1024;
        if (snapshot.AvailableMemoryBytes >= thresholdBytes
            || (snapshot.Timestamp - _lastAutoPurge).TotalMinutes < 5)
            return;

        _lastAutoPurge = snapshot.Timestamp;
        if (TryPurge(out var error))
            _log.Info("Memory",
                $"Auto-purged standby list (available memory fell below {options.FreeMemoryThresholdMb} MB).");
        else
            _log.Warn("Memory", $"Auto-purge failed: {error}");
    }

    private bool EnablePrivilege()
    {
        if (_privilegeEnabled)
            return true;

        if (!NativeMethods.OpenProcessToken(NativeMethods.GetCurrentProcess(),
                NativeMethods.TOKEN_ADJUST_PRIVILEGES | NativeMethods.TOKEN_QUERY, out var token))
            return false;

        try
        {
            if (!NativeMethods.LookupPrivilegeValueW(null, "SeProfileSingleProcessPrivilege", out var luid))
                return false;

            var privileges = new NativeMethods.TOKEN_PRIVILEGES
            {
                PrivilegeCount = 1,
                Luid = luid,
                Attributes = NativeMethods.SE_PRIVILEGE_ENABLED,
            };
            if (!NativeMethods.AdjustTokenPrivileges(token, false, ref privileges, 0, IntPtr.Zero, IntPtr.Zero)
                || new Win32Exception().NativeErrorCode != 0)
            {
                // ERROR_NOT_ALL_ASSIGNED (1300) means the privilege isn't in the token.
                if (new Win32Exception().NativeErrorCode == 1300)
                    return false;
            }

            _privilegeEnabled = true;
            return true;
        }
        finally
        {
            NativeMethods.CloseHandle(token);
        }
    }

    public void Dispose() => _snapshots.SnapshotTaken -= OnSnapshot;
}
