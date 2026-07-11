using System.Diagnostics;
using Nexus.Core.Logging;
using Nexus.Core.Tweaks;

namespace Nexus.App.TweaksImpl;

/// <summary>
/// Orchestrates tweak lifecycle: backup → capture originals → apply → record.
/// Undo restores the captured originals (or runs the tweak's undo command).
/// A tweak whose mandatory backup fails is never applied.
/// </summary>
public sealed class TweakService
{
    private readonly RegistryTweakApplier _registry;
    private readonly BackupService _backup;
    private readonly TweakStateStore _state;
    private readonly ActivityLog _log;

    public event Action? Changed;

    public TweakService(RegistryTweakApplier registry, BackupService backup, TweakStateStore state, ActivityLog log)
    {
        _registry = registry;
        _backup = backup;
        _state = state;
        _log = log;
    }

    public IReadOnlyList<TweakDefinition> Catalog => TweakCatalog.All;

    public bool IsApplied(string tweakId) => _state.FindApplied(tweakId) is not null;

    public bool Apply(string tweakId, out string? error)
    {
        error = null;
        var tweak = TweakCatalog.Find(tweakId);
        if (tweak is null)
        {
            error = $"unknown tweak {tweakId}";
            return false;
        }

        try
        {
            var ops = ResolveOps(tweak);

            string? backupDir = null;
            if (ops.Count > 0)
            {
                backupDir = _backup.BackupBeforeTweak(tweak.Id, ops.Select(o => o.KeyPath)
                    .Distinct(StringComparer.OrdinalIgnoreCase).ToArray());
                if (backupDir is null)
                {
                    error = "the mandatory registry backup failed, so the tweak was not applied";
                    _log.Error("Tweaks", $"Refused to apply \"{tweak.Name}\": {error}.");
                    return false;
                }
            }

            var originals = _registry.Capture(ops);
            _registry.Apply(ops);

            foreach (var command in tweak.Commands)
            {
                if (!RunCommand(command.FileName, command.ApplyArgs, out var commandError))
                {
                    error = commandError;
                    // Roll the registry part back; command tweaks are all-or-nothing.
                    _registry.Restore(originals);
                    _log.Error("Tweaks", $"\"{tweak.Name}\" failed: {commandError}. Registry changes rolled back.");
                    return false;
                }
            }

            _state.RecordApplied(new AppliedTweak(tweak.Id, DateTimeOffset.Now, originals, backupDir));
            _log.Info("Tweaks", $"Applied \"{tweak.Name}\"." +
                (tweak.RequiresReboot ? " Takes effect after a reboot." : ""));
            Changed?.Invoke();
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            _log.Error("Tweaks", $"Applying \"{tweak.Name}\" failed: {ex.Message}");
            return false;
        }
    }

    public bool Undo(string tweakId, out string? error)
    {
        error = null;
        var tweak = TweakCatalog.Find(tweakId);
        var applied = _state.FindApplied(tweakId);
        if (tweak is null || applied is null)
        {
            error = "tweak is not applied";
            return false;
        }

        try
        {
            _registry.Restore(applied.Originals);

            foreach (var command in tweak.Commands)
            {
                if (!RunCommand(command.FileName, command.UndoArgs, out var commandError))
                {
                    error = commandError;
                    _log.Error("Tweaks", $"Undo of \"{tweak.Name}\" failed: {commandError}");
                    return false;
                }
            }

            _state.RemoveApplied(tweakId);
            _log.Info("Tweaks", $"Undid \"{tweak.Name}\"; original values restored." +
                (tweak.RequiresReboot ? " Takes effect after a reboot." : ""));
            Changed?.Invoke();
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            _log.Error("Tweaks", $"Undo of \"{tweak.Name}\" failed: {ex.Message}");
            return false;
        }
    }

    /// <summary>Undo every applied tweak (restore-defaults path). Returns failures.</summary>
    public IReadOnlyList<string> UndoAll()
    {
        var failures = new List<string>();
        foreach (var applied in _state.Current.Applied.ToArray())
        {
            if (!Undo(applied.TweakId, out var error))
                failures.Add($"{applied.TweakId}: {error}");
        }
        return failures;
    }

    private IReadOnlyList<RegistryOp> ResolveOps(TweakDefinition tweak)
    {
        if (!tweak.PerNetworkAdapter)
            return tweak.RegistryOps;

        var resolved = new List<RegistryOp>();
        foreach (var adapterGuid in _registry.EnumerateTcpInterfaceGuids())
        {
            foreach (var op in tweak.RegistryOps)
                resolved.Add(op with { KeyPath = op.KeyPath.Replace("{adapter}", adapterGuid) });
        }
        return resolved;
    }

    private bool RunCommand(string fileName, string arguments, out string? error)
    {
        error = null;
        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            });
            if (process is null)
            {
                error = $"could not start {fileName}";
                return false;
            }
            if (!process.WaitForExit(15_000))
            {
                process.Kill();
                error = $"{fileName} {arguments} timed out";
                return false;
            }
            if (process.ExitCode != 0)
            {
                error = $"{fileName} {arguments} exited with code {process.ExitCode}";
                return false;
            }
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }
}
