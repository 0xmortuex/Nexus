namespace Nexus.Core.Tweaks;

public enum TweakRisk
{
    Low,
    Medium,
    High,
}

/// <summary>One registry write. Kind is a string ("dword" | "string") so the model
/// stays platform-neutral; the App layer maps it to RegistryValueKind.
/// A null <see cref="Value"/> means "delete this value".</summary>
public sealed record RegistryOp(string KeyPath, string ValueName, string Kind, string? Value);

/// <summary>A reversible external command (e.g. powercfg /h off ↔ /h on).</summary>
public sealed record CommandOp(string FileName, string ApplyArgs, string UndoArgs);

/// <summary>
/// A system tweak. Every entry must be honest: Description states the realistic
/// expected impact in one line, and every tweak must have a working undo
/// (captured original registry values, or an explicit undo command).
/// </summary>
public sealed record TweakDefinition
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public required string Category { get; init; }
    /// <summary>One-line, no-hype statement of what to actually expect.</summary>
    public required string Description { get; init; }
    public TweakRisk Risk { get; init; } = TweakRisk.Low;
    public bool RequiresReboot { get; init; }
    public IReadOnlyList<RegistryOp> RegistryOps { get; init; } = [];
    public IReadOnlyList<CommandOp> Commands { get; init; } = [];
    /// <summary>When true, RegistryOps' KeyPath contains "{adapter}" and is expanded
    /// once per TCP/IP interface GUID at apply time (Nagle).</summary>
    public bool PerNetworkAdapter { get; init; }

    /// <summary>Distinct registry keys touched — exported to .reg backups before apply.</summary>
    public IReadOnlyList<string> AffectedKeys()
        => RegistryOps.Select(op => op.KeyPath).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
}
