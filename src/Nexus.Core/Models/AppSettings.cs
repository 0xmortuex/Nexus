using Nexus.Core.ProBalance;

namespace Nexus.Core.Models;

/// <summary>Root settings document (settings.json). Extended stage by stage.</summary>
public sealed record AppSettings
{
    public ProBalanceOptions ProBalance { get; init; } = new();
}
