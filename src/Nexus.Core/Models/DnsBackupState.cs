namespace Nexus.Core.Models;

/// <summary>One adapter's pre-Nexus DNS configuration. An empty
/// <see cref="OriginalNameServer"/> means the adapter used DHCP-provided DNS.</summary>
public sealed record AdapterDnsBackup(string InterfaceGuid, string AdapterName, string OriginalNameServer);

/// <summary>Persisted so a custom DNS applied by Nexus can always be undone,
/// even after a restart.</summary>
public sealed record DnsBackupState
{
    public IReadOnlyList<AdapterDnsBackup> Adapters { get; init; } = [];
    public bool Applied => Adapters.Count > 0;
}
