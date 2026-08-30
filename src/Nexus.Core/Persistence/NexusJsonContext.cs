using System.Text.Json.Serialization;
using Nexus.Core.GameMode;
using Nexus.Core.Models;
using Nexus.Core.Performance;
using Nexus.Core.Security;

namespace Nexus.Core.Persistence;

[JsonSourceGenerationOptions(
    WriteIndented = true,
    UseStringEnumConverter = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(List<ProcessRule>))]
[JsonSerializable(typeof(AppSettings))]
[JsonSerializable(typeof(List<GameProfile>))]
[JsonSerializable(typeof(IntendedState))]
[JsonSerializable(typeof(Tweaks.TweaksState))]
[JsonSerializable(typeof(DnsBackupState))]
[JsonSerializable(typeof(TrustStoreState))]
[JsonSerializable(typeof(QuarantineState))]
[JsonSerializable(typeof(VerdictCacheState))]
[JsonSerializable(typeof(BaselineState))]
[JsonSerializable(typeof(ScanHistoryState))]
public sealed partial class NexusJsonContext : JsonSerializerContext
{
}
