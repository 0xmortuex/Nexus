using System.Text.Json.Serialization;
using Nexus.Core.GameMode;
using Nexus.Core.Models;

namespace Nexus.Core.Persistence;

[JsonSourceGenerationOptions(
    WriteIndented = true,
    UseStringEnumConverter = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(List<ProcessRule>))]
[JsonSerializable(typeof(AppSettings))]
[JsonSerializable(typeof(List<GameProfile>))]
[JsonSerializable(typeof(IntendedState))]
public sealed partial class NexusJsonContext : JsonSerializerContext
{
}
