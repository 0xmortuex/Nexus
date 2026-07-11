using System.Text.Json.Serialization;
using Nexus.Core.Models;

namespace Nexus.Core.Persistence;

[JsonSourceGenerationOptions(
    WriteIndented = true,
    UseStringEnumConverter = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(List<ProcessRule>))]
public sealed partial class NexusJsonContext : JsonSerializerContext
{
}
