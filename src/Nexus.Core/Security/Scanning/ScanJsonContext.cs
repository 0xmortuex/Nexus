using System.Text.Json.Serialization;

namespace Nexus.Core.Security.Scanning;

/// <summary>
/// Serializer for the worker protocol. Separate from NexusJsonContext because the
/// on-disk formats are written indented for a human to read, while this is
/// line-delimited over a pipe and a newline inside a message would desynchronise
/// the stream.
/// </summary>
[JsonSourceGenerationOptions(
    WriteIndented = false,
    UseStringEnumConverter = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(ScanRequest))]
[JsonSerializable(typeof(ScanResponse))]
public sealed partial class ScanJsonContext : JsonSerializerContext
{
}
