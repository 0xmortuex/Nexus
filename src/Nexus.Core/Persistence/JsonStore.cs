using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace Nexus.Core.Persistence;

/// <summary>
/// Load/save one JSON document with atomic writes (temp file + rename) and
/// corruption tolerance (a broken file is renamed *.bad and defaults returned).
/// </summary>
public sealed class JsonStore<T> where T : class
{
    private readonly string _path;
    private readonly JsonTypeInfo<T> _typeInfo;
    private readonly Func<T> _defaults;
    private readonly object _gate = new();

    public JsonStore(string path, JsonTypeInfo<T> typeInfo, Func<T> defaults)
    {
        _path = path;
        _typeInfo = typeInfo;
        _defaults = defaults;
    }

    public string Path => _path;

    public T Load()
    {
        lock (_gate)
        {
            if (!File.Exists(_path))
                return _defaults();

            try
            {
                using var stream = File.OpenRead(_path);
                return JsonSerializer.Deserialize(stream, _typeInfo) ?? _defaults();
            }
            catch (Exception ex) when (ex is JsonException or IOException)
            {
                try
                {
                    File.Move(_path, _path + ".bad", overwrite: true);
                }
                catch (IOException)
                {
                    // Preserving the corrupt file is best-effort.
                }
                return _defaults();
            }
        }
    }

    public void Save(T value)
    {
        lock (_gate)
        {
            var dir = System.IO.Path.GetDirectoryName(_path);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);

            var tmp = _path + ".tmp";
            using (var stream = File.Create(tmp))
            {
                JsonSerializer.Serialize(stream, value, _typeInfo);
            }
            File.Move(tmp, _path, overwrite: true);
        }
    }
}
