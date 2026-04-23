using System.Text.Json;

namespace SecureVol.Common.Logging;

public sealed class JsonFileLogger
{
    private readonly string _path;
    private readonly SemaphoreSlim _gate = new(1, 1);

    public JsonFileLogger(string path)
    {
        _path = path;
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
    }

    public async Task WriteAsync(object record, CancellationToken cancellationToken = default)
    {
        var json = JsonSerializer.Serialize(record);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await File.AppendAllTextAsync(_path, json + Environment.NewLine, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }
}
