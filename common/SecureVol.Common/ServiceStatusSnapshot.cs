using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecureVol.Common;

public sealed record ServiceStatusSnapshot
{
    [JsonPropertyName("timestampUtc")]
    public DateTimeOffset TimestampUtc { get; init; }

    [JsonPropertyName("policyProtectionEnabled")]
    public bool PolicyProtectionEnabled { get; init; }

    [JsonPropertyName("driverConnected")]
    public bool DriverConnected { get; init; }

    [JsonPropertyName("policyGeneration")]
    public uint PolicyGeneration { get; init; }

    [JsonPropertyName("protectedVolume")]
    public string ProtectedVolume { get; init; } = string.Empty;

    [JsonPropertyName("allowRuleCount")]
    public int AllowRuleCount { get; init; }

    [JsonPropertyName("lastError")]
    public string? LastError { get; init; }

    public static ServiceStatusSnapshot? TryLoad(string path)
    {
        if (!File.Exists(path))
        {
            return null;
        }

        var json = File.ReadAllText(path);
        return JsonSerializer.Deserialize<ServiceStatusSnapshot>(json, SecureVol.Common.Policy.PolicyConfig.JsonOptions());
    }

    public void Save(string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var json = JsonSerializer.Serialize(this, SecureVol.Common.Policy.PolicyConfig.JsonOptions());
        File.WriteAllText(path, json);
    }
}
