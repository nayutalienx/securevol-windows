using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecureVol.Common.Policy;

public sealed record PolicyConfig
{
    [JsonPropertyName("protectionEnabled")]
    public bool ProtectionEnabled { get; init; }

    [JsonPropertyName("protectedVolume")]
    public string ProtectedVolume { get; init; } = string.Empty;

    [JsonPropertyName("defaultExpectedUser")]
    public string? DefaultExpectedUser { get; init; }

    [JsonPropertyName("allowRules")]
    public List<AllowRule> AllowRules { get; init; } = [];

    public string NormalizedProtectedVolume => NormalizeVolumeIdentifier(ProtectedVolume);
    public string? NormalizedDefaultUser => NormalizeUser(DefaultExpectedUser);

    public static PolicyConfig Load(string path)
    {
        var json = File.ReadAllText(path);
        var config = JsonSerializer.Deserialize<PolicyConfig>(json, JsonOptions()) ??
                     throw new InvalidOperationException($"Unable to deserialize {path}.");

        return config.WithNormalizedRules();
    }

    public void Save(string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var json = JsonSerializer.Serialize(this, JsonOptions());
        File.WriteAllText(path, json);
    }

    public static JsonSerializerOptions JsonOptions() => new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    public static string NormalizeVolumeIdentifier(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var normalized = value.Trim().Replace('/', '\\');
        if (normalized.StartsWith(@"\??\Volume{", StringComparison.OrdinalIgnoreCase))
        {
            normalized = @"\\" + normalized.Substring(2);
        }

        if (normalized.Length == 2 && normalized[1] == ':')
        {
            normalized += "\\";
        }

        return normalized.TrimEnd('\\') switch
        {
            var drive when drive.Length == 2 && drive[1] == ':' => drive + "\\",
            var other => other
        };
    }

    public static string NormalizePath(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        return Path.GetFullPath(value)
            .Trim()
            .Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar);
    }

    public static string? NormalizeUser(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private PolicyConfig WithNormalizedRules() =>
        this with
        {
            AllowRules = AllowRules
                .Select(rule => rule with
                {
                    ImagePath = NormalizePath(rule.ImagePath),
                    Sha256 = NormalizeSha256(rule.Sha256),
                    Publisher = rule.Publisher?.Trim(),
                    ExpectedUser = NormalizeUser(rule.ExpectedUser)
                })
                .ToList()
        };

    private static string? NormalizeSha256(string? value) =>
        string.IsNullOrWhiteSpace(value)
            ? null
            : value.Replace(" ", string.Empty, StringComparison.Ordinal).ToUpperInvariant();
}

public sealed record AllowRule
{
    [JsonPropertyName("name")]
    public string Name { get; init; } = string.Empty;

    [JsonPropertyName("imagePath")]
    public string ImagePath { get; init; } = string.Empty;

    [JsonPropertyName("sha256")]
    public string? Sha256 { get; init; }

    [JsonPropertyName("requireSignature")]
    public bool RequireSignature { get; init; }

    [JsonPropertyName("publisher")]
    public string? Publisher { get; init; }

    [JsonPropertyName("expectedUser")]
    public string? ExpectedUser { get; init; }

    [JsonPropertyName("notes")]
    public string? Notes { get; init; }
}
