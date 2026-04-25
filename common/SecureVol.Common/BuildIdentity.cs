using System.Reflection;

namespace SecureVol.Common;

public static class BuildIdentity
{
    public static string ReleaseTag { get; } = ResolveReleaseTag();

    private static string ResolveReleaseTag()
    {
        var assembly = typeof(BuildIdentity).Assembly;
        var metadataTag = assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .FirstOrDefault(static attribute => string.Equals(attribute.Key, "SecureVolReleaseTag", StringComparison.OrdinalIgnoreCase))
            ?.Value;

        if (!string.IsNullOrWhiteSpace(metadataTag))
        {
            return metadataTag.Trim();
        }

        var informationalVersion = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        return string.IsNullOrWhiteSpace(informationalVersion)
            ? "dev-local"
            : informationalVersion.Trim();
    }
}
