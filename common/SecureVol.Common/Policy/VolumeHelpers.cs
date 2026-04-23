using SecureVol.Common.Interop;

namespace SecureVol.Common.Policy;

public static class VolumeHelpers
{
    public static string ResolveVolumeGuid(string rawValue)
    {
        var normalized = PolicyConfig.NormalizeVolumeIdentifier(rawValue);
        if (normalized.StartsWith(@"\\?\Volume{", StringComparison.OrdinalIgnoreCase))
        {
            return normalized.TrimEnd('\\');
        }

        var driveRoot = normalized.EndsWith("\\", StringComparison.Ordinal) ? normalized : normalized + "\\";
        Span<char> volumeName = stackalloc char[SecureVolProtocol.MaxVolumeChars];
        if (!NativeMethodsEx.GetVolumeNameForVolumeMountPoint(driveRoot, volumeName, (uint)volumeName.Length))
        {
            throw new InvalidOperationException($"Unable to resolve a volume GUID for '{rawValue}'.");
        }

        return new string(volumeName).TrimEnd('\0', '\\');
    }

    public static IReadOnlyList<string> EnumerateMountedDriveRoots()
    {
        return DriveInfo.GetDrives()
            .Where(drive => drive.IsReady && !string.IsNullOrWhiteSpace(drive.Name))
            .Select(drive => PolicyConfig.NormalizeVolumeIdentifier(drive.Name))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(static value => value, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }
}
