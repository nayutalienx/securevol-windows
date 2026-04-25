using System.ComponentModel;
using SecureVol.Common.Policy;

namespace SecureVol.Common.Interop;

public static class DriverPolicyController
{
    private const int HResultFilterAlreadyLoaded = unchecked((int)0x80070420);
    private const int HResultFilterInstanceAlreadyExists = unchecked((int)0x801F0012);
    private const int HResultPrivilegeNotHeld = unchecked((int)0x80070522);

    public static DriverStateDto PushPolicy(PolicyConfig policy, uint generation, uint processId)
    {
        EnsureFilterLoaded();

        if (policy.ProtectionEnabled)
        {
            EnsureFilterAttached(policy);
        }

        using var controlConnection = FilterPortConnection.ConnectControl(processId);
        return controlConnection.SetPolicy(policy.ProtectionEnabled, generation, policy.NormalizedProtectedVolume);
    }

    public static void EnsureFilterLoaded()
    {
        if (NativeMethods.IsServiceRunning("SecureVolFlt"))
        {
            return;
        }

        var result = NativeMethods.FilterLoad("SecureVolFlt");
        if (result == 0 || result == HResultFilterAlreadyLoaded)
        {
            return;
        }

        if (NativeMethods.IsServiceRunning("SecureVolFlt"))
        {
            return;
        }

        throw new Win32Exception(result, $"SecureVolFlt could not be loaded. HRESULT=0x{result:X8}");
    }

    public static void EnsureFilterAttached(PolicyConfig policy)
    {
        var volumeName = ResolveAttachVolumeName(policy);
        if (string.IsNullOrWhiteSpace(volumeName))
        {
            throw new InvalidOperationException("Protection is enabled but no protected volume or mounted drive is configured.");
        }

        var result = NativeMethods.FilterAttach("SecureVolFlt", volumeName, null, 0, IntPtr.Zero);
        if (result == 0 || result == HResultFilterInstanceAlreadyExists)
        {
            return;
        }

        // SecureVolFlt's INF installs a default minifilter instance with Flags=0,
        // so Filter Manager auto-attaches it to mounted volumes. On some Windows
        // 11 builds FilterAttach/FilterLoad can still return ERROR_PRIVILEGE_NOT_HELD
        // even when the driver service is already running. Do not block SetPolicy
        // in that case; the driver-side volume GUID check remains the enforcement
        // scope, and diagnostics still expose fltmc instance state.
        if (result == HResultPrivilegeNotHeld && NativeMethods.IsServiceRunning("SecureVolFlt"))
        {
            return;
        }

        throw new Win32Exception(result, $"SecureVolFlt could not be attached to '{volumeName}'. HRESULT=0x{result:X8}");
    }

    public static string ResolveAttachVolumeName(PolicyConfig policy)
    {
        var mountPoint = policy.NormalizedProtectedMountPoint;
        if (IsDriveRoot(mountPoint))
        {
            return mountPoint.TrimEnd('\\');
        }

        return policy.NormalizedProtectedVolume;
    }

    private static bool IsDriveRoot(string value) =>
        value.Length == 3 && value[1] == ':' && value[2] == '\\';
}
