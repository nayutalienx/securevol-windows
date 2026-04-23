using System.Runtime.InteropServices;

namespace SecureVol.Common.Interop;

public static class NativeMethodsEx
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetVolumeNameForVolumeMountPointW(
        string lpszVolumeMountPoint,
        char[] lpszVolumeName,
        uint cchBufferLength);

    public static bool GetVolumeNameForVolumeMountPoint(string volumeMountPoint, Span<char> buffer, uint cchBufferLength)
    {
        var temp = new char[buffer.Length];
        var result = GetVolumeNameForVolumeMountPointW(volumeMountPoint, temp, cchBufferLength);
        if (result)
        {
            temp.CopyTo(buffer);
        }

        return result;
    }
}
