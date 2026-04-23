using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SecureVol.Common;

public static class SecureVolProtocol
{
    public const int MaxVolumeChars = 96;
    public const int MaxPathChars = 512;
    public const int MaxDenyEvents = 64;
}

public enum DriverMessageType : uint
{
    Invalid = 0,
    ProcessQuery = 1,
    SetPolicy = 2,
    GetState = 3,
    GetRecentDenies = 4,
    FlushCache = 5
}

public enum AccessVerdict : uint
{
    Unknown = 0,
    Allow = 1,
    Deny = 2,
    Bypass = 3
}

public enum DecisionReason : uint
{
    None = 0,
    AllowedByRule = 1,
    PolicyDisabled = 2,
    UnprotectedVolume = 3,
    KernelRequest = 4,
    CachedAllow = 5,
    CachedDeny = 6,
    ServiceUnavailable = 7,
    ProcessLookupFailed = 8,
    NoMatchingRule = 9,
    PathMismatch = 10,
    HashMismatch = 11,
    UserMismatch = 12,
    SignatureRequired = 13,
    PublisherMismatch = 14,
    PolicyNotLoaded = 15,
    EmergencyBypass = 16,
    InternalError = 17
}

[StructLayout(LayoutKind.Sequential)]
public struct SecureVolMessageHeader
{
    public DriverMessageType MessageType;
    public uint Size;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct ProcessQueryMessage
{
    public SecureVolMessageHeader Header;
    public uint PolicyGeneration;
    public uint ProcessId;
    public ulong ProcessCreateTime;
    public uint DesiredAccess;
    public uint CreateOptions;

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = SecureVolProtocol.MaxVolumeChars)]
    public string VolumeGuid;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct ProcessReplyMessage
{
    public SecureVolMessageHeader Header;
    public uint PolicyGeneration;
    public AccessVerdict Verdict;
    public DecisionReason Reason;

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = SecureVolProtocol.MaxPathChars)]
    public string ImagePath;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct SetPolicyMessage
{
    public SecureVolMessageHeader Header;
    public uint PolicyGeneration;
    public uint ProtectionEnabled;

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = SecureVolProtocol.MaxVolumeChars)]
    public string ProtectedVolumeGuid;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct DriverStateMessage
{
    public SecureVolMessageHeader Header;
    public uint PolicyGeneration;
    public uint ProtectionEnabled;
    public uint ClientConnected;
    public uint CacheEntryCount;

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = SecureVolProtocol.MaxVolumeChars)]
    public string ProtectedVolumeGuid;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
public struct RecentDenyEvent
{
    public long TimestampUtc;
    public uint ProcessId;
    public DecisionReason Reason;

    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 16)]
    public string ImageName;
}

[StructLayout(LayoutKind.Sequential)]
public struct RecentDenyEventList
{
    public SecureVolMessageHeader Header;
    public uint Count;
    public uint Reserved;

    [MarshalAs(UnmanagedType.ByValArray, SizeConst = SecureVolProtocol.MaxDenyEvents)]
    public RecentDenyEvent[] Events;
}

[StructLayout(LayoutKind.Sequential)]
public struct FilterMessageHeader
{
    public uint ReplyLength;
    public ulong MessageId;
}

[StructLayout(LayoutKind.Sequential)]
public struct FilterReplyHeader
{
    public int Status;
    public ulong MessageId;
}

public sealed record DriverStateDto(
    bool ProtectionEnabled,
    bool ClientConnected,
    uint PolicyGeneration,
    uint CacheEntryCount,
    string ProtectedVolumeGuid);

public sealed record RecentDenyEventDto(
    DateTimeOffset TimestampUtc,
    uint ProcessId,
    DecisionReason Reason,
    string ImageName);

public sealed record ProcessAccessQuery(
    ulong MessageId,
    ProcessQueryMessage Query);

public sealed class FilterPortMessageBuffer : IDisposable
{
    public FilterPortMessageBuffer(int size)
    {
        Pointer = Marshal.AllocHGlobal(size);
        Size = size;
    }

    public IntPtr Pointer { get; }
    public int Size { get; }

    public void Dispose()
    {
        Marshal.FreeHGlobal(Pointer);
        GC.SuppressFinalize(this);
    }
}
