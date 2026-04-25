using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace SecureVol.Common.Interop;

public sealed class FilterPortConnection : IDisposable
{
    private readonly SafeFileHandle _handle;

    private FilterPortConnection(SafeFileHandle handle)
    {
        _handle = handle;
    }

    public static FilterPortConnection Connect(uint serviceProcessId) => ConnectQuery(serviceProcessId);

    public static FilterPortConnection ConnectQuery(uint serviceProcessId) =>
        Connect(serviceProcessId, FilterPortConnectionRole.Query);

    public static FilterPortConnection ConnectControl(uint serviceProcessId) =>
        Connect(serviceProcessId, FilterPortConnectionRole.Control);

    private static FilterPortConnection Connect(uint serviceProcessId, FilterPortConnectionRole role)
    {
        var contextSize = Marshal.SizeOf<ConnectContext>();
        using var context = new FilterPortMessageBuffer(contextSize);
        Marshal.StructureToPtr(
            new ConnectContext
            {
                ServiceProcessId = serviceProcessId,
                Role = (uint)role
            },
            context.Pointer,
            false);

        var hr = NativeMethods.FilterConnectCommunicationPort(
            AppPaths.DriverPortName,
            0,
            context.Pointer,
            checked((ushort)contextSize),
            IntPtr.Zero,
            out var handle);

        if (hr != 0 || handle.IsInvalid)
        {
            throw new Win32Exception(hr, $"FilterConnectCommunicationPort failed for {AppPaths.DriverPortName}.");
        }

        return new FilterPortConnection(handle);
    }

    public ProcessAccessQuery ReceiveProcessQuery()
    {
        var payloadSize = Marshal.SizeOf<ProcessQueryMessage>();
        var totalSize = Marshal.SizeOf<FilterMessageHeader>() + payloadSize;
        using var buffer = new FilterPortMessageBuffer(totalSize);

        var hr = NativeMethods.FilterGetMessage(_handle, buffer.Pointer, (uint)totalSize, IntPtr.Zero);
        if (hr != 0)
        {
            throw new Win32Exception(hr, "FilterGetMessage failed.");
        }

        var header = Marshal.PtrToStructure<FilterMessageHeader>(buffer.Pointer);
        var payloadPtr = IntPtr.Add(buffer.Pointer, Marshal.SizeOf<FilterMessageHeader>());
        var query = Marshal.PtrToStructure<ProcessQueryMessage>(payloadPtr);
        return new ProcessAccessQuery(header.MessageId, query);
    }

    public void Reply(ulong messageId, ProcessReplyMessage reply)
    {
        var headerSize = Marshal.SizeOf<FilterReplyHeader>();
        var payloadSize = Marshal.SizeOf<ProcessReplyMessage>();
        using var buffer = new FilterPortMessageBuffer(headerSize + payloadSize);

        var replyHeader = new FilterReplyHeader
        {
            Status = 0,
            MessageId = messageId
        };

        Marshal.StructureToPtr(replyHeader, buffer.Pointer, false);
        Marshal.StructureToPtr(reply, IntPtr.Add(buffer.Pointer, headerSize), false);

        var hr = NativeMethods.FilterReplyMessage(_handle, buffer.Pointer, (uint)(headerSize + payloadSize));
        if (hr != 0)
        {
            throw new Win32Exception(hr, "FilterReplyMessage failed.");
        }
    }

    public DriverStateDto SetPolicy(bool protectionEnabled, uint generation, string protectedVolumeGuid)
    {
        var request = new SetPolicyMessage
        {
            Header = new SecureVolMessageHeader
            {
                MessageType = DriverMessageType.SetPolicy,
                Size = (uint)Marshal.SizeOf<SetPolicyMessage>()
            },
            PolicyGeneration = generation,
            ProtectionEnabled = protectionEnabled ? 1u : 0u,
            ProtectedVolumeGuid = protectedVolumeGuid ?? string.Empty
        };

        SendControlMessage(request, out DriverStateMessage response);
        return ToDriverStateDto(response);
    }

    public DriverStateDto GetDriverState()
    {
        var request = new SecureVolMessageHeader
        {
            MessageType = DriverMessageType.GetState,
            Size = (uint)Marshal.SizeOf<SecureVolMessageHeader>()
        };

        SendControlMessage(request, out DriverStateMessage response);
        return ToDriverStateDto(response);
    }

    public IReadOnlyList<RecentDenyEventDto> GetRecentDenies()
    {
        var request = new SecureVolMessageHeader
        {
            MessageType = DriverMessageType.GetRecentDenies,
            Size = (uint)Marshal.SizeOf<SecureVolMessageHeader>()
        };

        SendControlMessage(request, out RecentDenyEventList response);

        var list = new List<RecentDenyEventDto>((int)response.Count);
        foreach (var item in response.Events.Take((int)response.Count))
        {
            list.Add(new RecentDenyEventDto(
                DateTimeOffset.FromFileTime(item.TimestampUtc),
                item.ProcessId,
                item.Reason,
                item.ImageName.TrimEnd('\0')));
        }

        return list;
    }

    public void FlushCache()
    {
        var request = new SecureVolMessageHeader
        {
            MessageType = DriverMessageType.FlushCache,
            Size = (uint)Marshal.SizeOf<SecureVolMessageHeader>()
        };

        SendControlMessage(request, out DriverStateMessage _);
    }

    private void SendControlMessage<TRequest, TResponse>(TRequest request, out TResponse response)
        where TRequest : struct
        where TResponse : struct
    {
        using var inBuffer = new FilterPortMessageBuffer(Marshal.SizeOf<TRequest>());
        using var outBuffer = new FilterPortMessageBuffer(Marshal.SizeOf<TResponse>());

        Marshal.StructureToPtr(request, inBuffer.Pointer, false);
        var hr = NativeMethods.FilterSendMessage(
            _handle,
            inBuffer.Pointer,
            (uint)inBuffer.Size,
            outBuffer.Pointer,
            (uint)outBuffer.Size,
            out var _);

        if (hr != 0)
        {
            throw new Win32Exception(hr, "FilterSendMessage failed.");
        }

        response = Marshal.PtrToStructure<TResponse>(outBuffer.Pointer);
    }

    private static DriverStateDto ToDriverStateDto(DriverStateMessage response) =>
        new(
            response.ProtectionEnabled != 0,
            response.ClientConnected != 0,
            response.PolicyGeneration,
            response.CacheEntryCount,
            response.ProtectedVolumeGuid.TrimEnd('\0'));

    public void Dispose()
    {
        _handle.Dispose();
        GC.SuppressFinalize(this);
    }

    private enum FilterPortConnectionRole : uint
    {
        Query = 1,
        Control = 2
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ConnectContext
    {
        public uint ServiceProcessId;
        public uint Role;
    }
}
