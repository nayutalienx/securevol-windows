using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace SecureVol.Common.Interop;

public static class NativeMethods
{
    public const uint ProcessQueryLimitedInformation = 0x1000;
    public const uint ProcessVmRead = 0x0010;
    public const uint TokenQuery = 0x0008;
    public const int ErrorInsufficientBuffer = 122;
    public static readonly IntPtr InvalidHandleValue = new(-1);

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int FilterLoad(string lpFilterName);

    [DllImport("fltlib.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int FilterConnectCommunicationPort(
        string lpPortName,
        uint dwOptions,
        IntPtr lpContext,
        ushort wSizeOfContext,
        IntPtr lpSecurityAttributes,
        out SafeFileHandle hPort);

    [DllImport("fltlib.dll", SetLastError = true)]
    public static extern int FilterGetMessage(
        SafeFileHandle hPort,
        IntPtr lpMessageBuffer,
        uint dwMessageBufferSize,
        IntPtr lpOverlapped);

    [DllImport("fltlib.dll", SetLastError = true)]
    public static extern int FilterReplyMessage(
        SafeFileHandle hPort,
        IntPtr lpReplyBuffer,
        uint dwReplyBufferSize);

    [DllImport("fltlib.dll", SetLastError = true)]
    public static extern int FilterSendMessage(
        SafeFileHandle hPort,
        IntPtr lpInBuffer,
        uint dwInBufferSize,
        IntPtr lpOutBuffer,
        uint dwOutBufferSize,
        out uint lpBytesReturned);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern SafeFileHandle OpenProcess(
        uint dwDesiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
        uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool QueryFullProcessImageName(
        SafeFileHandle hProcess,
        uint dwFlags,
        char[] lpExeName,
        ref uint lpdwSize);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool OpenProcessToken(
        SafeFileHandle ProcessHandle,
        uint DesiredAccess,
        out SafeAccessTokenHandle TokenHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CreateProcessWithLogonW(
        string userName,
        string? domain,
        string password,
        uint logonFlags,
        string? applicationName,
        string commandLine,
        uint creationFlags,
        IntPtr environment,
        string? currentDirectory,
        ref STARTUPINFO startupInfo,
        out PROCESS_INFORMATION processInformation);

    [DllImport("wintrust.dll", PreserveSig = true, CharSet = CharSet.Unicode)]
    public static extern uint WinVerifyTrust(
        IntPtr hwnd,
        [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID,
        ref WINTRUST_DATA pWVTData);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
        public uint cb;
        public string? lpReserved;
        public string? lpDesktop;
        public string? lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WINTRUST_FILE_INFO : IDisposable
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;

        public static WINTRUST_FILE_INFO Create(string filePath) =>
            new()
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
                pcwszFilePath = Marshal.StringToCoTaskMemUni(filePath),
                hFile = IntPtr.Zero,
                pgKnownSubject = IntPtr.Zero
            };

        public void Dispose()
        {
            if (pcwszFilePath != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(pcwszFilePath);
                pcwszFilePath = IntPtr.Zero;
            }
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WINTRUST_DATA : IDisposable
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public string? pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;

        public static WINTRUST_DATA Create(ref WINTRUST_FILE_INFO fileInfo)
        {
            var fileInfoPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf<WINTRUST_FILE_INFO>());
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

            return new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = 2,
                fdwRevocationChecks = 0,
                dwUnionChoice = 1,
                pFile = fileInfoPtr,
                dwStateAction = 0,
                dwProvFlags = 0x00000010 | 0x00000100,
                dwUIContext = 0
            };
        }

        public void Dispose()
        {
            if (pFile != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(pFile);
                pFile = IntPtr.Zero;
            }
        }
    }

    public static string GetProcessImagePath(uint processId)
    {
        using var process = OpenProcess(ProcessQueryLimitedInformation, false, processId);
        if (process.IsInvalid)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"OpenProcess failed for PID {processId}.");
        }

        var buffer = new char[SecureVolProtocol.MaxPathChars];
        uint size = (uint)buffer.Length;
        if (!QueryFullProcessImageName(process, 0, buffer, ref size))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"QueryFullProcessImageName failed for PID {processId}.");
        }

        return new string(buffer, 0, (int)size);
    }

    public static string GetProcessUser(uint processId)
    {
        using var process = OpenProcess(ProcessQueryLimitedInformation, false, processId);
        if (process.IsInvalid)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"OpenProcess failed for PID {processId}.");
        }

        if (!OpenProcessToken(process, TokenQuery, out var token))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), $"OpenProcessToken failed for PID {processId}.");
        }

        using (token)
        {
            using var identity = new WindowsIdentity(token.DangerousGetHandle());
            return identity.Name;
        }
    }

    public static void CloseProcessInformation(ref PROCESS_INFORMATION processInformation)
    {
        if (processInformation.hProcess != IntPtr.Zero && processInformation.hProcess != InvalidHandleValue)
        {
            CloseHandle(processInformation.hProcess);
            processInformation.hProcess = IntPtr.Zero;
        }

        if (processInformation.hThread != IntPtr.Zero && processInformation.hThread != InvalidHandleValue)
        {
            CloseHandle(processInformation.hThread);
            processInformation.hThread = IntPtr.Zero;
        }
    }

    [SuppressMessage("Interoperability", "CA1401", Justification = "P/Invoke boundary.")]
    public static bool VerifyAuthenticode(string filePath)
    {
        var action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
        var fileInfo = WINTRUST_FILE_INFO.Create(filePath);
        try
        {
            var trustData = WINTRUST_DATA.Create(ref fileInfo);
            try
            {
                return WinVerifyTrust(IntPtr.Zero, action, ref trustData) == 0;
            }
            finally
            {
                trustData.Dispose();
            }
        }
        finally
        {
            fileInfo.Dispose();
        }
    }
}
