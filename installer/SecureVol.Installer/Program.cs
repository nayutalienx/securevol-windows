using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Windows.Forms;

namespace SecureVol.Installer;

internal static class Program
{
    private const uint TokenQuery = 0x0008;

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(
        IntPtr tokenHandle,
        TokenInformationClass tokenInformationClass,
        out TokenElevation tokenInformation,
        uint tokenInformationLength,
        out uint returnLength);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [STAThread]
    private static void Main(string[] args)
    {
        EnsureElevatedOrExit(args);
        Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
        Application.ThreadException += (_, args) => ShowFatalError(args.Exception);
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
        {
            if (args.ExceptionObject is Exception ex)
            {
                ShowFatalError(ex);
            }
        };

        ApplicationConfiguration.Initialize();
        Application.Run(new InstallerForm(ParseStartupAction(args)));
    }

    private static void ShowFatalError(Exception exception)
    {
        MessageBox.Show(
            exception.ToString(),
            "SecureVol Installer",
            MessageBoxButtons.OK,
            MessageBoxIcon.Error);
    }

    private static void EnsureElevatedOrExit(string[] args)
    {
        if (IsProcessElevated())
        {
            return;
        }

        if (TryRelaunchElevated(args))
        {
            Environment.Exit(0);
            return;
        }

        MessageBox.Show(
            "SecureVol Installer must run as Administrator. The non-elevated instance will exit.",
            "SecureVol Installer",
            MessageBoxButtons.OK,
            MessageBoxIcon.Error);

        Environment.Exit(1);
    }

    internal static bool IsProcessElevated()
    {
        if (!OpenProcessToken(GetCurrentProcess(), TokenQuery, out var tokenHandle))
        {
            return false;
        }

        try
        {
            var elevation = new TokenElevation();
            var size = (uint)Marshal.SizeOf<TokenElevation>();
            return GetTokenInformation(tokenHandle, TokenInformationClass.TokenElevation, out elevation, size, out _) &&
                   elevation.TokenIsElevated != 0;
        }
        finally
        {
            CloseHandle(tokenHandle);
        }
    }

    internal static bool TryRelaunchElevated(string[] args)
    {
        var executable = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(executable))
        {
            return false;
        }

        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = executable,
                Arguments = string.Join(" ", args.Select(QuoteArgument)),
                UseShellExecute = true,
                Verb = "runas"
            });

            return process is not null;
        }
        catch
        {
            return false;
        }
    }

    private static InstallerStartupAction? ParseStartupAction(string[] args)
    {
        var autoRunIndex = Array.FindIndex(args, arg => string.Equals(arg, "--autorun", StringComparison.OrdinalIgnoreCase));
        if (autoRunIndex < 0 || autoRunIndex + 1 >= args.Length)
        {
            return null;
        }

        var action = args[autoRunIndex + 1].Trim().ToLowerInvariant();
        if (action is not ("install" or "repair" or "uninstall" or "update"))
        {
            throw new InvalidOperationException("--autorun must be followed by install, repair, uninstall, or update.");
        }

        var enableTestSigning = HasFlag(args, "--enable-testsigning");
        var autoStart = HasFlag(args, "--autostart") || !HasFlag(args, "--no-autostart");
        return new InstallerStartupAction(action, enableTestSigning, autoStart);
    }

    private static bool HasFlag(string[] args, string name) =>
        args.Any(arg => string.Equals(arg, name, StringComparison.OrdinalIgnoreCase));

    private static string QuoteArgument(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "\"\"";
        }

        return value.Any(char.IsWhiteSpace) || value.Contains('"')
            ? $"\"{value.Replace("\"", "\\\"", StringComparison.Ordinal)}\""
            : value;
    }

    private enum TokenInformationClass
    {
        TokenElevation = 20
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenElevation
    {
        public uint TokenIsElevated;
    }
}
