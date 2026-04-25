using System.Diagnostics;
using System.Security.Principal;
using System.Windows.Forms;

namespace SecureVol.Installer;

internal static class Program
{
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
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        if (principal.IsInRole(WindowsBuiltInRole.Administrator))
        {
            return;
        }

        var executable = Environment.ProcessPath;
        if (!string.IsNullOrWhiteSpace(executable))
        {
            try
            {
                using var process = Process.Start(new ProcessStartInfo
                {
                    FileName = executable,
                    Arguments = string.Join(" ", args.Select(QuoteArgument)),
                    UseShellExecute = true,
                    Verb = "runas"
                });

                if (process is not null)
                {
                    Environment.Exit(0);
                    return;
                }
            }
            catch
            {
                // Fall through to the explicit user-facing error.
            }
        }

        MessageBox.Show(
            "SecureVol Installer must be launched with administrative rights.",
            "SecureVol Installer",
            MessageBoxButtons.OK,
            MessageBoxIcon.Error);

        Environment.Exit(1);
    }

    private static InstallerStartupAction? ParseStartupAction(string[] args)
    {
        var autoRunIndex = Array.FindIndex(args, arg => string.Equals(arg, "--autorun", StringComparison.OrdinalIgnoreCase));
        if (autoRunIndex < 0 || autoRunIndex + 1 >= args.Length)
        {
            return null;
        }

        var action = args[autoRunIndex + 1].Trim().ToLowerInvariant();
        if (action is not ("install" or "repair" or "uninstall"))
        {
            throw new InvalidOperationException("--autorun must be followed by install, repair, or uninstall.");
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
}
