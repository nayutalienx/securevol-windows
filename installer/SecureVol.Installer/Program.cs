using System.Diagnostics;
using System.Security.Principal;
using System.Windows.Forms;

namespace SecureVol.Installer;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        EnsureElevatedOrExit();
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
        Application.Run(new InstallerForm());
    }

    private static void ShowFatalError(Exception exception)
    {
        MessageBox.Show(
            exception.ToString(),
            "SecureVol Installer",
            MessageBoxButtons.OK,
            MessageBoxIcon.Error);
    }

    private static void EnsureElevatedOrExit()
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
}
