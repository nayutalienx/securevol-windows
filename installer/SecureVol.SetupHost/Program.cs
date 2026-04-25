using System.Text.Json;

namespace SecureVol.SetupHost;

internal static class Program
{
    public static int Main(string[] args)
    {
        var plan = InstallerPlan.Resolve(AppContext.BaseDirectory);
        var command = args.FirstOrDefault()?.Trim().ToLowerInvariant() ?? "check";
        var rest = args.Skip(1).ToArray();

        try
        {
            return command switch
            {
                "check" => RunCheck(plan),
                "plan" => RunPlan(plan),
                "install" => RunInstall(plan, rest),
                "repair" => RunInstall(plan, rest),
                "uninstall" => RunUninstall(plan, rest),
                _ => ShowUsage()
            };
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 1;
        }
    }

    private static int RunCheck(InstallerPlan plan)
    {
        var readiness = InstallerReadiness.FromPlan(plan);

        Console.WriteLine("SecureVol setup host");
        Console.WriteLine($"LayoutMode          : {plan.LayoutMode}");
        Console.WriteLine($"SourceRoot          : {plan.SourceRoot}");
        Console.WriteLine($"PayloadRoot         : {plan.PayloadRoot}");
        Console.WriteLine($"DefaultInstallRoot  : {plan.DefaultInstallRoot}");
        Console.WriteLine($"ServiceExecutable   : {readiness.ServiceExecutableFound}");
        Console.WriteLine($"CliExecutable       : {readiness.CliExecutableFound}");
        Console.WriteLine($"AppExecutable       : {readiness.AppExecutableFound}");
        Console.WriteLine($"DriverSys           : {readiness.DriverSysFound}");
        Console.WriteLine($"DriverInf           : {readiness.DriverInfFound}");
        Console.WriteLine($"DriverCat           : {readiness.DriverCatFound}");
        Console.WriteLine($"DriverCert          : {readiness.DriverCertificateFound}");
        Console.WriteLine($"ArtifactsReady      : {readiness.HasAllArtifacts}");
        Console.WriteLine();
        Console.WriteLine("Use:");
        Console.WriteLine("  SecureVol.SetupHost install --enable-testsigning --autostart");
        Console.WriteLine("  SecureVol.SetupHost uninstall");

        return readiness.HasAllArtifacts ? 0 : 1;
    }

    private static int RunPlan(InstallerPlan plan)
    {
        var json = JsonSerializer.Serialize(plan, new JsonSerializerOptions
        {
            WriteIndented = true
        });

        Console.WriteLine(json);
        return 0;
    }

    private static int RunInstall(InstallerPlan plan, string[] args)
    {
        if (InstallerEngine.EnsureElevatedOrRelaunch(args.Prepend("install").ToArray()))
        {
            return 0;
        }

        var options = new InstallOptions(
            GetOption(args, "--target-root") ?? plan.DefaultInstallRoot,
            HasFlag(args, "--enable-testsigning"),
            HasFlag(args, "--autostart"),
            !HasFlag(args, "--no-start-menu-shortcuts"),
            GetOption(args, "--installer-source"));

        return InstallerEngine.Install(plan, options);
    }

    private static int RunUninstall(InstallerPlan plan, string[] args)
    {
        if (InstallerEngine.EnsureElevatedOrRelaunch(args.Prepend("uninstall").ToArray()))
        {
            return 0;
        }

        var options = new UninstallOptions(
            GetOption(args, "--target-root") ?? plan.DefaultInstallRoot);

        return InstallerEngine.Uninstall(plan, options);
    }

    private static int ShowUsage()
    {
        Console.Error.WriteLine("""
Usage: SecureVol.SetupHost [check|plan|install|repair|uninstall]

Commands:
  check
      Validate that the packaged payload contains the service, CLI, driver, and admin UI.

  plan
      Print the resolved payload/install plan as JSON.

  install [--target-root "C:\Program Files\SecureVol"] [--enable-testsigning] [--autostart] [--installer-source SecureVol.Installer.exe] [--no-start-menu-shortcuts]
      Copy the packaged payload into Program Files, install/update the service and driver,
      start the backend, and create the SecureVol Admin shortcut.

  repair
      Alias for install.

  uninstall [--target-root "C:\Program Files\SecureVol"]
      Stop/unload SecureVol, remove the driver service and Windows service, remove shortcuts,
      and delete installed payload folders where possible.
""");
        return 1;
    }

    private static string? GetOption(string[] args, string name)
    {
        var index = Array.FindIndex(args, arg => string.Equals(arg, name, StringComparison.OrdinalIgnoreCase));
        return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
    }

    private static bool HasFlag(string[] args, string name) =>
        args.Any(arg => string.Equals(arg, name, StringComparison.OrdinalIgnoreCase));
}
