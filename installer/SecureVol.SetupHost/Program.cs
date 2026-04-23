using System.Security.Principal;
using System.Text.Json;

namespace SecureVol.SetupHost;

internal static class Program
{
    public static int Main(string[] args)
    {
        var repoRoot = ResolveRepoRoot();
        var plan = InstallerPlan.FromRepoRoot(repoRoot);
        var command = args.FirstOrDefault()?.Trim().ToLowerInvariant() ?? "check";

        return command switch
        {
            "check" => RunCheck(plan),
            "plan" => RunPlan(plan),
            _ => ShowUsage()
        };
    }

    private static int RunCheck(InstallerPlan plan)
    {
        var readiness = new InstallerReadiness(
            IsElevated(),
            File.Exists(plan.ServiceExecutable),
            File.Exists(plan.CliExecutable),
            File.Exists(plan.DriverSysPath),
            File.Exists(plan.DriverInfPath),
            File.Exists(plan.DriverCatPath));

        Console.WriteLine("SecureVol setup host scaffold");
        Console.WriteLine($"RepoRoot            : {plan.RepoRoot}");
        Console.WriteLine($"IsElevated          : {readiness.IsElevated}");
        Console.WriteLine($"ServiceExecutable   : {readiness.ServiceExecutableFound}");
        Console.WriteLine($"CliExecutable       : {readiness.CliExecutableFound}");
        Console.WriteLine($"DriverSys           : {readiness.DriverSysFound}");
        Console.WriteLine($"DriverInf           : {readiness.DriverInfFound}");
        Console.WriteLine($"DriverCat           : {readiness.DriverCatFound}");
        Console.WriteLine($"ArtifactsReady      : {readiness.HasAllArtifacts}");
        Console.WriteLine();
        Console.WriteLine("This is the installer/bootstrapper foundation. The next step is wiring these checks");
        Console.WriteLine("into a real end-user setup workflow that installs the service, driver, shortcuts, and UI.");

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

    private static int ShowUsage()
    {
        Console.Error.WriteLine("Usage: SecureVol.SetupHost [check|plan]");
        return 1;
    }

    private static string ResolveRepoRoot()
    {
        var current = AppContext.BaseDirectory;
        for (var i = 0; i < 6; i++)
        {
            if (File.Exists(Path.Combine(current, "SecureVol.sln")))
            {
                return current;
            }

            var parent = Directory.GetParent(current);
            if (parent is null)
            {
                break;
            }

            current = parent.FullName;
        }

        return Directory.GetCurrentDirectory();
    }

    private static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }
}
