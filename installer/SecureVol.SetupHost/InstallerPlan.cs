namespace SecureVol.SetupHost;

public sealed record InstallerPlan(
    string LayoutMode,
    string SourceRoot,
    string PayloadRoot,
    string SetupRoot,
    string ServiceExecutable,
    string CliExecutable,
    string AppExecutable,
    string DriverPackageDirectory,
    string DriverSysPath,
    string DriverInfPath,
    string DriverCatPath,
    string? DriverCertificatePath,
    string DefaultInstallRoot,
    string ServiceName,
    string DriverServiceName,
    string StartMenuFolderName)
{
    public static InstallerPlan Resolve(string baseDirectory)
    {
        var releasePlan = TryResolveReleaseLayout(baseDirectory);
        if (releasePlan is not null)
        {
            return releasePlan;
        }

        return ResolveRepoLayout(baseDirectory);
    }

    private static InstallerPlan? TryResolveReleaseLayout(string baseDirectory)
    {
        var setupRoot = Path.GetFullPath(baseDirectory);
        var payloadRoot = Path.GetFullPath(Path.Combine(setupRoot, ".."));
        var releaseRoot = Path.GetFullPath(Path.Combine(payloadRoot, ".."));

        var serviceExecutable = Path.Combine(payloadRoot, "service", "SecureVol.Service.exe");
        var cliExecutable = Path.Combine(payloadRoot, "cli", "securevol.exe");
        var appExecutable = FindAppExecutable(Path.Combine(payloadRoot, "app"));
        var driverPackageDirectory = Path.Combine(releaseRoot, "driver");

        if (!File.Exists(serviceExecutable) &&
            !File.Exists(cliExecutable) &&
            !Directory.Exists(driverPackageDirectory))
        {
            return null;
        }

        return BuildPlan(
            "release",
            releaseRoot,
            payloadRoot,
            setupRoot,
            serviceExecutable,
            cliExecutable,
            appExecutable,
            driverPackageDirectory);
    }

    private static InstallerPlan ResolveRepoLayout(string baseDirectory)
    {
        var current = Path.GetFullPath(baseDirectory);
        for (var i = 0; i < 8; i++)
        {
            if (File.Exists(Path.Combine(current, "SecureVol.sln")))
            {
                var outRoot = Path.Combine(current, "out");
                var setupRoot = Path.Combine(outRoot, "setup");
                var serviceExecutable = Path.Combine(outRoot, "service", "SecureVol.Service.exe");
                var cliExecutable = Path.Combine(outRoot, "cli", "securevol.exe");
                var appExecutable = FindAppExecutable(outRoot);
                var driverPackageDirectory = Path.Combine(outRoot, "driver", "package");

                return BuildPlan(
                    "repo",
                    current,
                    outRoot,
                    setupRoot,
                    serviceExecutable,
                    cliExecutable,
                    appExecutable,
                    driverPackageDirectory);
            }

            var parent = Directory.GetParent(current);
            if (parent is null)
            {
                break;
            }

            current = parent.FullName;
        }

        return BuildPlan(
            "unknown",
            Path.GetFullPath(baseDirectory),
            Path.GetFullPath(baseDirectory),
            Path.GetFullPath(baseDirectory),
            Path.Combine(baseDirectory, "service", "SecureVol.Service.exe"),
            Path.Combine(baseDirectory, "cli", "securevol.exe"),
            string.Empty,
            Path.Combine(baseDirectory, "driver"));
    }

    private static InstallerPlan BuildPlan(
        string layoutMode,
        string sourceRoot,
        string payloadRoot,
        string setupRoot,
        string serviceExecutable,
        string cliExecutable,
        string appExecutable,
        string driverPackageDirectory)
    {
        var defaultInstallRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "SecureVol");

        var certificatePath = Directory.Exists(driverPackageDirectory)
            ? Directory.EnumerateFiles(driverPackageDirectory, "*.cer", SearchOption.TopDirectoryOnly).FirstOrDefault()
            : null;

        return new InstallerPlan(
            layoutMode,
            sourceRoot,
            payloadRoot,
            setupRoot,
            serviceExecutable,
            cliExecutable,
            appExecutable,
            driverPackageDirectory,
            Path.Combine(driverPackageDirectory, "SecureVolFlt.sys"),
            Path.Combine(driverPackageDirectory, "SecureVolFlt.inf"),
            Path.Combine(driverPackageDirectory, "SecureVolFlt.cat"),
            certificatePath,
            defaultInstallRoot,
            "SecureVolSvc",
            "SecureVolFlt",
            "SecureVol");
    }

    private static string FindAppExecutable(string searchRoot)
    {
        if (!Directory.Exists(searchRoot))
        {
            return string.Empty;
        }

        var preferredNames = new[]
        {
            "SecureVol.ImGui.exe",
            "SecureVol.App.exe"
        };

        foreach (var name in preferredNames)
        {
            var exact = Directory.EnumerateFiles(searchRoot, name, SearchOption.AllDirectories).FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(exact))
            {
                return exact;
            }
        }

        return Directory.EnumerateFiles(searchRoot, "SecureVol*.exe", SearchOption.AllDirectories)
            .FirstOrDefault(path =>
                !path.EndsWith("SecureVol.SetupHost.exe", StringComparison.OrdinalIgnoreCase) &&
                !path.EndsWith("SecureVol.Service.exe", StringComparison.OrdinalIgnoreCase))
            ?? string.Empty;
    }
}

public sealed record InstallerReadiness(
    bool ServiceExecutableFound,
    bool CliExecutableFound,
    bool AppExecutableFound,
    bool DriverSysFound,
    bool DriverInfFound,
    bool DriverCatFound,
    bool DriverCertificateFound)
{
    public bool HasAllArtifacts =>
        ServiceExecutableFound &&
        CliExecutableFound &&
        AppExecutableFound &&
        DriverSysFound &&
        DriverInfFound &&
        DriverCatFound;

    public static InstallerReadiness FromPlan(InstallerPlan plan) =>
        new(
            File.Exists(plan.ServiceExecutable),
            File.Exists(plan.CliExecutable),
            File.Exists(plan.AppExecutable),
            File.Exists(plan.DriverSysPath),
            File.Exists(plan.DriverInfPath),
            File.Exists(plan.DriverCatPath),
            !string.IsNullOrWhiteSpace(plan.DriverCertificatePath) && File.Exists(plan.DriverCertificatePath));
}

public readonly record struct InstallOptions(
    string TargetRoot,
    bool EnableTestSigning,
    bool AutoStart,
    bool CreateStartMenuShortcuts);

public readonly record struct UninstallOptions(
    string TargetRoot);
