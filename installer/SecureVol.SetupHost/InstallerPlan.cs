namespace SecureVol.SetupHost;

public sealed record InstallerPlan(
    string RepoRoot,
    string ServiceExecutable,
    string CliExecutable,
    string DriverPackageDirectory,
    string DriverSysPath,
    string DriverInfPath,
    string DriverCatPath,
    string ServiceName,
    string DriverServiceName)
{
    public static InstallerPlan FromRepoRoot(string repoRoot)
    {
        var serviceExecutable = Path.Combine(repoRoot, "out", "service", "SecureVol.Service.exe");
        var cliExecutable = Path.Combine(repoRoot, "out", "cli", "securevol.exe");
        var driverPackageDirectory = Path.Combine(repoRoot, "out", "driver", "package");

        return new InstallerPlan(
            repoRoot,
            serviceExecutable,
            cliExecutable,
            driverPackageDirectory,
            Path.Combine(driverPackageDirectory, "SecureVolFlt.sys"),
            Path.Combine(driverPackageDirectory, "SecureVolFlt.inf"),
            Path.Combine(driverPackageDirectory, "SecureVolFlt.cat"),
            "SecureVolSvc",
            "SecureVolFlt");
    }
}

public sealed record InstallerReadiness(
    bool IsElevated,
    bool ServiceExecutableFound,
    bool CliExecutableFound,
    bool DriverSysFound,
    bool DriverInfFound,
    bool DriverCatFound)
{
    public bool HasAllArtifacts =>
        ServiceExecutableFound &&
        CliExecutableFound &&
        DriverSysFound &&
        DriverInfFound &&
        DriverCatFound;
}
