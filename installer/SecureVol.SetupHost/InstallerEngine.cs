using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using SecureVol.Common;
using SecureVol.Common.Policy;

namespace SecureVol.SetupHost;

internal static class InstallerEngine
{
    public static bool EnsureElevatedOrRelaunch(string[] args)
    {
        if (IsElevated())
        {
            return false;
        }

        var executable = Environment.ProcessPath
                         ?? throw new InvalidOperationException("Unable to locate the current setup host executable.");

        var quotedArgs = string.Join(" ", args.Select(QuoteArgument));
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = executable,
            Arguments = quotedArgs,
            UseShellExecute = true,
            Verb = "runas"
        });

        if (process is null)
        {
            throw new InvalidOperationException("Failed to relaunch the installer with administrative rights.");
        }

        return true;
    }

    public static int Install(InstallerPlan plan, InstallOptions options)
    {
        var readiness = InstallerReadiness.FromPlan(plan);
        if (!readiness.HasAllArtifacts)
        {
            throw new InvalidOperationException("The setup payload is incomplete. Run 'SecureVol.SetupHost check' first.");
        }

        var targetRoot = Path.GetFullPath(options.TargetRoot);
        var installLayout = InstalledLayout.FromRoot(targetRoot);

        Console.WriteLine($"[SecureVol] Installing to '{targetRoot}'");
        Directory.CreateDirectory(targetRoot);

        // Existing installs may have the service running from the target path.
        // Stop mutable components before copying replacement payloads into place.
        TryStopService(plan.ServiceName);
        TryUnloadFilter(plan.DriverServiceName);

        CopyDirectory(Path.GetDirectoryName(plan.ServiceExecutable)!, installLayout.ServiceRoot);
        CopyDirectory(Path.GetDirectoryName(plan.CliExecutable)!, installLayout.CliRoot);
        CopyDirectory(Path.GetDirectoryName(plan.AppExecutable)!, installLayout.AppRoot);
        CopyDirectory(plan.SetupRoot, installLayout.SetupRoot);
        CopyDirectory(plan.DriverPackageDirectory, installLayout.DriverRoot);

        EnsureDefaultPolicyFile();
        ImportDriverCertificateIfPresent(plan.DriverCertificatePath);

        var rebootRequired = EnsureTestSigningIfNeeded(
            hasDriverCertificate: InstallerReadiness.FromPlan(plan).DriverCertificateFound,
            enableTestSigning: options.EnableTestSigning);

        InstallOrUpdateService(plan.ServiceName, installLayout.ServiceExecutable);
        InstallOrUpdateDriver(installLayout.DriverInfPath);
        StartService(plan.ServiceName);

        if (!rebootRequired)
        {
            EnsureFilterLoaded(plan.DriverServiceName);
        }

        if (options.CreateStartMenuShortcuts)
        {
            CreateStartMenuShortcuts(plan, installLayout);
        }

        Console.WriteLine();
        Console.WriteLine("[SecureVol] Install summary");
        Console.WriteLine($"InstallRoot      : {targetRoot}");
        Console.WriteLine($"AdminApp         : {installLayout.AppExecutable}");
        Console.WriteLine($"ServiceInstalled : {ServiceExists(plan.ServiceName)}");
        Console.WriteLine($"DriverInstalled  : {File.Exists(installLayout.DriverInfPath)}");
        Console.WriteLine($"DriverLoaded     : {IsServiceRunning(plan.DriverServiceName)}");
        Console.WriteLine($"PolicyFile       : {AppPaths.PolicyFilePath}");
        if (rebootRequired)
        {
            Console.WriteLine("RebootRequired   : True");
            Console.WriteLine("NextStep         : Reboot Windows, then launch SecureVol Admin from the Start Menu.");
        }
        else
        {
            Console.WriteLine("RebootRequired   : False");
        }

        return 0;
    }

    public static int Uninstall(InstallerPlan plan, UninstallOptions options)
    {
        var targetRoot = Path.GetFullPath(options.TargetRoot);
        var installLayout = InstalledLayout.FromRoot(targetRoot);

        Console.WriteLine($"[SecureVol] Uninstalling from '{targetRoot}'");

        TryUnloadFilter(plan.DriverServiceName);
        TryStopService(plan.ServiceName);

        if (File.Exists(installLayout.DriverInfPath))
        {
            TryUninstallDriver(installLayout.DriverInfPath);
        }

        TryDeleteService(plan.ServiceName);
        RemoveShortcuts(plan.StartMenuFolderName);

        TryDeleteDirectory(installLayout.AppRoot);
        TryDeleteDirectory(installLayout.CliRoot);
        TryDeleteDirectory(installLayout.ServiceRoot);
        TryDeleteDirectory(installLayout.DriverRoot);

        var runningFromInstallRoot = !string.IsNullOrWhiteSpace(Environment.ProcessPath) &&
                                     Path.GetFullPath(Environment.ProcessPath)
                                         .StartsWith(targetRoot, StringComparison.OrdinalIgnoreCase);

        if (!runningFromInstallRoot)
        {
            TryDeleteDirectory(installLayout.SetupRoot);
            TryDeleteDirectory(targetRoot);
        }
        else
        {
            Console.WriteLine("[SecureVol] Leaving the setup folder in place because the uninstaller is running from that directory.");
        }

        Console.WriteLine();
        Console.WriteLine("[SecureVol] Uninstall summary");
        Console.WriteLine($"InstallRoot        : {targetRoot}");
        Console.WriteLine($"ServiceStillExists : {ServiceExists(plan.ServiceName)}");
        Console.WriteLine($"DriverStillRunning : {IsServiceRunning(plan.DriverServiceName)}");
        Console.WriteLine("ProgramDataKept    : True");

        return 0;
    }

    private static void EnsureDefaultPolicyFile()
    {
        AppPaths.EnsureDefaultAcls();
        if (File.Exists(AppPaths.PolicyFilePath))
        {
            return;
        }

        var policy = new PolicyConfig
        {
            ProtectionEnabled = false,
            ProtectedVolume = string.Empty,
            DefaultExpectedUser = null,
            AllowRules = []
        };

        policy.Save(AppPaths.PolicyFilePath);
    }

    private static void ImportDriverCertificateIfPresent(string? certificatePath)
    {
        if (string.IsNullOrWhiteSpace(certificatePath) || !File.Exists(certificatePath))
        {
            return;
        }

        using var certificate = new X509Certificate2(certificatePath);
        AddCertificateToStore(StoreName.Root, StoreLocation.LocalMachine, certificate);
        AddCertificateToStore(StoreName.TrustedPublisher, StoreLocation.LocalMachine, certificate);
    }

    private static void AddCertificateToStore(StoreName storeName, StoreLocation storeLocation, X509Certificate2 certificate)
    {
        using var store = new X509Store(storeName, storeLocation);
        store.Open(OpenFlags.ReadWrite);
        var existing = store.Certificates.Find(X509FindType.FindByThumbprint, certificate.Thumbprint, validOnly: false);
        if (existing.Count == 0)
        {
            store.Add(certificate);
        }
    }

    private static bool EnsureTestSigningIfNeeded(bool hasDriverCertificate, bool enableTestSigning)
    {
        if (!hasDriverCertificate)
        {
            return false;
        }

        if (IsTestSigningEnabled())
        {
            return false;
        }

        if (!enableTestSigning)
        {
            throw new InvalidOperationException(
                "The packaged driver is test-signed. Rerun installation with '--enable-testsigning' or replace the package with a production-signed driver.");
        }

        RunProcess("bcdedit.exe", "/set testsigning on", "Failed to enable Windows test-signing mode.");
        return true;
    }

    private static bool IsTestSigningEnabled()
    {
        var output = RunProcessCapture("bcdedit.exe", "/enum", allowNonZeroExit: false);
        return output.Contains("testsigning", StringComparison.OrdinalIgnoreCase) &&
               output.Contains("Yes", StringComparison.OrdinalIgnoreCase);
    }

    private static void InstallOrUpdateService(string serviceName, string serviceExecutable)
    {
        TryStopService(serviceName);
        if (ServiceExists(serviceName))
        {
            RunProcess("sc.exe", $@"config {serviceName} binPath= ""{serviceExecutable}"" start= demand", "Failed to update the SecureVol service.");
        }
        else
        {
            RunProcess(
                "sc.exe",
                $@"create {serviceName} binPath= ""{serviceExecutable}"" start= demand DisplayName= ""SecureVol Service""",
                "Failed to create the SecureVol service.");
        }
    }

    private static void InstallOrUpdateDriver(string driverInfPath)
    {
        RunProcess(
            Path.Combine(Environment.SystemDirectory, "rundll32.exe"),
            $@"setupapi.dll,InstallHinfSection DefaultInstall.NTamd64 132 ""{driverInfPath}""",
            "Failed to install the SecureVol minifilter package.");
    }

    private static void TryUninstallDriver(string driverInfPath)
    {
        try
        {
            RunProcess(
                Path.Combine(Environment.SystemDirectory, "rundll32.exe"),
                $@"setupapi.dll,InstallHinfSection DefaultUninstall.NTamd64 132 ""{driverInfPath}""",
                "Failed to uninstall the SecureVol minifilter package.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SecureVol] Driver uninstall warning: {ex.Message}");
        }
    }

    private static void StartService(string serviceName)
    {
        if (GetServiceState(serviceName) == "RUNNING")
        {
            return;
        }

        RunProcess("sc.exe", $"start {serviceName}", "Failed to start the SecureVol service.");
        WaitForServiceState(serviceName, "RUNNING", TimeSpan.FromSeconds(20));
    }

    private static void TryStopService(string serviceName)
    {
        if (!ServiceExists(serviceName))
        {
            return;
        }

        var state = GetServiceState(serviceName);
        if (state is "STOPPED" or "STOP_PENDING")
        {
            if (state == "STOP_PENDING")
            {
                WaitForServiceState(serviceName, "STOPPED", TimeSpan.FromSeconds(20));
            }

            return;
        }

        var output = RunProcessCapture("sc.exe", $"stop {serviceName}", allowNonZeroExit: true, out var exitCode);
        if (exitCode != 0 &&
            !output.Contains("service has not been started", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException($"Failed to stop the SecureVol service. {output}".Trim());
        }

        WaitForServiceState(serviceName, "STOPPED", TimeSpan.FromSeconds(20));
    }

    private static void EnsureFilterLoaded(string driverServiceName)
    {
        if (IsServiceRunning(driverServiceName))
        {
            return;
        }

        var output = RunProcessCapture("fltmc.exe", $"load {driverServiceName}", allowNonZeroExit: true, out var exitCode);
        if (exitCode == 0 ||
            output.Contains("already loaded", StringComparison.OrdinalIgnoreCase) ||
            output.Contains("already running", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        throw new InvalidOperationException($"Failed to load the SecureVol minifilter. {output}".Trim());
    }

    private static void TryUnloadFilter(string driverServiceName)
    {
        var output = RunProcessCapture("fltmc.exe", $"unload {driverServiceName}", allowNonZeroExit: true, out var exitCode);
        if (exitCode == 0 ||
            output.Contains("not found", StringComparison.OrdinalIgnoreCase) ||
            output.Contains("is not currently loaded", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        Console.WriteLine($"[SecureVol] Filter unload warning: {output}".Trim());
    }

    private static void TryDeleteService(string serviceName)
    {
        if (!ServiceExists(serviceName))
        {
            return;
        }

        var output = RunProcessCapture("sc.exe", $"delete {serviceName}", allowNonZeroExit: true, out var exitCode);
        if (exitCode == 0)
        {
            return;
        }

        Console.WriteLine($"[SecureVol] Service delete warning: {output}".Trim());
    }

    private static bool ServiceExists(string serviceName)
    {
        _ = RunProcessCapture("sc.exe", $"query {serviceName}", allowNonZeroExit: true, out var exitCode);
        return exitCode == 0;
    }

    private static bool IsServiceRunning(string serviceName)
    {
        return GetServiceState(serviceName) == "RUNNING";
    }

    private static string? GetServiceState(string serviceName)
    {
        var output = RunProcessCapture("sc.exe", $"query {serviceName}", allowNonZeroExit: true, out var exitCode);
        if (exitCode != 0)
        {
            return null;
        }

        foreach (var line in output.Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries))
        {
            if (!line.Contains("STATE", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (line.Contains("RUNNING", StringComparison.OrdinalIgnoreCase))
            {
                return "RUNNING";
            }

            if (line.Contains("STOPPED", StringComparison.OrdinalIgnoreCase))
            {
                return "STOPPED";
            }

            if (line.Contains("STOP_PENDING", StringComparison.OrdinalIgnoreCase))
            {
                return "STOP_PENDING";
            }

            if (line.Contains("START_PENDING", StringComparison.OrdinalIgnoreCase))
            {
                return "START_PENDING";
            }
        }

        return null;
    }

    private static void WaitForServiceState(string serviceName, string expectedState, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            if (string.Equals(GetServiceState(serviceName), expectedState, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            Thread.Sleep(500);
        }

        throw new InvalidOperationException($"Timed out waiting for service '{serviceName}' to reach state '{expectedState}'.");
    }

    private static void CreateStartMenuShortcuts(InstallerPlan plan, InstalledLayout layout)
    {
        var commonPrograms = Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms);
        var shortcutRoot = Path.Combine(commonPrograms, plan.StartMenuFolderName);
        Directory.CreateDirectory(shortcutRoot);

        CreateShortcut(
            Path.Combine(shortcutRoot, "SecureVol Admin.lnk"),
            layout.AppExecutable,
            Path.GetDirectoryName(layout.AppExecutable)!,
            layout.AppExecutable);

        CreateShortcut(
            Path.Combine(shortcutRoot, "Uninstall SecureVol.lnk"),
            layout.SetupExecutable,
            Path.GetDirectoryName(layout.SetupExecutable)!,
            layout.SetupExecutable,
            "uninstall");
    }

    private static void RemoveShortcuts(string startMenuFolderName)
    {
        var commonPrograms = Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms);
        var shortcutRoot = Path.Combine(commonPrograms, startMenuFolderName);
        TryDeleteDirectory(shortcutRoot);
    }

    private static void CreateShortcut(string shortcutPath, string targetPath, string workingDirectory, string iconPath, string? arguments = null)
    {
        var shellType = Type.GetTypeFromProgID("WScript.Shell")
                        ?? throw new InvalidOperationException("WScript.Shell is not available for shortcut creation.");

        var shell = Activator.CreateInstance(shellType)
                    ?? throw new InvalidOperationException("Failed to create the Windows Script Host shell object.");

        object? shortcut = null;
        try
        {
            shortcut = shellType.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, shell, [shortcutPath]);
            var shortcutType = shortcut!.GetType();
            shortcutType.InvokeMember("TargetPath", BindingFlags.SetProperty, null, shortcut, [targetPath]);
            shortcutType.InvokeMember("WorkingDirectory", BindingFlags.SetProperty, null, shortcut, [workingDirectory]);
            shortcutType.InvokeMember("IconLocation", BindingFlags.SetProperty, null, shortcut, [$"{iconPath},0"]);
            if (!string.IsNullOrWhiteSpace(arguments))
            {
                shortcutType.InvokeMember("Arguments", BindingFlags.SetProperty, null, shortcut, [arguments]);
            }

            shortcutType.InvokeMember("Save", BindingFlags.InvokeMethod, null, shortcut, null);
        }
        finally
        {
            if (shortcut is not null)
            {
                _ = System.Runtime.InteropServices.Marshal.FinalReleaseComObject(shortcut);
            }

            _ = System.Runtime.InteropServices.Marshal.FinalReleaseComObject(shell);
        }
    }

    private static void CopyDirectory(string sourceRoot, string destinationRoot)
    {
        if (!Directory.Exists(sourceRoot))
        {
            throw new InvalidOperationException($"Payload directory '{sourceRoot}' does not exist.");
        }

        Directory.CreateDirectory(destinationRoot);

        foreach (var directory in Directory.EnumerateDirectories(sourceRoot, "*", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(sourceRoot, directory);
            Directory.CreateDirectory(Path.Combine(destinationRoot, relative));
        }

        foreach (var file in Directory.EnumerateFiles(sourceRoot, "*", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(sourceRoot, file);
            var destinationFile = Path.Combine(destinationRoot, relative);
            Directory.CreateDirectory(Path.GetDirectoryName(destinationFile)!);
            File.Copy(file, destinationFile, overwrite: true);
        }
    }

    private static void TryDeleteDirectory(string path)
    {
        if (!Directory.Exists(path))
        {
            return;
        }

        try
        {
            Directory.Delete(path, recursive: true);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SecureVol] Cleanup warning for '{path}': {ex.Message}");
        }
    }

    private static void RunProcess(string fileName, string arguments, string failureMessage)
    {
        var output = RunProcessCapture(fileName, arguments, allowNonZeroExit: true, out var exitCode);
        if (exitCode != 0)
        {
            throw new InvalidOperationException($"{failureMessage} {output}".Trim());
        }
    }

    private static string RunProcessCapture(string fileName, string arguments, bool allowNonZeroExit)
    {
        return RunProcessCapture(fileName, arguments, allowNonZeroExit, out _);
    }

    private static string RunProcessCapture(string fileName, string arguments, bool allowNonZeroExit, out int exitCode)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            }
        };

        process.Start();
        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        process.WaitForExit();
        exitCode = process.ExitCode;

        var output = string.Join(Environment.NewLine, new[] { stdout, stderr }.Where(text => !string.IsNullOrWhiteSpace(text))).Trim();
        if (!allowNonZeroExit && exitCode != 0)
        {
            throw new InvalidOperationException(output);
        }

        return output;
    }

    private static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

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

    private sealed record InstalledLayout(
        string Root,
        string ServiceRoot,
        string CliRoot,
        string AppRoot,
        string DriverRoot,
        string SetupRoot,
        string ServiceExecutable,
        string CliExecutable,
        string AppExecutable,
        string DriverInfPath,
        string SetupExecutable)
    {
        public static InstalledLayout FromRoot(string root)
        {
            var normalizedRoot = Path.GetFullPath(root);
            var serviceRoot = Path.Combine(normalizedRoot, "service");
            var cliRoot = Path.Combine(normalizedRoot, "cli");
            var appRoot = Path.Combine(normalizedRoot, "app");
            var driverRoot = Path.Combine(normalizedRoot, "driver");
            var setupRoot = Path.Combine(normalizedRoot, "setup");

            return new InstalledLayout(
                normalizedRoot,
                serviceRoot,
                cliRoot,
                appRoot,
                driverRoot,
                setupRoot,
                Path.Combine(serviceRoot, "SecureVol.Service.exe"),
                Path.Combine(cliRoot, "securevol.exe"),
                Directory.Exists(appRoot)
                    ? Directory.EnumerateFiles(appRoot, "SecureVol*.exe", SearchOption.TopDirectoryOnly)
                        .FirstOrDefault(path => !path.EndsWith("SecureVol.SetupHost.exe", StringComparison.OrdinalIgnoreCase))
                      ?? Path.Combine(appRoot, "SecureVol.ImGui.exe")
                    : Path.Combine(appRoot, "SecureVol.ImGui.exe"),
                Path.Combine(driverRoot, "SecureVolFlt.inf"),
                Path.Combine(setupRoot, "SecureVol.SetupHost.exe"));
        }
    }
}
