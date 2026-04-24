using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using Microsoft.Win32;
using SecureVol.Common;
using SecureVol.Common.Policy;

namespace SecureVol.SetupHost;

internal static class InstallerEngine
{
    private const int MoveFileReplaceExisting = 0x1;
    private const int MoveFileDelayUntilReboot = 0x4;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool MoveFileEx(string lpExistingFileName, string? lpNewFileName, int dwFlags);

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

        PrepareInstallTargetForUpdate(targetRoot, plan.ServiceName, plan.DriverServiceName);

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
        var driverUpdateDeferred = InstallOrUpdateDriver(installLayout.DriverInfPath, installLayout.DriverRoot, plan.DriverServiceName);
        StartService(plan.ServiceName);

        if (driverUpdateDeferred)
        {
            rebootRequired = true;
            Console.WriteLine("[SecureVol] Driver update is deferred until reboot because the minifilter is already loaded.");
        }

        if (!rebootRequired &&
            !TryEnsureFilterLoaded(
                plan.DriverServiceName,
                readiness.DriverCertificateFound,
                out var deferredLoadReason))
        {
            rebootRequired = true;
            Console.WriteLine($"[SecureVol] {deferredLoadReason}");
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

    private static void PrepareInstallTargetForUpdate(string targetRoot, string serviceName, string driverServiceName)
    {
        // Existing installs may have a running service, an orphaned worker, or an open UI process
        // loaded from the current install root. Clear those first so in-place payload replacement works.
        TryStopService(serviceName);
        if (IsServiceRunning(driverServiceName))
        {
            Console.WriteLine("[SecureVol] Existing minifilter is loaded; repair will leave the live driver in place until reboot.");
        }

        TerminateProcessesUnderPath(targetRoot, TimeSpan.FromSeconds(15));
    }

    public static int Uninstall(InstallerPlan plan, UninstallOptions options)
    {
        var targetRoot = Path.GetFullPath(options.TargetRoot);
        var installLayout = InstalledLayout.FromRoot(targetRoot);

        Console.WriteLine($"[SecureVol] Uninstalling from '{targetRoot}'");

        DisableProtectionForRemoval();
        TryStopService(plan.ServiceName);

        TryDeleteService(plan.ServiceName);

        var driverStillRunning = IsServiceRunning(plan.DriverServiceName);
        if (driverStillRunning)
        {
            Console.WriteLine("[SecureVol] SecureVolFlt is still loaded. Skipping live driver unload for system safety.");
            Console.WriteLine("[SecureVol] Driver service and SecureVolFlt.sys removal are deferred until after reboot.");
            TryDisableDriverAutostart(plan.DriverServiceName);
            TryDeleteInstalledDriverBinary(plan.DriverServiceName);
        }
        else
        {
            TryDeleteService(plan.DriverServiceName);
            TryDeleteInstalledDriverBinary(plan.DriverServiceName);
        }

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
        Console.WriteLine($"DriverStillRunning : {driverStillRunning}");
        Console.WriteLine($"RebootRequired   : {driverStillRunning}");
        if (driverStillRunning)
        {
            Console.WriteLine("NextStep           : Reboot Windows to finish unloading SecureVolFlt safely.");
        }

        Console.WriteLine("ProgramDataKept    : True");

        return 0;
    }

    private static void EnsureDefaultPolicyFile()
    {
        AppPaths.EnsureDefaultAcls();
        if (File.Exists(AppPaths.PolicyFilePath))
        {
            TrySeedFirstRunPolicy();
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
        TrySeedFirstRunPolicy();
    }

    private static void TrySeedFirstRunPolicy()
    {
        try
        {
            var policy = PolicyConfig.Load(AppPaths.PolicyFilePath);
            if (!string.IsNullOrWhiteSpace(policy.ProtectedVolume) || policy.AllowRules.Count > 0)
            {
                return;
            }

            var mountedDrive = ResolvePreferredMountedDrive();
            if (mountedDrive is null)
            {
                return;
            }

            var currentUser = WindowsIdentity.GetCurrent().Name;
            var seeded = new PolicyConfig
            {
                ProtectionEnabled = false,
                ProtectedVolume = VolumeHelpers.ResolveVolumeGuid(mountedDrive),
                DefaultExpectedUser = string.IsNullOrWhiteSpace(currentUser) ? null : currentUser,
                AllowRules = []
            };

            seeded.Save(AppPaths.PolicyFilePath);
            Console.WriteLine($"[SecureVol] First-run policy initialized for mounted drive '{mountedDrive}' as user '{seeded.DefaultExpectedUser ?? "<none>"}'.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SecureVol] First-run policy initialization warning: {ex.Message}");
        }
    }

    private static string? ResolvePreferredMountedDrive()
    {
        const string preferredDrive = @"A:\";
        try
        {
            if (Directory.Exists(preferredDrive))
            {
                var drive = new DriveInfo(preferredDrive);
                if (drive.IsReady)
                {
                    return preferredDrive;
                }
            }
        }
        catch
        {
            return null;
        }

        return null;
    }

    private static void DisableProtectionForRemoval()
    {
        try
        {
            AppPaths.EnsureDefaultAcls();
            var policy = File.Exists(AppPaths.PolicyFilePath)
                ? PolicyConfig.Load(AppPaths.PolicyFilePath)
                : new PolicyConfig();

            if (policy.ProtectionEnabled)
            {
                (policy with { ProtectionEnabled = false }).Save(AppPaths.PolicyFilePath);
                Console.WriteLine("[SecureVol] Policy file updated: protection disabled before removal.");
            }
            else
            {
                Console.WriteLine("[SecureVol] Policy file already has protection disabled.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SecureVol] Policy-disable warning: {ex.Message}");
        }

        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(4));
            var response = new AdminPipeClient()
                .SendAsync(new AdminRequest { Command = "set-protection", ProtectionEnabled = false }, cts.Token)
                .GetAwaiter()
                .GetResult();

            Console.WriteLine(response.Success
                ? "[SecureVol] Live driver policy disabled through SecureVolSvc."
                : $"[SecureVol] Live policy-disable warning: {response.Message}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SecureVol] Live policy-disable warning: {ex.Message}");
        }
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

    private static bool InstallOrUpdateDriver(string driverInfPath, string driverPackageRoot, string driverServiceName)
    {
        var packagedDriverBinary = Path.Combine(driverPackageRoot, "SecureVolFlt.sys");
        var installedDriverBinary = Path.Combine(Environment.SystemDirectory, "drivers", "SecureVolFlt.sys");

        if (!File.Exists(packagedDriverBinary))
        {
            throw new InvalidOperationException($"Packaged SecureVolFlt.sys was not found at '{packagedDriverBinary}'.");
        }

        TryStageDriverPackage(driverInfPath);

        if (IsServiceRunning(driverServiceName) && File.Exists(installedDriverBinary))
        {
            Console.WriteLine("[SecureVol] SecureVolFlt is already loaded. Skipping live driver binary replacement.");
            ScheduleDriverReplacementOnReboot(packagedDriverBinary, installedDriverBinary);
            EnsureMinifilterServiceRegistration(driverServiceName, installedDriverBinary);
            return true;
        }

        Console.WriteLine($"[SecureVol] Copying driver binary to '{installedDriverBinary}'.");
        Directory.CreateDirectory(Path.GetDirectoryName(installedDriverBinary)!);
        CopyFileWithRetry(packagedDriverBinary, installedDriverBinary, TimeSpan.FromSeconds(10));

        EnsureMinifilterServiceRegistration(driverServiceName, installedDriverBinary);
        return false;
    }

    private static void ScheduleDriverReplacementOnReboot(string sourceDriverBinary, string installedDriverBinary)
    {
        var pendingRoot = Path.Combine(AppPaths.ProgramDataRoot, "pending");
        Directory.CreateDirectory(pendingRoot);

        var pendingDriverBinary = Path.Combine(pendingRoot, "SecureVolFlt.sys");
        File.Copy(sourceDriverBinary, pendingDriverBinary, overwrite: true);

        if (!MoveFileEx(
                pendingDriverBinary,
                installedDriverBinary,
                MoveFileDelayUntilReboot | MoveFileReplaceExisting))
        {
            throw new InvalidOperationException(
                $"Failed to schedule SecureVolFlt.sys replacement at reboot. Win32={Marshal.GetLastWin32Error()}");
        }

        Console.WriteLine($"[SecureVol] Scheduled SecureVolFlt.sys replacement at next reboot from '{pendingDriverBinary}'.");
    }

    private static void TryStageDriverPackage(string driverInfPath)
    {
        var output = RunProcessCapture("pnputil.exe", $@"/add-driver ""{driverInfPath}""", allowNonZeroExit: true, out var exitCode);
        if (exitCode == 0)
        {
            Console.WriteLine("[SecureVol] Driver package staged with pnputil.");
            return;
        }

        // The minifilter service is registered explicitly below. Staging is useful for Driver Store
        // bookkeeping, but it must not surface SetupAPI GUI popups or block local repair installs.
        Console.WriteLine($"[SecureVol] pnputil staging warning: {output}".Trim());
    }

    private static void EnsureMinifilterServiceRegistration(string driverServiceName, string installedDriverBinary)
    {
        var binaryPath = @"\SystemRoot\System32\drivers\" + Path.GetFileName(installedDriverBinary);
        var serviceDisplayName = "SecureVol VeraCrypt Volume Minifilter";

        if (ServiceExists(driverServiceName))
        {
            RunProcess(
                "sc.exe",
                $@"config {driverServiceName} type= filesys start= demand error= normal binPath= ""{binaryPath}"" group= ""FSFilter Activity Monitor"" depend= FltMgr DisplayName= ""{serviceDisplayName}""",
                "Failed to update the SecureVol minifilter service.");
        }
        else
        {
            RunProcess(
                "sc.exe",
                $@"create {driverServiceName} type= filesys start= demand error= normal binPath= ""{binaryPath}"" group= ""FSFilter Activity Monitor"" depend= FltMgr DisplayName= ""{serviceDisplayName}""",
                "Failed to create the SecureVol minifilter service.");
        }

        RunProcess(
            "sc.exe",
            $@"description {driverServiceName} ""{serviceDisplayName}""",
            "Failed to set the SecureVol minifilter description.");

        using var serviceKey = Registry.LocalMachine.CreateSubKey($@"SYSTEM\CurrentControlSet\Services\{driverServiceName}");
        if (serviceKey is null)
        {
            throw new InvalidOperationException($"The service registry key for '{driverServiceName}' could not be opened.");
        }

        serviceKey.SetValue("Type", 2, RegistryValueKind.DWord);
        serviceKey.SetValue("Start", 3, RegistryValueKind.DWord);
        serviceKey.SetValue("ErrorControl", 1, RegistryValueKind.DWord);
        serviceKey.SetValue("ImagePath", binaryPath, RegistryValueKind.ExpandString);
        serviceKey.SetValue("Group", "FSFilter Activity Monitor", RegistryValueKind.String);
        serviceKey.SetValue("DependOnService", new[] { "FltMgr" }, RegistryValueKind.MultiString);
        serviceKey.SetValue("DisplayName", serviceDisplayName, RegistryValueKind.String);
        serviceKey.SetValue("Description", serviceDisplayName, RegistryValueKind.String);

        using var instancesKey = serviceKey.CreateSubKey("Instances");
        if (instancesKey is null)
        {
            throw new InvalidOperationException($"The Instances registry key for '{driverServiceName}' could not be created.");
        }

        const string defaultInstance = "SecureVolFlt Instance";
        instancesKey.SetValue("DefaultInstance", defaultInstance, RegistryValueKind.String);

        using var defaultInstanceKey = instancesKey.CreateSubKey(defaultInstance);
        if (defaultInstanceKey is null)
        {
            throw new InvalidOperationException($"The default minifilter instance key for '{driverServiceName}' could not be created.");
        }

        defaultInstanceKey.SetValue("Altitude", "370030", RegistryValueKind.String);
        defaultInstanceKey.SetValue("Flags", 0, RegistryValueKind.DWord);
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
        if (state == "STOPPED")
        {
            return;
        }

        if (state != "STOP_PENDING")
        {
            var output = RunProcessCapture("sc.exe", $"stop {serviceName}", allowNonZeroExit: true, out var exitCode);
            if (exitCode != 0 &&
                !output.Contains("service has not been started", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException($"Failed to stop the SecureVol service. {output}".Trim());
            }
        }

        if (TryWaitForServiceState(serviceName, "STOPPED", TimeSpan.FromSeconds(20)))
        {
            return;
        }

        ForceStopServiceProcess(serviceName);

        if (!TryWaitForServiceState(serviceName, "STOPPED", TimeSpan.FromSeconds(10)))
        {
            throw new InvalidOperationException($"Timed out waiting for service '{serviceName}' to reach state 'STOPPED'.");
        }
    }

    private static void ForceStopServiceProcess(string serviceName)
    {
        var serviceProcessId = GetServiceProcessId(serviceName);
        if (!serviceProcessId.HasValue || serviceProcessId.Value <= 0)
        {
            return;
        }

        try
        {
            using var process = Process.GetProcessById(serviceProcessId.Value);
            Console.WriteLine($"[SecureVol] Forcing hung service '{serviceName}' to exit via PID {serviceProcessId.Value}.");
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit(5000);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SecureVol] Forced service-stop warning for '{serviceName}': {ex.Message}");
        }
    }

    private static bool TryEnsureFilterLoaded(string driverServiceName, bool testSignedDriver, out string? deferredReason)
    {
        deferredReason = null;

        if (IsServiceRunning(driverServiceName))
        {
            return true;
        }

        var output = RunProcessCapture("fltmc.exe", $"load {driverServiceName}", allowNonZeroExit: true, out var exitCode);
        if (exitCode == 0 ||
            output.Contains("already loaded", StringComparison.OrdinalIgnoreCase) ||
            output.Contains("already running", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (testSignedDriver && IsDriverSignatureRebootCase(output))
        {
            deferredReason =
                "Driver load is deferred until after reboot because Windows is still rejecting the packaged test-signed minifilter in the current boot session. Reboot Windows, then run the installer again.";
            return false;
        }

        throw new InvalidOperationException($"Failed to load the SecureVol minifilter. {output}".Trim());
    }

    private static bool IsDriverSignatureRebootCase(string output)
    {
        return output.Contains("0x80070241", StringComparison.OrdinalIgnoreCase) ||
               output.Contains("cannot verify the digital signature", StringComparison.OrdinalIgnoreCase) ||
               output.Contains("Windows cannot verify the digital signature", StringComparison.OrdinalIgnoreCase);
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

    private static void TryDisableDriverAutostart(string driverServiceName)
    {
        if (!ServiceExists(driverServiceName))
        {
            return;
        }

        try
        {
            RunProcess(
                "sc.exe",
                $@"config {driverServiceName} start= demand",
                "Failed to keep the SecureVol minifilter service on demand start.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SecureVol] Driver autostart cleanup warning: {ex.Message}");
        }
    }

    private static void TryDeleteInstalledDriverBinary(string driverServiceName)
    {
        var installedDriverBinary = Path.Combine(Environment.SystemDirectory, "drivers", "SecureVolFlt.sys");
        if (!File.Exists(installedDriverBinary))
        {
            return;
        }

        try
        {
            if (IsServiceRunning(driverServiceName))
            {
                if (!MoveFileEx(installedDriverBinary, null, MoveFileDelayUntilReboot))
                {
                    throw new InvalidOperationException(
                        $"MoveFileEx delete scheduling failed. Win32={Marshal.GetLastWin32Error()}");
                }

                Console.WriteLine($"[SecureVol] Scheduled '{installedDriverBinary}' for removal at next reboot.");
            }
            else
            {
                File.Delete(installedDriverBinary);
                Console.WriteLine($"[SecureVol] Removed '{installedDriverBinary}'.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[SecureVol] Driver binary cleanup warning: {ex.Message}");
        }
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
        if (TryWaitForServiceState(serviceName, expectedState, timeout))
        {
            return;
        }

        throw new InvalidOperationException($"Timed out waiting for service '{serviceName}' to reach state '{expectedState}'.");
    }

    private static bool TryWaitForServiceState(string serviceName, string expectedState, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            if (string.Equals(GetServiceState(serviceName), expectedState, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            Thread.Sleep(500);
        }
        
        return false;
    }

    private static int? GetServiceProcessId(string serviceName)
    {
        var output = RunProcessCapture("sc.exe", $"queryex {serviceName}", allowNonZeroExit: true, out var exitCode);
        if (exitCode != 0)
        {
            return null;
        }

        foreach (var rawLine in output.Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries))
        {
            var line = rawLine.Trim();
            if (!line.StartsWith("PID", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var parts = line.Split(':', 2, StringSplitOptions.TrimEntries);
            if (parts.Length == 2 && int.TryParse(parts[1], out var pid))
            {
                return pid;
            }
        }

        return null;
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
            CopyFileWithRetry(file, destinationFile, TimeSpan.FromSeconds(10));
        }
    }

    private static void CopyFileWithRetry(string sourceFile, string destinationFile, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        Exception? lastError = null;

        while (DateTime.UtcNow < deadline)
        {
            try
            {
                File.Copy(sourceFile, destinationFile, overwrite: true);
                return;
            }
            catch (IOException ex)
            {
                lastError = ex;
            }
            catch (UnauthorizedAccessException ex)
            {
                lastError = ex;
            }

            Thread.Sleep(500);
        }

        throw new InvalidOperationException(
            $"Failed to replace '{destinationFile}' within {timeout.TotalSeconds:0} seconds. {lastError?.Message}",
            lastError);
    }

    private static void TerminateProcessesUnderPath(string rootPath, TimeSpan timeout)
    {
        if (!Directory.Exists(rootPath))
        {
            return;
        }

        var normalizedRoot = EnsureTrailingSeparator(Path.GetFullPath(rootPath));
        var currentProcessId = Environment.ProcessId;
        var deadline = DateTime.UtcNow + timeout;

        while (DateTime.UtcNow < deadline)
        {
            var matchingProcesses = GetProcessesUnderPath(normalizedRoot, currentProcessId);
            if (matchingProcesses.Count == 0)
            {
                return;
            }

            foreach (var process in matchingProcesses)
            {
                try
                {
                    Console.WriteLine($"[SecureVol] Stopping in-use process PID={process.Id} Path='{TryGetProcessPath(process)}'");
                    if (!process.HasExited && process.CloseMainWindow())
                    {
                        process.WaitForExit(2000);
                    }

                    if (!process.HasExited)
                    {
                        process.Kill(entireProcessTree: true);
                        process.WaitForExit(5000);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[SecureVol] Process termination warning for PID={process.Id}: {ex.Message}");
                }
                finally
                {
                    process.Dispose();
                }
            }

            Thread.Sleep(500);
        }

        var survivors = GetProcessesUnderPath(normalizedRoot, currentProcessId);
        if (survivors.Count == 0)
        {
            return;
        }

        var summary = string.Join(
            ", ",
            survivors.Select(process => $"{process.Id}:{Path.GetFileName(TryGetProcessPath(process) ?? process.ProcessName)}"));

        foreach (var process in survivors)
        {
            process.Dispose();
        }

        throw new InvalidOperationException(
            $"Timed out waiting for existing SecureVol processes to exit from '{rootPath}'. Remaining processes: {summary}");
    }

    private static List<Process> GetProcessesUnderPath(string normalizedRoot, int currentProcessId)
    {
        var result = new List<Process>();

        foreach (var process in Process.GetProcesses())
        {
            try
            {
                if (process.Id == currentProcessId || process.HasExited)
                {
                    process.Dispose();
                    continue;
                }

                var processPath = TryGetProcessPath(process);
                if (string.IsNullOrWhiteSpace(processPath))
                {
                    process.Dispose();
                    continue;
                }

                var normalizedProcessPath = Path.GetFullPath(processPath);
                if (normalizedProcessPath.StartsWith(normalizedRoot, StringComparison.OrdinalIgnoreCase))
                {
                    result.Add(process);
                }
                else
                {
                    process.Dispose();
                }
            }
            catch
            {
                process.Dispose();
            }
        }

        return result;
    }

    private static string? TryGetProcessPath(Process process)
    {
        try
        {
            return process.MainModule?.FileName;
        }
        catch
        {
            return null;
        }
    }

    private static string EnsureTrailingSeparator(string path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return path;
        }

        return path.EndsWith(Path.DirectorySeparatorChar) || path.EndsWith(Path.AltDirectorySeparatorChar)
            ? path
            : path + Path.DirectorySeparatorChar;
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
