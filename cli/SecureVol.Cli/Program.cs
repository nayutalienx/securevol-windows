using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using SecureVol.Common;
using SecureVol.Common.Diagnostics;
using SecureVol.Common.Interop;
using SecureVol.Common.Policy;

return await SecureVolCli.RunAsync(args);

internal static class SecureVolCli
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

    public static async Task<int> RunAsync(string[] args)
    {
        if (args.Length == 0)
        {
            PrintUsage();
            return 1;
        }

        AppPaths.EnsureDefaultAcls();

        try
        {
            var command = args[0].ToLowerInvariant();
            var rest = args.Skip(1).ToArray();
            return command switch
            {
                "service" => await HandleServiceAsync(rest),
                "driver" => await HandleDriverAsync(rest),
                "volume" => await HandleVolumeAsync(rest),
                "rule" => await HandleRuleAsync(rest),
                "reload" => await ReloadAsync(),
                "state" => await StateAsync(),
                "denies" => await DeniesAsync(),
                "protection" => await HandleProtectionAsync(rest),
                "launch" => await HandleLaunchAsync(rest),
                "hash" => await HandleHashAsync(rest),
                "diagnostics" => await HandleDiagnosticsAsync(rest),
                _ => throw new InvalidOperationException($"Unknown command '{command}'.")
            };
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 1;
        }
    }

    private static Task<int> HandleServiceAsync(string[] args)
    {
        if (args.Length == 0)
        {
            throw new InvalidOperationException("Missing service subcommand.");
        }

        return Task.FromResult(args[0].ToLowerInvariant() switch
        {
            "install" => RunProcess("sc.exe", $@"create SecureVolSvc binPath= ""{RequireOption(args, "--service-exe")}"" start= demand DisplayName= ""SecureVol Service"""),
            "uninstall" => RunProcess("sc.exe", "delete SecureVolSvc"),
            "start" => RunProcess("sc.exe", "start SecureVolSvc"),
            "stop" => RunProcess("sc.exe", "stop SecureVolSvc"),
            _ => throw new InvalidOperationException($"Unknown service subcommand '{args[0]}'.")
        });
    }

    private static Task<int> HandleDriverAsync(string[] args)
    {
        if (args.Length == 0)
        {
            throw new InvalidOperationException("Missing driver subcommand.");
        }

        return Task.FromResult(args[0].ToLowerInvariant() switch
        {
            "install-inf" => RunProcess("pnputil.exe", $@"/add-driver ""{RequireOption(args, "--inf")}"" /install"),
            "load" => RunProcess("fltmc.exe", "load SecureVolFlt"),
            "unload" => RunProcess("fltmc.exe", "unload SecureVolFlt"),
            _ => throw new InvalidOperationException($"Unknown driver subcommand '{args[0]}'.")
        });
    }

    private static async Task<int> HandleVolumeAsync(string[] args)
    {
        if (args.Length < 2 || !string.Equals(args[0], "set", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Usage: securevol volume set --volume V:");
        }

        var policy = LoadOrCreatePolicy();
        var requestedVolume = RequireOption(args, "--volume");
        var normalizedVolume = PolicyConfig.NormalizeVolumeIdentifier(requestedVolume);
        var mountPoint = normalizedVolume.Length == 3 && normalizedVolume[1] == ':' && normalizedVolume[2] == '\\'
            ? normalizedVolume
            : null;

        policy = new PolicyConfig
        {
            ProtectionEnabled = policy.ProtectionEnabled,
            ProtectedVolume = VolumeHelpers.ResolveVolumeGuid(requestedVolume),
            ProtectedMountPoint = mountPoint,
            DefaultExpectedUser = policy.DefaultExpectedUser,
            AllowRules = [.. policy.AllowRules]
        };

        policy.Save(AppPaths.PolicyFilePath);
        await TryReloadAsync().ConfigureAwait(false);
        Console.WriteLine($"Protected volume set to {policy.NormalizedProtectedVolume}");
        return 0;
    }

    private static async Task<int> HandleRuleAsync(string[] args)
    {
        if (args.Length == 0)
        {
            throw new InvalidOperationException("Missing rule subcommand.");
        }

        var policy = LoadOrCreatePolicy();
        switch (args[0].ToLowerInvariant())
        {
            case "add":
            {
                var rule = new AllowRule
                {
                    Name = RequireOption(args, "--name"),
                    ImagePath = PolicyConfig.NormalizePath(RequireOption(args, "--image")),
                    Sha256 = GetOption(args, "--sha256")?.Replace(" ", string.Empty, StringComparison.Ordinal).ToUpperInvariant(),
                    Publisher = GetOption(args, "--publisher"),
                    RequireSignature = HasFlag(args, "--require-signed"),
                    ExpectedUser = GetOption(args, "--user"),
                    Notes = GetOption(args, "--notes")
                };

                var updatedRules = policy.AllowRules
                    .Where(existing => !string.Equals(existing.Name, rule.Name, StringComparison.OrdinalIgnoreCase))
                    .ToList();
                updatedRules.Add(rule);

                policy = new PolicyConfig
                {
                    ProtectionEnabled = policy.ProtectionEnabled,
                    ProtectedVolume = policy.ProtectedVolume,
                    ProtectedMountPoint = policy.ProtectedMountPoint,
                    DefaultExpectedUser = policy.DefaultExpectedUser,
                    AllowRules = updatedRules
                };

                policy.Save(AppPaths.PolicyFilePath);
                await TryReloadAsync().ConfigureAwait(false);
                Console.WriteLine($"Rule '{rule.Name}' saved.");
                return 0;
            }

            case "remove":
            {
                var name = RequireOption(args, "--name");
                policy = new PolicyConfig
                {
                    ProtectionEnabled = policy.ProtectionEnabled,
                    ProtectedVolume = policy.ProtectedVolume,
                    ProtectedMountPoint = policy.ProtectedMountPoint,
                    DefaultExpectedUser = policy.DefaultExpectedUser,
                    AllowRules = policy.AllowRules
                        .Where(rule => !string.Equals(rule.Name, name, StringComparison.OrdinalIgnoreCase))
                        .ToList()
                };

                policy.Save(AppPaths.PolicyFilePath);
                await TryReloadAsync().ConfigureAwait(false);
                Console.WriteLine($"Rule '{name}' removed.");
                return 0;
            }

            default:
                throw new InvalidOperationException($"Unknown rule subcommand '{args[0]}'.");
        }
    }

    private static async Task<int> ReloadAsync()
    {
        var client = new AdminPipeClient();
        var response = await client.SendAsync(new AdminRequest { Command = "reload" }, CancellationToken.None).ConfigureAwait(false);
        Console.WriteLine(response.Message);
        return response.Success ? 0 : 1;
    }

    private static async Task<int> StateAsync()
    {
        var client = new AdminPipeClient();
        var response = await client.SendAsync(new AdminRequest { Command = "state" }, CancellationToken.None).ConfigureAwait(false);
        if (!response.Success)
        {
            Console.Error.WriteLine(response.Message);
            return 1;
        }

        if (response.Policy is not null)
        {
            Console.WriteLine($"ProtectionEnabled : {response.Policy.ProtectionEnabled}");
            Console.WriteLine($"ProtectedVolume   : {response.Policy.NormalizedProtectedVolume}");
            Console.WriteLine($"DefaultUser       : {response.Policy.DefaultExpectedUser ?? "<none>"}");
            Console.WriteLine($"AllowRules        : {response.Policy.AllowRules.Count}");
        }

        if (response.State is not null)
        {
            Console.WriteLine($"DriverConnected   : {response.State.ClientConnected}");
            Console.WriteLine($"PolicyGeneration  : {response.State.PolicyGeneration}");
            Console.WriteLine($"DriverCacheCount  : {response.State.CacheEntryCount}");
            Console.WriteLine($"DriverVolume      : {response.State.ProtectedVolumeGuid}");
        }

        return 0;
    }

    private static async Task<int> DeniesAsync()
    {
        var client = new AdminPipeClient();
        var response = await client.SendAsync(new AdminRequest { Command = "recent-denies" }, CancellationToken.None).ConfigureAwait(false);
        if (!response.Success)
        {
            Console.Error.WriteLine(response.Message);
            return 1;
        }

        foreach (var deny in response.RecentDenies ?? [])
        {
            Console.WriteLine($"{deny.TimestampUtc:u} pid={deny.ProcessId} image={deny.ImageName} reason={deny.Reason}");
        }

        return 0;
    }

    private static async Task<int> HandleProtectionAsync(string[] args)
    {
        if (args.Length == 0)
        {
            throw new InvalidOperationException("Missing protection subcommand.");
        }

        var action = args[0].ToLowerInvariant();
        if (action is not ("enable" or "disable"))
        {
            throw new InvalidOperationException("Usage: securevol protection enable|disable [--volume V:]");
        }

        if (!IsElevated())
        {
            throw new InvalidOperationException("securevol protection enable|disable must be run as Administrator.");
        }

        var policy = LoadOrCreatePolicy();
        var requestedVolume = GetOption(args, "--volume");
        var protectedVolume = policy.ProtectedVolume;
        var protectedMountPoint = policy.ProtectedMountPoint;

        if (!string.IsNullOrWhiteSpace(requestedVolume))
        {
            var normalizedVolume = PolicyConfig.NormalizeVolumeIdentifier(requestedVolume);
            protectedMountPoint = IsDriveRoot(normalizedVolume) ? normalizedVolume : protectedMountPoint;
            protectedVolume = VolumeHelpers.ResolveVolumeGuid(requestedVolume);
        }
        else if (action == "enable" && IsDriveRoot(policy.NormalizedProtectedMountPoint) && Directory.Exists(policy.NormalizedProtectedMountPoint))
        {
            protectedVolume = VolumeHelpers.ResolveVolumeGuid(policy.NormalizedProtectedMountPoint);
        }

        if (action == "enable" && string.IsNullOrWhiteSpace(PolicyConfig.NormalizeVolumeIdentifier(protectedVolume)))
        {
            throw new InvalidOperationException("Protection cannot be enabled because no protected volume is configured. Use --volume A: first.");
        }

        policy = new PolicyConfig
        {
            ProtectionEnabled = action == "enable",
            ProtectedVolume = protectedVolume,
            ProtectedMountPoint = protectedMountPoint,
            DefaultExpectedUser = policy.DefaultExpectedUser,
            AllowRules = [.. policy.AllowRules]
        };

        policy.Save(AppPaths.PolicyFilePath);

        TryStartServiceBestEffort();
        var generation = NewPolicyGeneration();
        DriverStateDto driverState;
        try
        {
            driverState = DriverPolicyController.PushPolicy(policy, generation, (uint)Environment.ProcessId);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Policy file updated, but driver policy push failed: {ex.Message}");
            return 1;
        }

        await TryReloadAsync().ConfigureAwait(false);
        Console.WriteLine($"Protection enabled: {policy.ProtectionEnabled}");
        Console.WriteLine($"Driver policy enabled: {driverState.ProtectionEnabled}");
        Console.WriteLine($"Driver query client connected: {driverState.ClientConnected}");
        Console.WriteLine($"Driver protected volume: {driverState.ProtectedVolumeGuid}");
        return 0;
    }

    private static Task<int> HandleLaunchAsync(string[] args)
    {
        var app = PolicyConfig.NormalizePath(RequireOption(args, "--app"));
        var arguments = GetOption(args, "--args") ?? string.Empty;
        var workingDirectory = GetOption(args, "--working-dir") ?? Path.GetDirectoryName(app);
        var configuredUser = GetOption(args, "--user") ?? LoadOrCreatePolicy().DefaultExpectedUser;
        if (string.IsNullOrWhiteSpace(configuredUser))
        {
            throw new InvalidOperationException("No launch user supplied and no defaultExpectedUser is configured.");
        }

        var (domain, userName) = SplitUser(configuredUser);
        var password = PromptForPassword($"Password for {configuredUser}: ");

        var startupInfo = new NativeMethods.STARTUPINFO
        {
            cb = (uint)Marshal.SizeOf<NativeMethods.STARTUPINFO>()
        };

        var commandLine = Quote(app);
        if (!string.IsNullOrWhiteSpace(arguments))
        {
            commandLine += " " + arguments;
        }

        if (!NativeMethods.CreateProcessWithLogonW(
                userName,
                domain,
                password,
                0,
                null,
                commandLine,
                0,
                IntPtr.Zero,
                workingDirectory,
                ref startupInfo,
                out var processInformation))
        {
            throw new InvalidOperationException("CreateProcessWithLogonW failed.");
        }

        NativeMethods.CloseProcessInformation(ref processInformation);
        Console.WriteLine($"Launched {app} as {configuredUser}");
        return Task.FromResult(0);
    }

    private static async Task<int> HandleHashAsync(string[] args)
    {
        var imagePath = PolicyConfig.NormalizePath(RequireOption(args, "--image"));
        Console.WriteLine(await HashingHelpers.ComputeSha256Async(imagePath).ConfigureAwait(false));
        return 0;
    }

    private static async Task<int> HandleDiagnosticsAsync(string[] args)
    {
        if (args.Length == 0)
        {
            throw new InvalidOperationException("Usage: securevol diagnostics upload [--open] | copy | create");
        }

        switch (args[0].ToLowerInvariant())
        {
            case "create":
            {
                var report = await DiagnosticReport.CreateAsync(CancellationToken.None).ConfigureAwait(false);
                Console.WriteLine(report.ReportPath);
                return 0;
            }

            case "upload":
            {
                try
                {
                    var result = await DiagnosticReport.UploadAsync(CancellationToken.None).ConfigureAwait(false);
                    Console.WriteLine($"Provider : {result.Provider}");
                    Console.WriteLine($"Report   : {result.ReportPath}");
                    Console.WriteLine($"URL      : {result.Url}");
                    if (HasFlag(args, "--open"))
                    {
                        DiagnosticReport.OpenInBrowser(result.Url);
                    }

                    return 0;
                }
                catch (DiagnosticUploadException ex)
                {
                    Console.Error.WriteLine(ex.Message);
                    Console.Error.WriteLine(TryCopyTextToClipboard(ex.ReportText)
                        ? "Clipboard: full local diagnostic report copied."
                        : "Clipboard: failed to copy the local diagnostic report.");
                    return 1;
                }
            }
            case "copy":
            {
                var report = await DiagnosticReport.CreateAsync(CancellationToken.None).ConfigureAwait(false);
                Console.WriteLine($"Report   : {report.ReportPath}");
                Console.WriteLine(TryCopyTextToClipboard(report.ReportText)
                    ? "Clipboard: full local diagnostic report copied."
                    : "Clipboard: failed to copy the local diagnostic report.");

                return 0;
            }

            default:
                throw new InvalidOperationException($"Unknown diagnostics subcommand '{args[0]}'.");
        }
    }

    private static PolicyConfig LoadOrCreatePolicy()
    {
        if (!File.Exists(AppPaths.PolicyFilePath))
        {
            var empty = new PolicyConfig
            {
                ProtectionEnabled = false,
                ProtectedVolume = string.Empty,
                AllowRules = []
            };
            empty.Save(AppPaths.PolicyFilePath);
            return PolicyConfig.Load(AppPaths.PolicyFilePath);
        }

        return PolicyConfig.Load(AppPaths.PolicyFilePath);
    }

    private static async Task TryReloadAsync()
    {
        try
        {
            await ReloadAsync().ConfigureAwait(false);
        }
        catch
        {
            Console.WriteLine("Policy file updated. Service reload skipped because the service is not reachable.");
        }
    }

    private static int RunProcess(string fileName, string arguments)
    {
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            UseShellExecute = false
        }) ?? throw new InvalidOperationException($"Failed to start {fileName}.");

        process.WaitForExit();
        return process.ExitCode;
    }

    private static bool TryCopyTextToClipboard(string text)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = "clip.exe",
                UseShellExecute = false,
                RedirectStandardInput = true,
                RedirectStandardOutput = false,
                RedirectStandardError = false,
                CreateNoWindow = true
            });

            if (process is null)
            {
                return false;
            }

            process.StandardInput.Write(text);
            process.StandardInput.Close();
            return process.WaitForExit(3000) && process.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    private static void TryStartServiceBestEffort()
    {
        try
        {
            var exitCode = RunProcess("sc.exe", "start SecureVolSvc");
            if (exitCode is not (0 or 1056))
            {
                Console.WriteLine($"SecureVolSvc start returned exit code {exitCode}; continuing with direct driver policy push.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"SecureVolSvc start skipped: {ex.Message}");
        }
    }

    private static uint NewPolicyGeneration() =>
        unchecked((uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds());

    private static bool IsDriveRoot(string value) =>
        value.Length == 3 && value[1] == ':' && value[2] == '\\';

    private static bool IsElevated()
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
            NativeMethods.CloseHandle(tokenHandle);
        }
    }

    private static string RequireOption(string[] args, string name) =>
        GetOption(args, name) ?? throw new InvalidOperationException($"Missing required option '{name}'.");

    private static string? GetOption(string[] args, string name)
    {
        var index = Array.FindIndex(args, arg => string.Equals(arg, name, StringComparison.OrdinalIgnoreCase));
        return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
    }

    private static bool HasFlag(string[] args, string name) =>
        args.Any(arg => string.Equals(arg, name, StringComparison.OrdinalIgnoreCase));

    private static void PrintUsage()
    {
        Console.WriteLine("""
SecureVol CLI
  securevol service install --service-exe "C:\Path\SecureVol.Service.exe"
  securevol service start|stop|uninstall
  securevol driver install-inf --inf "C:\Path\SecureVolFlt.inf"
  securevol driver load|unload
  securevol volume set --volume V:
  securevol rule add --name chrome --image "C:\Program Files\Google\Chrome\Application\chrome.exe" --publisher "Google LLC" --user ".\vc_app" --require-signed
  securevol rule remove --name chrome
  securevol protection enable|disable [--volume V:]
  securevol reload
  securevol state
  securevol denies
  securevol hash --image "C:\Path\App.exe"
  securevol launch --app "C:\Path\App.exe" --args "--user-data-dir=V:\Profile" --user ".\vc_app"
  securevol diagnostics upload --open
""");
    }

    private static (string? Domain, string UserName) SplitUser(string rawUser)
    {
        var trimmed = rawUser.Trim();
        var index = trimmed.IndexOf('\\');
        if (index < 0)
        {
            return (Environment.MachineName, trimmed);
        }

        var domain = trimmed[..index];
        if (string.Equals(domain, ".", StringComparison.Ordinal))
        {
            domain = Environment.MachineName;
        }

        return (domain, trimmed[(index + 1)..]);
    }

    private static string PromptForPassword(string prompt)
    {
        Console.Write(prompt);
        var buffer = new List<char>();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                return new string([.. buffer]);
            }

            if (key.Key == ConsoleKey.Backspace && buffer.Count > 0)
            {
                buffer.RemoveAt(buffer.Count - 1);
                continue;
            }

            if (!char.IsControl(key.KeyChar))
            {
                buffer.Add(key.KeyChar);
            }
        }
    }

    private static string Quote(string value) =>
        value.StartsWith('"') && value.EndsWith("\"", StringComparison.Ordinal) ? value : $"\"{value}\"";

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
