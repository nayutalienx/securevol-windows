using System.Diagnostics;
using System.IO;
using System.ServiceProcess;
using SecureVol.Common;
using SecureVol.Common.Policy;

namespace SecureVol.AppCore;

public sealed record DashboardSnapshot(
    PolicyConfig Policy,
    DriverStateDto? DriverState,
    IReadOnlyList<RecentDenyEventDto> RecentDenies,
    ServiceControllerStatus? ServiceStatus,
    ServiceControllerStatus? DriverServiceStatus,
    string? BackendError,
    bool IsLive,
    long BackendLatencyMs);

public sealed class SecureVolDesktopController
{
    public string? LastOperationMessage { get; private set; }
    public bool LastOperationUsedFallback { get; private set; }

    public IReadOnlyList<string> GetMountedDriveRoots() => VolumeHelpers.EnumerateMountedDriveRoots();

    public DashboardSnapshot GetCachedDashboard(PolicyConfig? overridePolicy = null, string? backendError = null)
    {
        AppPaths.EnsureDirectories();

        var policy = overridePolicy ?? LoadPolicyOrDefault();
        var status = LoadStatusSnapshot();
        var state = new DriverStateDto(
            status?.PolicyProtectionEnabled ?? policy.ProtectionEnabled,
            ClientConnected: status?.DriverConnected ?? false,
            PolicyGeneration: status?.PolicyGeneration ?? 0,
            CacheEntryCount: 0,
            ProtectedVolumeGuid: status?.ProtectedVolume ?? policy.NormalizedProtectedVolume);

        return new DashboardSnapshot(
            policy,
            state,
            [],
            GetServiceStatus("SecureVolSvc"),
            GetServiceStatus("SecureVolFlt"),
            backendError,
            IsLive: false,
            BackendLatencyMs: 0);
    }

    public async Task<DashboardSnapshot> GetDashboardAsync(CancellationToken cancellationToken)
    {
        var snapshot = GetCachedDashboard();
        var stopwatch = Stopwatch.StartNew();

        try
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(TimeSpan.FromMilliseconds(1500));

            var response = await SendAsync(new AdminRequest { Command = "dashboard" }, timeoutCts.Token).ConfigureAwait(false);
            return new DashboardSnapshot(
                response.Policy ?? snapshot.Policy,
                response.State ?? snapshot.DriverState,
                response.RecentDenies ?? [],
                snapshot.ServiceStatus,
                snapshot.DriverServiceStatus,
                null,
                IsLive: true,
                BackendLatencyMs: stopwatch.ElapsedMilliseconds);
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("Unknown command 'dashboard'", StringComparison.OrdinalIgnoreCase))
        {
            return await GetLegacyDashboardAsync(snapshot, stopwatch, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return snapshot with
            {
                BackendError = "Backend request timed out. Showing cached local state.",
                BackendLatencyMs = stopwatch.ElapsedMilliseconds
            };
        }
        catch (Exception ex)
        {
            return snapshot with
            {
                BackendError = ex.Message,
                BackendLatencyMs = stopwatch.ElapsedMilliseconds
            };
        }
    }

    public async Task<PolicyConfig> ReloadAsync(CancellationToken cancellationToken)
    {
        LastOperationMessage = null;
        LastOperationUsedFallback = false;
        try
        {
            var response = await SendAsync(new AdminRequest { Command = "reload" }, cancellationToken).ConfigureAwait(false);
            return response.Policy ?? LoadPolicyOrDefault();
        }
        catch
        {
            var baseline = LoadStatusSnapshot()?.TimestampUtc ?? DateTimeOffset.UtcNow;
            var policy = LoadPolicyOrDefault();
            await WaitForServiceStatusConfirmationAsync(policy.ProtectionEnabled, baseline, cancellationToken).ConfigureAwait(false);
            LastOperationUsedFallback = true;
            LastOperationMessage = "Policy file is saved. The service will apply it from disk.";
            return policy;
        }
    }

    public async Task<PolicyConfig> SetProtectionAsync(bool enabled, CancellationToken cancellationToken)
    {
        LastOperationMessage = null;
        LastOperationUsedFallback = false;

        try
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(3));

            var response = await SendAsync(new AdminRequest
            {
                Command = "set-protection",
                ProtectionEnabled = enabled
            }, timeoutCts.Token).ConfigureAwait(false);

            LastOperationMessage = enabled
                ? "Protection enabled. It applies to new file opens only; close and reopen any windows or processes that already had the protected volume open."
                : "Protection paused.";
            return response.Policy ?? LoadPolicyOrDefault();
        }
        catch (Exception ex)
        {
            var baseline = LoadStatusSnapshot()?.TimestampUtc ?? DateTimeOffset.UtcNow;
            var fallback = await ApplyLocalProtectionFallbackAsync(enabled, ex, baseline, cancellationToken).ConfigureAwait(false);
            LastOperationUsedFallback = true;
            LastOperationMessage = fallback.Message;

            if (!fallback.Confirmed && enabled)
            {
                throw new InvalidOperationException(
                    $"Enable failed because SecureVol could not confirm a live driver/service path. Refusing to arm policy-only mode. Backend error: {ex.Message}",
                    ex);
            }

            return fallback.Policy;
        }
    }

    public async Task<PolicyConfig> SetProtectedVolumeAsync(string selectedVolume, CancellationToken cancellationToken)
    {
        LastOperationMessage = null;
        LastOperationUsedFallback = false;
        try
        {
            var response = await SendAsync(new AdminRequest
            {
                Command = "set-volume",
                Volume = selectedVolume
            }, cancellationToken).ConfigureAwait(false);

            return response.Policy ?? LoadPolicyOrDefault();
        }
        catch
        {
            var current = LoadPolicyOrDefault();
            var updated = new PolicyConfig
            {
                ProtectionEnabled = current.ProtectionEnabled,
                ProtectedVolume = VolumeHelpers.ResolveVolumeGuid(selectedVolume),
                DefaultExpectedUser = current.DefaultExpectedUser,
                AllowRules = [.. current.AllowRules]
            };

            updated.Save(AppPaths.PolicyFilePath);
            var baseline = LoadStatusSnapshot()?.TimestampUtc ?? DateTimeOffset.UtcNow;
            await WaitForServiceStatusConfirmationAsync(updated.ProtectionEnabled, baseline, cancellationToken).ConfigureAwait(false);
            LastOperationUsedFallback = true;
            LastOperationMessage = $"Protected volume saved locally as {updated.NormalizedProtectedVolume}.";
            return PolicyConfig.Load(AppPaths.PolicyFilePath);
        }
    }

    public async Task<PolicyConfig> SetDefaultExpectedUserAsync(string? userName, CancellationToken cancellationToken)
    {
        LastOperationMessage = null;
        LastOperationUsedFallback = false;

        var response = await SendAsync(new AdminRequest
        {
            Command = "set-default-user",
            DefaultExpectedUser = string.IsNullOrWhiteSpace(userName) ? null : userName.Trim()
        }, cancellationToken).ConfigureAwait(false);

        return response.Policy ?? LoadPolicyOrDefault();
    }

    public async Task<PolicyConfig> AddRuleAsync(AllowRule rule, CancellationToken cancellationToken)
    {
        LastOperationMessage = null;
        LastOperationUsedFallback = false;

        var response = await SendAsync(new AdminRequest
        {
            Command = "add-rule",
            Rule = rule
        }, cancellationToken).ConfigureAwait(false);

        return response.Policy ?? LoadPolicyOrDefault();
    }

    public async Task<PolicyConfig> RemoveRuleAsync(string ruleName, CancellationToken cancellationToken)
    {
        LastOperationMessage = null;
        LastOperationUsedFallback = false;

        var response = await SendAsync(new AdminRequest
        {
            Command = "remove-rule",
            RuleName = ruleName
        }, cancellationToken).ConfigureAwait(false);

        return response.Policy ?? LoadPolicyOrDefault();
    }

    public Task<ExecutableFacts> ProbeExecutableAsync(string executablePath, CancellationToken cancellationToken)
    {
        return ExecutableFactsResolver.ResolveAsync(executablePath, cancellationToken);
    }

    public void OpenLogDirectory() => OpenShellTarget(AppPaths.LogDirectory);

    public void OpenConfigDirectory() => OpenShellTarget(AppPaths.ConfigDirectory);

    public void OpenProjectReadme() => OpenShellTarget(Path.Combine(AppContext.BaseDirectory, "README.md"));

    private async Task<DashboardSnapshot> GetLegacyDashboardAsync(
        DashboardSnapshot snapshot,
        Stopwatch stopwatch,
        CancellationToken cancellationToken)
    {
        try
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(TimeSpan.FromMilliseconds(1800));

            var stateTask = SendAsync(new AdminRequest { Command = "state" }, timeoutCts.Token);
            var deniesTask = SendAsync(new AdminRequest { Command = "recent-denies" }, timeoutCts.Token);
            await Task.WhenAll(stateTask, deniesTask).ConfigureAwait(false);

            var stateResponse = await stateTask.ConfigureAwait(false);
            var deniesResponse = await deniesTask.ConfigureAwait(false);

            return new DashboardSnapshot(
                stateResponse.Policy ?? snapshot.Policy,
                stateResponse.State ?? snapshot.DriverState,
                deniesResponse.RecentDenies ?? [],
                snapshot.ServiceStatus,
                snapshot.DriverServiceStatus,
                null,
                IsLive: true,
                BackendLatencyMs: stopwatch.ElapsedMilliseconds);
        }
        catch (OperationCanceledException)
        {
            return snapshot with
            {
                BackendError = "Legacy backend request timed out. Showing cached local state.",
                BackendLatencyMs = stopwatch.ElapsedMilliseconds
            };
        }
        catch (Exception ex)
        {
            return snapshot with
            {
                BackendError = ex.Message,
                BackendLatencyMs = stopwatch.ElapsedMilliseconds
            };
        }
    }

    private static PolicyConfig LoadPolicyOrDefault()
    {
        if (!File.Exists(AppPaths.PolicyFilePath))
        {
            return new PolicyConfig
            {
                ProtectionEnabled = false,
                ProtectedVolume = string.Empty,
                AllowRules = []
            };
        }

        return PolicyConfig.Load(AppPaths.PolicyFilePath);
    }

    private static ServiceControllerStatus? GetServiceStatus(string serviceName)
    {
        try
        {
            using var controller = new ServiceController(serviceName);
            return controller.Status;
        }
        catch
        {
            return null;
        }
    }

    private static async Task<AdminResponse> SendAsync(AdminRequest request, CancellationToken cancellationToken)
    {
        var client = new AdminPipeClient();
        var response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.Success)
        {
            throw new InvalidOperationException(response.Message);
        }

        return response;
    }

    private static async Task<LocalProtectionFallbackResult> ApplyLocalProtectionFallbackAsync(
        bool enabled,
        Exception rootCause,
        DateTimeOffset baselineTimestampUtc,
        CancellationToken cancellationToken)
    {
        var policy = ApplyLocalProtectionSetting(enabled);
        var actions = new List<string> { "policy saved locally" };
        var confirmed = false;

        if (enabled)
        {
            if (TryRunProcess("fltmc.exe", "load SecureVolFlt", out var loadError, 2500, 0))
            {
                actions.Add("filter loaded");
            }
            else if (!string.IsNullOrWhiteSpace(loadError))
            {
                actions.Add($"filter load pending ({loadError.Trim()})");
            }

            confirmed = await WaitForServiceStatusConfirmationAsync(enabled, baselineTimestampUtc, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            if (TryRunProcess("fltmc.exe", "unload SecureVolFlt", out var unloadError, 2500, 0))
            {
                actions.Add("filter unloaded");
                confirmed = true;
            }
            else
            {
                confirmed = await WaitForServiceStatusConfirmationAsync(enabled, baselineTimestampUtc, cancellationToken).ConfigureAwait(false);
                if (!string.IsNullOrWhiteSpace(unloadError))
                {
                    actions.Add($"filter unload pending ({unloadError.Trim()})");
                }
            }
        }

        var confirmationText = confirmed ? "confirmed by service status" : "not confirmed";
        var message = $"Backend control path was unavailable ({rootCause.Message}). Applied local {(enabled ? "enable" : "pause")} fallback: {string.Join(", ", actions)}, {confirmationText}.";
        return new LocalProtectionFallbackResult(policy, message, confirmed);
    }

    private static PolicyConfig ApplyLocalProtectionSetting(bool enabled)
    {
        AppPaths.EnsureDefaultAcls();

        var current = LoadPolicyOrDefault();
        var updated = new PolicyConfig
        {
            ProtectionEnabled = enabled,
            ProtectedVolume = current.ProtectedVolume,
            DefaultExpectedUser = current.DefaultExpectedUser,
            AllowRules = [.. current.AllowRules]
        };

        updated.Save(AppPaths.PolicyFilePath);
        return PolicyConfig.Load(AppPaths.PolicyFilePath);
    }

    private static ServiceStatusSnapshot? LoadStatusSnapshot()
    {
        try
        {
            return ServiceStatusSnapshot.TryLoad(AppPaths.StatusFilePath);
        }
        catch
        {
            return null;
        }
    }

    private static async Task<bool> WaitForServiceStatusConfirmationAsync(
        bool enabled,
        DateTimeOffset baselineTimestampUtc,
        CancellationToken cancellationToken)
    {
        var deadline = DateTimeOffset.UtcNow.AddSeconds(6);

        while (DateTimeOffset.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var status = LoadStatusSnapshot();
            if (status is not null &&
                status.TimestampUtc >= baselineTimestampUtc &&
                status.PolicyProtectionEnabled == enabled &&
                (!enabled || status.DriverConnected))
            {
                return true;
            }

            await Task.Delay(250, cancellationToken).ConfigureAwait(false);
        }

        return false;
    }

    private static bool TryRunProcess(string fileName, string arguments, out string? error, int timeoutMs, params int[] successExitCodes)
    {
        error = null;

        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = fileName,
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardError = true,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            }) ?? throw new InvalidOperationException($"Failed to start {fileName}.");

            if (!process.WaitForExit(timeoutMs))
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                }
                catch
                {
                }

                error = $"{fileName} timed out";
                return false;
            }

            if (successExitCodes.Contains(process.ExitCode))
            {
                return true;
            }

            error = process.StandardError.ReadToEnd();
            if (string.IsNullOrWhiteSpace(error))
            {
                error = process.StandardOutput.ReadToEnd();
            }

            if (string.IsNullOrWhiteSpace(error))
            {
                error = $"{fileName} exited with code {process.ExitCode}.";
            }

            return false;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static void OpenShellTarget(string path)
    {
        if (!File.Exists(path) && !Directory.Exists(path))
        {
            throw new InvalidOperationException($"Path '{path}' was not found.");
        }

        Process.Start(new ProcessStartInfo
        {
            FileName = path,
            UseShellExecute = true
        });
    }

    private sealed record LocalProtectionFallbackResult(PolicyConfig Policy, string Message, bool Confirmed);
}
