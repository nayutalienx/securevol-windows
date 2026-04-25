using System.Collections.Concurrent;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using SecureVol.Common;
using SecureVol.Common.Interop;
using SecureVol.Common.Logging;
using SecureVol.Common.Policy;

namespace SecureVol.Service;

public sealed class SecureVolCoordinator
{
    private const int MaxRecentDenyEvents = 128;
    private readonly PolicyEngine _policyEngine;
    private readonly JsonFileLogger _fileLogger;
    private readonly WindowsEventLogger _eventLogger;
    private readonly ILogger<SecureVolCoordinator> _logger;
    private readonly SemaphoreSlim _policyGate = new(1, 1);
    private readonly ConcurrentDictionary<string, DateTimeOffset> _denyLogWindow = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentQueue<RecentDenyEventDto> _recentDenies = new();

    private PolicyConfig _policy = new();
    private uint _policyGeneration = 1;
    private FilterPortConnection? _driverConnection;
    private DriverStateDto? _lastDriverState;
    private string? _lastDriverPushError;

    public SecureVolCoordinator(
        PolicyEngine policyEngine,
        JsonFileLogger fileLogger,
        WindowsEventLogger eventLogger,
        ILogger<SecureVolCoordinator> logger)
    {
        _policyEngine = policyEngine;
        _fileLogger = fileLogger;
        _eventLogger = eventLogger;
        _logger = logger;
    }

    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        AppPaths.EnsureDefaultAcls();
        if (!File.Exists(AppPaths.PolicyFilePath))
        {
            new PolicyConfig
            {
                ProtectionEnabled = false,
                ProtectedVolume = string.Empty,
                AllowRules = []
            }.Save(AppPaths.PolicyFilePath);
        }

        await ReloadPolicyAsync(pushToDriver: false, cancellationToken).ConfigureAwait(false);
        WriteStatusSnapshot();
    }

    public void AttachDriver(FilterPortConnection connection)
    {
        _driverConnection = connection;
        WriteStatusSnapshot();
    }

    public void DetachDriver(FilterPortConnection connection)
    {
        if (ReferenceEquals(_driverConnection, connection))
        {
            _driverConnection = null;
        }

        WriteStatusSnapshot();
    }

    public Task<AdminResponse> ReloadPolicyFromDiskAsync(CancellationToken cancellationToken)
    {
        return ReloadPolicyAsync(pushToDriver: true, cancellationToken);
    }

    public async Task RefreshProtectedMountPointAsync(CancellationToken cancellationToken)
    {
        PolicyConfig policy;
        uint generation;
        bool changed = false;

        await _policyGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var resolvedPolicy = ResolveProtectedMountPoint(_policy);
            if (!string.Equals(resolvedPolicy.NormalizedProtectedVolume, _policy.NormalizedProtectedVolume, StringComparison.OrdinalIgnoreCase))
            {
                _policy = resolvedPolicy;
                _policyGeneration++;
                _policyEngine.ClearCache();
                _policy.Save(AppPaths.PolicyFilePath);
                changed = true;
            }

            policy = _policy;
            generation = _policyGeneration;
        }
        finally
        {
            _policyGate.Release();
        }

        if (!changed)
        {
            return;
        }

        await PushPolicyToDriverAsync(cancellationToken).ConfigureAwait(false);
        await _fileLogger.WriteAsync(new
        {
            ts = DateTimeOffset.UtcNow,
            level = "info",
            evt = "protected-mount-resolved",
            generation,
            protectedMountPoint = policy.NormalizedProtectedMountPoint,
            protectedVolume = policy.NormalizedProtectedVolume
        }, cancellationToken).ConfigureAwait(false);

        _eventLogger.Info($"SecureVol protected mount point resolved. Mount='{policy.NormalizedProtectedMountPoint}', Volume='{policy.NormalizedProtectedVolume}'.");
        WriteStatusSnapshot();
    }

    public async Task<bool> PushPolicyToDriverAsync(CancellationToken cancellationToken)
    {
        PolicyConfig policy;
        uint generation;

        await _policyGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            policy = _policy;
            generation = _policyGeneration;
        }
        finally
        {
            _policyGate.Release();
        }

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var state = await Task.Run(
                    () => DriverPolicyController.PushPolicy(policy, generation, (uint)Environment.ProcessId),
                    cancellationToken)
                .WaitAsync(TimeSpan.FromSeconds(5), cancellationToken)
                .ConfigureAwait(false);

            _lastDriverState = state;
            _lastDriverPushError = null;
            WriteStatusSnapshot();
            return true;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _lastDriverPushError = ex.Message;
            _logger.LogWarning(ex, "SecureVol could not push policy generation {Generation} directly to the minifilter.", generation);
            _eventLogger.Warning($"SecureVol could not push policy generation {generation} to the minifilter: {ex.Message}");
            WriteStatusSnapshot();
            return false;
        }
    }

    public async Task<ProcessReplyMessage> EvaluateQueryAsync(ProcessAccessQuery message, CancellationToken cancellationToken)
    {
        PolicyConfig policy;
        uint generation;

        await _policyGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            policy = _policy;
            generation = _policyGeneration;
        }
        finally
        {
            _policyGate.Release();
        }

        if (!policy.ProtectionEnabled)
        {
            return BuildReply(generation, AccessVerdict.Allow, DecisionReason.PolicyDisabled, string.Empty);
        }

        if (!string.Equals(policy.NormalizedProtectedVolume, PolicyConfig.NormalizeVolumeIdentifier(message.Query.VolumeGuid), StringComparison.OrdinalIgnoreCase))
        {
            return BuildReply(generation, AccessVerdict.Allow, DecisionReason.UnprotectedVolume, string.Empty);
        }

        var decision = await _policyEngine
            .EvaluateAsync(policy, generation, message.Query.ProcessId, message.Query.ProcessCreateTime, cancellationToken)
            .ConfigureAwait(false);

        if (decision.Verdict == AccessVerdict.Deny)
        {
            await LogDenyAsync(decision, generation, cancellationToken).ConfigureAwait(false);
        }

        return BuildReply(
            generation,
            decision.Verdict,
            decision.Reason,
            decision.Identity?.ImagePath ?? string.Empty);
    }

    public async Task<AdminResponse> HandleAdminRequestAsync(AdminRequest request, CancellationToken cancellationToken)
    {
        return request.Command.Trim().ToLowerInvariant() switch
        {
            "ping" => new AdminResponse { Success = true, Message = "pong" },
            "dashboard" => await GetDashboardAsync(cancellationToken).ConfigureAwait(false),
            "reload" => await ReloadPolicyAsync(pushToDriver: true, cancellationToken).ConfigureAwait(false),
            "state" => await GetStateAsync(cancellationToken).ConfigureAwait(false),
            "set-protection" => await SetProtectionAsync(request.ProtectionEnabled, cancellationToken).ConfigureAwait(false),
            "set-default-user" => await SetDefaultExpectedUserAsync(request.DefaultExpectedUser, cancellationToken).ConfigureAwait(false),
            "set-volume" => await SetVolumeAsync(request.Volume, cancellationToken).ConfigureAwait(false),
            "add-rule" => await AddRuleAsync(request.Rule, cancellationToken).ConfigureAwait(false),
            "remove-rule" => await RemoveRuleAsync(request.RuleName, cancellationToken).ConfigureAwait(false),
            "recent-denies" => await GetRecentDeniesAsync(cancellationToken).ConfigureAwait(false),
            _ => new AdminResponse { Success = false, Message = $"Unknown command '{request.Command}'." }
        };
    }

    private async Task<AdminResponse> ReloadPolicyAsync(bool pushToDriver, CancellationToken cancellationToken)
    {
        await _policyGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var loadedPolicy = PolicyConfig.Load(AppPaths.PolicyFilePath);
            var resolvedPolicy = ResolveProtectedMountPoint(loadedPolicy);
            if (!string.Equals(resolvedPolicy.NormalizedProtectedVolume, loadedPolicy.NormalizedProtectedVolume, StringComparison.OrdinalIgnoreCase))
            {
                resolvedPolicy.Save(AppPaths.PolicyFilePath);
            }

            _policy = resolvedPolicy;
            _policyGeneration++;
            _policyEngine.ClearCache();
        }
        finally
        {
            _policyGate.Release();
        }

        var driverPushOk = true;
        if (pushToDriver)
        {
            driverPushOk = await PushPolicyToDriverAsync(cancellationToken).ConfigureAwait(false);
        }

        await _fileLogger.WriteAsync(new
        {
            ts = DateTimeOffset.UtcNow,
            level = "info",
            evt = "policy-reloaded",
            generation = _policyGeneration,
            protectedVolume = _policy.NormalizedProtectedVolume,
            ruleCount = _policy.AllowRules.Count
        }, cancellationToken).ConfigureAwait(false);

        _eventLogger.Info($"SecureVol policy reloaded. Generation={_policyGeneration}, ProtectedVolume='{_policy.NormalizedProtectedVolume}', Rules={_policy.AllowRules.Count}.");
        WriteStatusSnapshot();
        return new AdminResponse
        {
            Success = driverPushOk,
            Message = driverPushOk ? "Policy reloaded and pushed to driver." : $"Policy reloaded on disk, but driver push failed: {_lastDriverPushError}",
            Policy = _policy,
            State = BuildDriverState(_policy, _policyGeneration)
        };
    }

    private async Task<AdminResponse> GetStateAsync(CancellationToken cancellationToken)
    {
        PolicyConfig policy;
        FilterPortConnection? driver;
        uint generation;

        await _policyGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            policy = _policy;
            driver = _driverConnection;
            generation = _policyGeneration;
        }
        finally
        {
            _policyGate.Release();
        }

        // Do not send control messages over the same filter-port handle that the
        // worker thread uses for FilterGetMessage. That pattern can block admin
        // requests while the receive loop is waiting for kernel queries.
        var state = BuildDriverState(policy, generation, driver is not null);

        return new AdminResponse
        {
            Success = true,
            Message = "State retrieved.",
            Policy = policy,
            State = state
        };
    }

    private async Task<AdminResponse> GetDashboardAsync(CancellationToken cancellationToken)
    {
        PolicyConfig policy;
        FilterPortConnection? driver;
        uint generation;
        IReadOnlyList<RecentDenyEventDto> denies;

        await _policyGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            policy = _policy;
            driver = _driverConnection;
            generation = _policyGeneration;
            denies = _recentDenies.ToArray();
        }
        finally
        {
            _policyGate.Release();
        }

        var state = BuildDriverState(policy, generation, driver is not null);

        return new AdminResponse
        {
            Success = true,
            Message = "Dashboard retrieved.",
            Policy = policy,
            State = state,
            RecentDenies = denies
        };
    }

    private async Task<AdminResponse> SetVolumeAsync(string? volume, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(volume))
        {
            return new AdminResponse { Success = false, Message = "Volume value is required." };
        }

        await _policyGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var normalizedMountPoint = PolicyConfig.NormalizeVolumeIdentifier(volume);
            var mountPoint = IsDriveRoot(normalizedMountPoint) ? normalizedMountPoint : null;

            _policy = _policy with
            {
                ProtectedVolume = VolumeHelpers.ResolveVolumeGuid(volume),
                ProtectedMountPoint = mountPoint
            };

            _policy.Save(AppPaths.PolicyFilePath);
        }
        finally
        {
            _policyGate.Release();
        }

        return await ReloadPolicyAsync(pushToDriver: true, cancellationToken).ConfigureAwait(false);
    }

    private async Task<AdminResponse> SetProtectionAsync(bool? protectionEnabled, CancellationToken cancellationToken)
    {
        if (protectionEnabled is null)
        {
            return new AdminResponse { Success = false, Message = "ProtectionEnabled is required." };
        }

        await _policyGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            _policy = _policy with
            {
                ProtectionEnabled = protectionEnabled.Value
            };

            _policy.Save(AppPaths.PolicyFilePath);
        }
        finally
        {
            _policyGate.Release();
        }

        return await ReloadPolicyAsync(pushToDriver: true, cancellationToken).ConfigureAwait(false);
    }

    private async Task<AdminResponse> SetDefaultExpectedUserAsync(string? defaultExpectedUser, CancellationToken cancellationToken)
    {
        await _policyGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            _policy = _policy with
            {
                DefaultExpectedUser = PolicyConfig.NormalizeUser(defaultExpectedUser)
            };

            _policy.Save(AppPaths.PolicyFilePath);
        }
        finally
        {
            _policyGate.Release();
        }

        return await ReloadPolicyAsync(pushToDriver: true, cancellationToken).ConfigureAwait(false);
    }

    private async Task<AdminResponse> AddRuleAsync(AllowRule? rule, CancellationToken cancellationToken)
    {
        if (rule is null || string.IsNullOrWhiteSpace(rule.Name) || string.IsNullOrWhiteSpace(rule.ImagePath))
        {
            return new AdminResponse { Success = false, Message = "Rule name and image path are required." };
        }

        await _policyGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var updatedRules = _policy.AllowRules
                .Where(existing => !string.Equals(existing.Name, rule.Name, StringComparison.OrdinalIgnoreCase))
                .ToList();

            updatedRules.Add(rule with
            {
                ImagePath = PolicyConfig.NormalizePath(rule.ImagePath),
                Sha256 = string.IsNullOrWhiteSpace(rule.Sha256) ? null : rule.Sha256.Replace(" ", string.Empty, StringComparison.Ordinal).ToUpperInvariant(),
                ExpectedUser = PolicyConfig.NormalizeUser(rule.ExpectedUser)
            });

            _policy = _policy with
            {
                AllowRules = updatedRules
            };

            _policy.Save(AppPaths.PolicyFilePath);
        }
        finally
        {
            _policyGate.Release();
        }

        return await ReloadPolicyAsync(pushToDriver: true, cancellationToken).ConfigureAwait(false);
    }

    private async Task<AdminResponse> RemoveRuleAsync(string? ruleName, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(ruleName))
        {
            return new AdminResponse { Success = false, Message = "Rule name is required." };
        }

        await _policyGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var updatedRules = _policy.AllowRules
                .Where(rule => !string.Equals(rule.Name, ruleName, StringComparison.OrdinalIgnoreCase))
                .ToList();

            _policy = _policy with
            {
                AllowRules = updatedRules
            };

            _policy.Save(AppPaths.PolicyFilePath);
        }
        finally
        {
            _policyGate.Release();
        }

        return await ReloadPolicyAsync(pushToDriver: true, cancellationToken).ConfigureAwait(false);
    }

    private Task<AdminResponse> GetRecentDeniesAsync(CancellationToken cancellationToken)
    {
        return Task.FromResult(new AdminResponse
        {
            Success = true,
            Message = "Recent denies retrieved.",
            RecentDenies = _recentDenies.ToArray()
        });
    }

    private async Task LogDenyAsync(PolicyDecision decision, uint generation, CancellationToken cancellationToken)
    {
        var identity = decision.Identity;
        var cacheKey = $"{identity?.ProcessId}|{identity?.ImagePath}|{decision.Reason}";
        var now = DateTimeOffset.UtcNow;

        if (_denyLogWindow.TryGetValue(cacheKey, out var lastLogged) && (now - lastLogged) < TimeSpan.FromSeconds(5))
        {
            return;
        }

        _denyLogWindow[cacheKey] = now;
        var record = new
        {
            ts = now,
            level = "warning",
            evt = "access-denied",
            generation,
            reason = decision.Reason.ToString(),
            rule = decision.RuleName,
            processId = identity?.ProcessId,
            imagePath = identity?.ImagePath,
            user = identity?.UserName,
            sha256 = identity?.Sha256,
            publisher = identity?.Publisher
        };

        await _fileLogger.WriteAsync(record, cancellationToken).ConfigureAwait(false);
        _logger.LogWarning("Denied PID {ProcessId} ({ImagePath}) for reason {Reason}.", identity?.ProcessId, identity?.ImagePath, decision.Reason);
        _eventLogger.Warning($"SecureVol denied PID {identity?.ProcessId} ({identity?.ImagePath}) because {decision.Reason}.");

        _recentDenies.Enqueue(new RecentDenyEventDto(
            now,
            identity?.ProcessId ?? 0,
            decision.Reason,
            identity?.ImagePath ?? string.Empty));

        while (_recentDenies.Count > MaxRecentDenyEvents && _recentDenies.TryDequeue(out _)) {
        }
    }

    private PolicyConfig ResolveProtectedMountPoint(PolicyConfig policy)
    {
        var mountPoint = policy.NormalizedProtectedMountPoint;
        if (!IsDriveRoot(mountPoint) || !Directory.Exists(mountPoint))
        {
            return policy;
        }

        try
        {
            var currentVolume = VolumeHelpers.ResolveVolumeGuid(mountPoint);
            return string.IsNullOrWhiteSpace(currentVolume)
                ? policy
                : policy with { ProtectedVolume = currentVolume };
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Protected mount point '{MountPoint}' is not resolvable yet.", mountPoint);
            return policy;
        }
    }

    private static bool IsDriveRoot(string value) =>
        value.Length == 3 && value[1] == ':' && value[2] == '\\';

    private DriverStateDto BuildDriverState(PolicyConfig policy, uint generation, bool queryConnectedHint = false)
    {
        if (_lastDriverState is { } state)
        {
            return state with
            {
                ClientConnected = state.ClientConnected || queryConnectedHint || _driverConnection is not null
            };
        }

        return new DriverStateDto(
            policy.ProtectionEnabled,
            queryConnectedHint || _driverConnection is not null,
            generation,
            0,
            policy.NormalizedProtectedVolume);
    }

    private static ProcessReplyMessage BuildReply(uint generation, AccessVerdict verdict, DecisionReason reason, string imagePath) =>
        new()
        {
            Header = new SecureVolMessageHeader
            {
                MessageType = DriverMessageType.ProcessQuery,
                Size = (uint)System.Runtime.InteropServices.Marshal.SizeOf<ProcessReplyMessage>()
            },
            PolicyGeneration = generation,
            Verdict = verdict,
            Reason = reason,
            ImagePath = imagePath.Length >= SecureVolProtocol.MaxPathChars
                ? imagePath[..(SecureVolProtocol.MaxPathChars - 1)]
                : imagePath
        };

    private void WriteStatusSnapshot()
    {
        PolicyConfig policy;
        DriverStateDto? driverState = _lastDriverState;
        var driverConnected = _driverConnection is not null || (driverState?.ClientConnected ?? false);
        uint generation;

        ExAcquire();
        try
        {
            policy = _policy;
            generation = _policyGeneration;
        }
        finally
        {
            ExRelease();
        }

        var snapshot = new ServiceStatusSnapshot
        {
            TimestampUtc = DateTimeOffset.UtcNow,
            PolicyProtectionEnabled = policy.ProtectionEnabled,
            DriverConnected = driverConnected,
            PolicyGeneration = generation,
            ProtectedVolume = policy.NormalizedProtectedVolume,
            AllowRuleCount = policy.AllowRules.Count,
            LastError = _lastDriverPushError
        };

        snapshot.Save(AppPaths.StatusFilePath);
    }

    private void ExAcquire() => _policyGate.Wait();

    private void ExRelease() => _policyGate.Release();

}
