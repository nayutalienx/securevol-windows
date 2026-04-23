using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SecureVol.Common;

namespace SecureVol.Service;

public sealed class PolicyFileWatcher : BackgroundService
{
    private readonly SecureVolCoordinator _coordinator;
    private readonly ILogger<PolicyFileWatcher> _logger;
    private DateTime _lastSeenWriteTimeUtc;

    public PolicyFileWatcher(SecureVolCoordinator coordinator, ILogger<PolicyFileWatcher> logger)
    {
        _coordinator = coordinator;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _lastSeenWriteTimeUtc = GetWriteTimeUtc();

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken).ConfigureAwait(false);
                var currentWriteTimeUtc = GetWriteTimeUtc();
                if (currentWriteTimeUtc <= _lastSeenWriteTimeUtc)
                {
                    continue;
                }

                _lastSeenWriteTimeUtc = currentWriteTimeUtc;
                await _coordinator.ReloadPolicyFromDiskAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Policy watcher failed to reload the changed policy file.");
            }
        }
    }

    private static DateTime GetWriteTimeUtc()
    {
        if (!File.Exists(AppPaths.PolicyFilePath))
        {
            return DateTime.MinValue;
        }

        return File.GetLastWriteTimeUtc(AppPaths.PolicyFilePath);
    }
}
