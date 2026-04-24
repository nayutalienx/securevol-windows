using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace SecureVol.Service;

public sealed class MountedVolumeWatcher : BackgroundService
{
    private readonly SecureVolCoordinator _coordinator;
    private readonly ILogger<MountedVolumeWatcher> _logger;

    public MountedVolumeWatcher(SecureVolCoordinator coordinator, ILogger<MountedVolumeWatcher> logger)
    {
        _coordinator = coordinator;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(2), stoppingToken).ConfigureAwait(false);
                await _coordinator.RefreshProtectedMountPointAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Mounted-volume watcher failed.");
            }
        }
    }
}
