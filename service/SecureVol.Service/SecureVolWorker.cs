using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SecureVol.Common.Interop;

namespace SecureVol.Service;

public sealed class SecureVolWorker : BackgroundService
{
    private const int HResultServiceAlreadyRunning = unchecked((int)0x80070420);
    private readonly SecureVolCoordinator _coordinator;
    private readonly ILogger<SecureVolWorker> _logger;
    private readonly WindowsEventLogger _eventLogger;
    private DateTimeOffset _lastFilterLoadFailureLog = DateTimeOffset.MinValue;

    public SecureVolWorker(
        SecureVolCoordinator coordinator,
        ILogger<SecureVolWorker> logger,
        WindowsEventLogger eventLogger)
    {
        _coordinator = coordinator;
        _logger = logger;
        _eventLogger = eventLogger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await _coordinator.InitializeAsync(stoppingToken).ConfigureAwait(false);
        await Task.Yield();

        while (!stoppingToken.IsCancellationRequested)
        {
            FilterPortConnection? connection = null;
            try
            {
                if (!_coordinator.ShouldAttemptDriverConnection())
                {
                    await Task.Delay(TimeSpan.FromSeconds(2), stoppingToken).ConfigureAwait(false);
                    continue;
                }

                if (!await TryEnsureFilterLoadedAsync(stoppingToken).ConfigureAwait(false))
                {
                    await Task.Delay(TimeSpan.FromSeconds(2), stoppingToken).ConfigureAwait(false);
                    continue;
                }

                // Push file policy into the driver before the long-lived query
                // channel is established. This prevents "policy enabled on disk,
                // driver still disabled" after reboot or service reconnect issues.
                await _coordinator.PushPolicyToDriverAsync(stoppingToken).ConfigureAwait(false);

                connection = FilterPortConnection.ConnectQuery((uint)Environment.ProcessId);
                _coordinator.AttachDriver(connection);
                await _coordinator.PushPolicyToDriverAsync(stoppingToken).ConfigureAwait(false);

                _logger.LogInformation("Connected to SecureVol filter port.");
                _eventLogger.Info("SecureVol service connected to the minifilter communication port.");

                while (!stoppingToken.IsCancellationRequested)
                {
                    var query = await Task.Run(connection.ReceiveProcessQuery, stoppingToken).ConfigureAwait(false);
                    var reply = await _coordinator.EvaluateQueryAsync(query, stoppingToken).ConfigureAwait(false);
                    connection.Reply(query.MessageId, reply);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Driver communication loop failed.");
                _eventLogger.Error($"SecureVol driver communication loop failed: {ex.Message}");
                await Task.Delay(TimeSpan.FromSeconds(2), stoppingToken).ConfigureAwait(false);
            }
            finally
            {
                if (connection is not null)
                {
                    _coordinator.DetachDriver(connection);
                    connection.Dispose();
                }
            }
        }
    }

    private async Task<bool> TryEnsureFilterLoadedAsync(CancellationToken cancellationToken)
    {
        try
        {
            return await Task.Run(TryEnsureFilterLoaded, cancellationToken)
                .WaitAsync(TimeSpan.FromSeconds(5), cancellationToken)
                .ConfigureAwait(false);
        }
        catch (TimeoutException ex)
        {
            LogFilterLoadFailure(ex, "SecureVolFlt load attempt timed out.");
            return false;
        }
    }

    private bool TryEnsureFilterLoaded()
    {
        if (NativeMethods.IsServiceRunning("SecureVolFlt"))
        {
            return true;
        }

        var result = NativeMethods.FilterLoad("SecureVolFlt");
        if (result == 0 || result == HResultServiceAlreadyRunning)
        {
            return true;
        }

        if (NativeMethods.IsServiceRunning("SecureVolFlt"))
        {
            return true;
        }

        var now = DateTimeOffset.UtcNow;
        if (now - _lastFilterLoadFailureLog > TimeSpan.FromSeconds(30))
        {
            _lastFilterLoadFailureLog = now;
            _logger.LogWarning("SecureVolFlt could not be loaded yet. HRESULT=0x{Result:X8}", result);
            _eventLogger.Error($"SecureVolFlt could not be loaded yet. HRESULT=0x{result:X8}");
        }

        return false;
    }

    private void LogFilterLoadFailure(Exception exception, string message)
    {
        var now = DateTimeOffset.UtcNow;
        if (now - _lastFilterLoadFailureLog <= TimeSpan.FromSeconds(30))
        {
            return;
        }

        _lastFilterLoadFailureLog = now;
        _logger.LogWarning(exception, "{Message}", message);
        _eventLogger.Error(message);
    }
}
