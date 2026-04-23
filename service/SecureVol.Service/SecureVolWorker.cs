using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SecureVol.Common.Interop;

namespace SecureVol.Service;

public sealed class SecureVolWorker : BackgroundService
{
    private readonly SecureVolCoordinator _coordinator;
    private readonly ILogger<SecureVolWorker> _logger;
    private readonly WindowsEventLogger _eventLogger;

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

        while (!stoppingToken.IsCancellationRequested)
        {
            FilterPortConnection? connection = null;
            try
            {
                connection = FilterPortConnection.Connect((uint)Environment.ProcessId);
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
}
