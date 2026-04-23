using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SecureVol.Common;

namespace SecureVol.Service;

public sealed class AdminPipeServer : BackgroundService
{
    private readonly SecureVolCoordinator _coordinator;
    private readonly ILogger<AdminPipeServer> _logger;

    public AdminPipeServer(SecureVolCoordinator coordinator, ILogger<AdminPipeServer> logger)
    {
        _coordinator = coordinator;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            try
            {
                pipe = new NamedPipeServerStream(
                    AppPaths.AdminPipeName,
                    PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous);

                await pipe.WaitForConnectionAsync(stoppingToken).ConfigureAwait(false);
                _ = HandleClientAsync(pipe, stoppingToken);
                pipe = null;
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                pipe?.Dispose();
                break;
            }
            catch (IOException ex) when (IsBrokenPipe(ex))
            {
                pipe?.Dispose();
                _logger.LogDebug(ex, "Admin pipe client disconnected before the response completed.");
            }
            catch (Exception ex)
            {
                pipe?.Dispose();
                _logger.LogError(ex, "Admin pipe server failed.");
                await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken).ConfigureAwait(false);
            }
        }
    }

    private async Task HandleClientAsync(NamedPipeServerStream pipe, CancellationToken stoppingToken)
    {
        await using (pipe.ConfigureAwait(false))
        {
            try
            {
                using var reader = new StreamReader(pipe, Encoding.UTF8, false, 1024, true);
                using var writer = new StreamWriter(pipe, Encoding.UTF8, 1024, true) { AutoFlush = true };

                var requestJson = await reader.ReadLineAsync(stoppingToken).ConfigureAwait(false);
                if (string.IsNullOrWhiteSpace(requestJson))
                {
                    return;
                }

                var request = JsonSerializer.Deserialize<AdminRequest>(requestJson, SecureVol.Common.Policy.PolicyConfig.JsonOptions());
                var response = request is null
                    ? new AdminResponse { Success = false, Message = "Invalid request payload." }
                    : await _coordinator.HandleAdminRequestAsync(request, stoppingToken).ConfigureAwait(false);

                var responseJson = JsonSerializer.Serialize(response, SecureVol.Common.Policy.PolicyConfig.JsonOptions());
                await writer.WriteLineAsync(responseJson.AsMemory(), stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
            }
            catch (IOException ex) when (IsBrokenPipe(ex))
            {
                _logger.LogDebug(ex, "Admin pipe client disconnected before the response completed.");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Admin pipe client handler failed.");
            }
        }
    }

    private static bool IsBrokenPipe(IOException ex)
    {
        var errorCode = ex.HResult & 0xFFFF;
        return errorCode is 109 or 232 or 233;
    }
}
