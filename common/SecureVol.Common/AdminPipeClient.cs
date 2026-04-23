using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace SecureVol.Common;

public sealed class AdminPipeClient
{
    private static readonly TimeSpan DefaultConnectTimeout = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan DefaultRoundTripTimeout = TimeSpan.FromSeconds(2);

    public async Task<AdminResponse> SendAsync(AdminRequest request, CancellationToken cancellationToken)
    {
        using var pipe = new NamedPipeClientStream(".", AppPaths.AdminPipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await pipe.ConnectAsync(cancellationToken).WaitAsync(DefaultConnectTimeout, cancellationToken).ConfigureAwait(false);

        using var writer = new StreamWriter(pipe, Encoding.UTF8, 1024, true) { AutoFlush = true };
        using var reader = new StreamReader(pipe, Encoding.UTF8, false, 1024, true);

        var json = JsonSerializer.Serialize(request, SecureVol.Common.Policy.PolicyConfig.JsonOptions());
        await writer.WriteLineAsync(json.AsMemory(), cancellationToken).WaitAsync(DefaultRoundTripTimeout, cancellationToken).ConfigureAwait(false);
        var responseJson = await reader.ReadLineAsync(cancellationToken).AsTask().WaitAsync(DefaultRoundTripTimeout, cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(responseJson))
        {
            return new AdminResponse { Success = false, Message = "Service returned an empty response." };
        }

        return JsonSerializer.Deserialize<AdminResponse>(responseJson, SecureVol.Common.Policy.PolicyConfig.JsonOptions())
               ?? new AdminResponse { Success = false, Message = "Failed to deserialize service response." };
    }
}
