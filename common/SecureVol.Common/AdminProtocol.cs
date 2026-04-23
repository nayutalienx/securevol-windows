using SecureVol.Common.Policy;

namespace SecureVol.Common;

public sealed class AdminRequest
{
    public string Command { get; init; } = string.Empty;
    public string? Volume { get; init; }
    public AllowRule? Rule { get; init; }
    public string? RuleName { get; init; }
    public bool? ProtectionEnabled { get; init; }
    public string? DefaultExpectedUser { get; init; }
}

public sealed class AdminResponse
{
    public bool Success { get; init; }
    public string Message { get; init; } = string.Empty;
    public DriverStateDto? State { get; init; }
    public IReadOnlyList<RecentDenyEventDto>? RecentDenies { get; init; }
    public PolicyConfig? Policy { get; init; }
}
