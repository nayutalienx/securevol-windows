using SecureVol.Common;
using SecureVol.Common.Policy;
using Xunit;

namespace SecureVol.Service.Tests;

public sealed class PolicyEngineTests
{
    [Fact]
    public async Task Allows_WhenPathHashPublisherAndUserMatch()
    {
        var identity = new ProcessIdentity(
            42,
            123,
            @"C:\Program Files\Google\Chrome\Application\chrome.exe",
            @".\vc_app",
            "ABCDEF",
            true,
            "Google LLC");

        var engine = new PolicyEngine(new StubResolver(identity));
        var policy = new PolicyConfig
        {
            ProtectionEnabled = true,
            ProtectedVolume = @"\\?\Volume{1234-5678}",
            AllowRules =
            [
                new AllowRule
                {
                    Name = "chrome",
                    ImagePath = PolicyConfig.NormalizePath(identity.ImagePath),
                    Sha256 = "ABCDEF",
                    RequireSignature = true,
                    Publisher = "Google LLC",
                    ExpectedUser = @".\vc_app"
                }
            ]
        };

        var result = await engine.EvaluateAsync(policy, 7, identity.ProcessId, identity.CreateTimeUtcFileTime, CancellationToken.None);

        Assert.Equal(AccessVerdict.Allow, result.Verdict);
        Assert.Equal(DecisionReason.AllowedByRule, result.Reason);
        Assert.Equal("chrome", result.RuleName);
    }

    [Fact]
    public async Task Denies_WhenExpectedUserDoesNotMatch()
    {
        var identity = new ProcessIdentity(
            52,
            456,
            @"C:\Telegram\Telegram.exe",
            @"MACHINE\wrong_user",
            "123456",
            true,
            "Telegram FZ-LLC");

        var engine = new PolicyEngine(new StubResolver(identity));
        var policy = new PolicyConfig
        {
            ProtectionEnabled = true,
            ProtectedVolume = @"\\?\Volume{1234-5678}",
            AllowRules =
            [
                new AllowRule
                {
                    Name = "telegram",
                    ImagePath = PolicyConfig.NormalizePath(identity.ImagePath),
                    ExpectedUser = @".\vc_app"
                }
            ]
        };

        var result = await engine.EvaluateAsync(policy, 9, identity.ProcessId, identity.CreateTimeUtcFileTime, CancellationToken.None);

        Assert.Equal(AccessVerdict.Deny, result.Verdict);
        Assert.Equal(DecisionReason.UserMismatch, result.Reason);
    }

    [Fact]
    public async Task Denies_WhenHashDoesNotMatch()
    {
        var identity = new ProcessIdentity(
            99,
            789,
            @"C:\Portable\Telegram.exe",
            @".\vc_app",
            "AAAAAA",
            false,
            null);

        var engine = new PolicyEngine(new StubResolver(identity));
        var policy = new PolicyConfig
        {
            ProtectionEnabled = true,
            ProtectedVolume = @"\\?\Volume{1234-5678}",
            AllowRules =
            [
                new AllowRule
                {
                    Name = "telegram",
                    ImagePath = PolicyConfig.NormalizePath(identity.ImagePath),
                    Sha256 = "BBBBBB"
                }
            ]
        };

        var result = await engine.EvaluateAsync(policy, 10, identity.ProcessId, identity.CreateTimeUtcFileTime, CancellationToken.None);

        Assert.Equal(AccessVerdict.Deny, result.Verdict);
        Assert.Equal(DecisionReason.HashMismatch, result.Reason);
    }

    [Fact]
    public async Task ComputesExpectedSha256()
    {
        var tempPath = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(tempPath, "securevol-test");
            var hash = await HashingHelpers.ComputeSha256Async(tempPath);
            Assert.Equal("9F406D05E87ACFEA82475746D0E0ADAD7FDFDBDB5F6465EFB4D49492EE1E6FCD", hash);
        }
        finally
        {
            File.Delete(tempPath);
        }
    }

    private sealed class StubResolver : IProcessIdentityResolver
    {
        private readonly ProcessIdentity _identity;

        public StubResolver(ProcessIdentity identity)
        {
            _identity = identity;
        }

        public Task<ProcessIdentity?> ResolveAsync(uint processId, ulong expectedCreateTimeUtcFileTime, CancellationToken cancellationToken)
        {
            if (_identity.ProcessId == processId && _identity.CreateTimeUtcFileTime == expectedCreateTimeUtcFileTime)
            {
                return Task.FromResult<ProcessIdentity?>(_identity);
            }

            return Task.FromResult<ProcessIdentity?>(null);
        }
    }
}
