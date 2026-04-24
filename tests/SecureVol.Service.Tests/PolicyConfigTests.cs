using Xunit;
using SecureVol.Common.Policy;

namespace SecureVol.Service.Tests;

public sealed class PolicyConfigTests
{
    [Fact]
    public void NormalizeVolumeIdentifier_ConvertsNtVolumePrefixToWin32VolumePrefix()
    {
        var normalized = PolicyConfig.NormalizeVolumeIdentifier(@"\??\Volume{12345678-1234-1234-1234-1234567890ab}\");

        Assert.Equal(@"\\?\Volume{12345678-1234-1234-1234-1234567890ab}", normalized);
    }

    [Fact]
    public void NormalizedProtectedMountPoint_KeepsDriveRootForm()
    {
        var policy = new PolicyConfig
        {
            ProtectedMountPoint = "A:"
        };

        Assert.Equal(@"A:\", policy.NormalizedProtectedMountPoint);
    }
}
