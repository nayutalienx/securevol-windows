using System.Security.Cryptography.X509Certificates;
using SecureVol.Common.Interop;

namespace SecureVol.Common.Policy;

public sealed record ExecutableFacts(
    string NormalizedPath,
    string Sha256,
    bool IsSigned,
    string? Publisher);

public static class ExecutableFactsResolver
{
    public static async Task<ExecutableFacts> ResolveAsync(string imagePath, CancellationToken cancellationToken = default)
    {
        var normalizedPath = PolicyConfig.NormalizePath(imagePath);
        var sha256 = await HashingHelpers.ComputeSha256Async(normalizedPath, cancellationToken).ConfigureAwait(false);
        var isSigned = NativeMethods.VerifyAuthenticode(normalizedPath);

        string? publisher = null;
        try
        {
            using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(normalizedPath));
            publisher = certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
        }
        catch
        {
            publisher = null;
        }

        return new ExecutableFacts(normalizedPath, sha256, isSigned, publisher);
    }
}
