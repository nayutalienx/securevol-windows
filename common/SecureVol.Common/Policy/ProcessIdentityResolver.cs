using System.Collections.Concurrent;
using System.Diagnostics;
using SecureVol.Common.Interop;

namespace SecureVol.Common.Policy;

public sealed class ProcessIdentityResolver : IProcessIdentityResolver
{
    private readonly ConcurrentDictionary<string, FileFactsCacheEntry> _fileFactsCache = new(StringComparer.OrdinalIgnoreCase);

    public async Task<ProcessIdentity?> ResolveAsync(
        uint processId,
        ulong expectedCreateTimeUtcFileTime,
        CancellationToken cancellationToken)
    {
        Process? process = null;
        try
        {
            process = Process.GetProcessById((int)processId);
            var observedStartTime = (ulong)process.StartTime.ToUniversalTime().ToFileTimeUtc();
            if (expectedCreateTimeUtcFileTime != 0 && observedStartTime != expectedCreateTimeUtcFileTime)
            {
                return null;
            }

            var imagePath = NativeMethods.GetProcessImagePath(processId);
            var userName = NativeMethods.GetProcessUser(processId);
            var fileFacts = await GetFileFactsAsync(imagePath, cancellationToken).ConfigureAwait(false);

            return new ProcessIdentity(
                processId,
                observedStartTime,
                fileFacts.NormalizedPath,
                userName,
                fileFacts.Sha256,
                fileFacts.IsSigned,
                fileFacts.Publisher);
        }
        catch
        {
            return null;
        }
        finally
        {
            process?.Dispose();
        }
    }

    private async Task<FileFactsCacheEntry> GetFileFactsAsync(string imagePath, CancellationToken cancellationToken)
    {
        var normalizedPath = PolicyConfig.NormalizePath(imagePath);
        var fileInfo = new FileInfo(normalizedPath);
        var lastWrite = fileInfo.LastWriteTimeUtc;
        var key = $"{normalizedPath}|{fileInfo.Length}|{lastWrite.ToFileTimeUtc()}";

        if (_fileFactsCache.TryGetValue(key, out var cached))
        {
            return cached;
        }

        var facts = await ExecutableFactsResolver.ResolveAsync(normalizedPath, cancellationToken).ConfigureAwait(false);

        var cacheEntry = new FileFactsCacheEntry(facts.NormalizedPath, facts.Sha256, facts.IsSigned, facts.Publisher);
        _fileFactsCache[key] = cacheEntry;
        return cacheEntry;
    }

    private sealed record FileFactsCacheEntry(string NormalizedPath, string Sha256, bool IsSigned, string? Publisher);
}
