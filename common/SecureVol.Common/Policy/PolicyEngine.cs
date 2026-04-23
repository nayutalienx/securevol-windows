using System.Collections.Concurrent;

namespace SecureVol.Common.Policy;

public sealed record ProcessIdentity(
    uint ProcessId,
    ulong CreateTimeUtcFileTime,
    string ImagePath,
    string UserName,
    string Sha256,
    bool IsSigned,
    string? Publisher);

public sealed record PolicyDecision(
    AccessVerdict Verdict,
    DecisionReason Reason,
    string? RuleName,
    ProcessIdentity? Identity);

public interface IProcessIdentityResolver
{
    Task<ProcessIdentity?> ResolveAsync(uint processId, ulong expectedCreateTimeUtcFileTime, CancellationToken cancellationToken);
}

public sealed class PolicyEngine
{
    private readonly IProcessIdentityResolver _identityResolver;
    private readonly ConcurrentDictionary<string, CachedDecision> _decisionCache = new(StringComparer.OrdinalIgnoreCase);

    public PolicyEngine(IProcessIdentityResolver identityResolver)
    {
        _identityResolver = identityResolver;
    }

    public void ClearCache() => _decisionCache.Clear();

    public async Task<PolicyDecision> EvaluateAsync(
        PolicyConfig policy,
        uint policyGeneration,
        uint processId,
        ulong expectedCreateTimeUtcFileTime,
        CancellationToken cancellationToken)
    {
        if (!policy.ProtectionEnabled)
        {
            return new PolicyDecision(AccessVerdict.Allow, DecisionReason.PolicyDisabled, null, null);
        }

        var identity = await _identityResolver.ResolveAsync(processId, expectedCreateTimeUtcFileTime, cancellationToken)
            .ConfigureAwait(false);

        if (identity is null)
        {
            return new PolicyDecision(AccessVerdict.Deny, DecisionReason.ProcessLookupFailed, null, null);
        }

        var cacheKey = BuildCacheKey(identity);
        if (_decisionCache.TryGetValue(cacheKey, out var cached) && cached.PolicyGeneration == policyGeneration)
        {
            return cached.Decision with
            {
                Identity = identity,
                Reason = cached.Decision.Verdict == AccessVerdict.Allow ? DecisionReason.CachedAllow : DecisionReason.CachedDeny
            };
        }

        var decision = MatchAgainstRules(policy, identity);
        _decisionCache[cacheKey] = new CachedDecision(policyGeneration, decision);
        return decision;
    }

    private static PolicyDecision MatchAgainstRules(PolicyConfig policy, ProcessIdentity identity)
    {
        var normalizedPath = PolicyConfig.NormalizePath(identity.ImagePath);
        var candidates = policy.AllowRules
            .Where(rule => string.Equals(rule.ImagePath, normalizedPath, StringComparison.OrdinalIgnoreCase))
            .ToList();

        if (candidates.Count == 0)
        {
            return new PolicyDecision(AccessVerdict.Deny, DecisionReason.NoMatchingRule, null, identity);
        }

        var expectedGlobalUser = policy.NormalizedDefaultUser;
        foreach (var rule in candidates)
        {
            var expectedUser = PolicyConfig.NormalizeUser(rule.ExpectedUser) ?? expectedGlobalUser;
            if (!string.IsNullOrWhiteSpace(expectedUser) &&
                !string.Equals(expectedUser, identity.UserName, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!string.IsNullOrWhiteSpace(rule.Sha256) &&
                !string.Equals(rule.Sha256, identity.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (rule.RequireSignature && !identity.IsSigned)
            {
                continue;
            }

            if (!string.IsNullOrWhiteSpace(rule.Publisher) &&
                !string.Equals(rule.Publisher, identity.Publisher, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            return new PolicyDecision(AccessVerdict.Allow, DecisionReason.AllowedByRule, rule.Name, identity);
        }

        var firstRule = candidates[0];
        var expectedRuleUser = PolicyConfig.NormalizeUser(firstRule.ExpectedUser) ?? expectedGlobalUser;
        if (!string.IsNullOrWhiteSpace(expectedRuleUser) &&
            !string.Equals(expectedRuleUser, identity.UserName, StringComparison.OrdinalIgnoreCase))
        {
            return new PolicyDecision(AccessVerdict.Deny, DecisionReason.UserMismatch, firstRule.Name, identity);
        }

        if (!string.IsNullOrWhiteSpace(firstRule.Sha256) &&
            !string.Equals(firstRule.Sha256, identity.Sha256, StringComparison.OrdinalIgnoreCase))
        {
            return new PolicyDecision(AccessVerdict.Deny, DecisionReason.HashMismatch, firstRule.Name, identity);
        }

        if (firstRule.RequireSignature && !identity.IsSigned)
        {
            return new PolicyDecision(AccessVerdict.Deny, DecisionReason.SignatureRequired, firstRule.Name, identity);
        }

        if (!string.IsNullOrWhiteSpace(firstRule.Publisher) &&
            !string.Equals(firstRule.Publisher, identity.Publisher, StringComparison.OrdinalIgnoreCase))
        {
            return new PolicyDecision(AccessVerdict.Deny, DecisionReason.PublisherMismatch, firstRule.Name, identity);
        }

        return new PolicyDecision(AccessVerdict.Deny, DecisionReason.InternalError, firstRule.Name, identity);
    }

    private static string BuildCacheKey(ProcessIdentity identity) =>
        string.Join("|",
            PolicyConfig.NormalizePath(identity.ImagePath),
            identity.Sha256,
            identity.IsSigned ? "signed" : "unsigned",
            identity.Publisher ?? string.Empty,
            PolicyConfig.NormalizeUser(identity.UserName) ?? string.Empty);

    private sealed record CachedDecision(uint PolicyGeneration, PolicyDecision Decision);
}
