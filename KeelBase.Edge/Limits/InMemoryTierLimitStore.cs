using System.Collections.Concurrent;

namespace KeelBase.Edge.Limits;

// NOTE: production needs a shared store (e.g. Redis) — this in-memory store resets on restart
// and is not shared across instances.
public class InMemoryTierLimitStore : ITierLimitStore
{
    private readonly ConcurrentDictionary<string, long> _counts = new();

    public Task<bool> TryIncrementAsync(string tenantClientId, string limitName, long limit, CancellationToken ct)
    {
        var key = $"{tenantClientId}:{limitName}:{DateTime.UtcNow:yyyyMMdd}";
        var newCount = _counts.AddOrUpdate(key, 1, (_, c) => c + 1);
        return Task.FromResult(newCount <= limit);
    }
}
