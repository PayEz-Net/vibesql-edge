namespace KeelBase.Edge.Limits;

public interface ITierLimitStore
{
    /// <summary>Increments the counter and returns true if within limit, false if exceeded.</summary>
    Task<bool> TryIncrementAsync(string tenantClientId, string limitName, long limit, CancellationToken ct);
}
