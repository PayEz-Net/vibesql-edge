using System.Threading;
using System.Threading.Tasks;
using KeelBase.Edge.Identity;

namespace KeelBase.Edge.Governance;

public interface ISchemaGovernor
{
    Task<GovernanceDecision> CheckDdlAsync(ResolvedCaller caller, CancellationToken ct);
}

public record GovernanceDecision(bool Allowed, string? Reason);

public class AllowAllSchemaGovernor : ISchemaGovernor
{
    public Task<GovernanceDecision> CheckDdlAsync(ResolvedCaller caller, CancellationToken ct)
        => Task.FromResult(new GovernanceDecision(true, null));
}
