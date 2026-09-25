namespace KeelBase.Edge.Tenancy;

using System.Threading;
using System.Threading.Tasks;

public interface ITenantRouter
{
    Task<TenantRoute> ResolveAsync(string tenantClientId, CancellationToken ct);
}
