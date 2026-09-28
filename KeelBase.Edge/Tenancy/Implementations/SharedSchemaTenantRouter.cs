using System.Threading;
using System.Threading.Tasks;
using KeelBase.Edge.Data;
using KeelBase.Edge.Data.Models;
using Microsoft.Extensions.Logging;

namespace KeelBase.Edge.Tenancy.Implementations;

public class SharedSchemaTenantRouter : ITenantRouter
{
    private readonly KeelBaseDataService _dataService;
    private readonly ILogger<SharedSchemaTenantRouter> _logger;

    public SharedSchemaTenantRouter(KeelBaseDataService dataService, ILogger<SharedSchemaTenantRouter> logger)
    {
        _dataService = dataService;
        _logger = logger;
    }

    public async Task<TenantRoute> ResolveAsync(string tenantClientId, CancellationToken ct)
    {
        // Query the edge_client_credentials table for the tenant client id
        var cred = await _dataService.GetCredentialByClientIdAsync(tenantClientId);
        if (cred == null)
        {
            _logger.LogWarning("EDGE_TENANT: No credential found for tenant client id {TenantClientId}", tenantClientId);
            // Return inactive with TODO note in report later
            return new TenantRoute(tenantClientId, false, StorageKind.SharedSchema);
        }

        // Use the IsActive flag from the credential record
        var isActive = cred.IsActive;
        // Storage kind is always SharedSchema for now
        return new TenantRoute(tenantClientId, isActive, StorageKind.SharedSchema);
    }
}
