using KeelBase.Edge.Data;
using KeelBase.Edge.Data.Models;
using KeelBase.Edge.Security;

namespace KeelBase.Edge.Identity;

public class FederatedIdentityResolver
{
    private readonly IKeelBaseDataService _dataService;
    private readonly ISecurityEventSink _eventSink;
    private readonly ILogger<FederatedIdentityResolver> _logger;

    public FederatedIdentityResolver(IKeelBaseDataService dataService, ISecurityEventSink eventSink, ILogger<FederatedIdentityResolver> logger)
    {
        _dataService = dataService;
        _eventSink = eventSink;
        _logger = logger;
    }

    public async Task<FederatedIdentity?> ResolveAsync(string providerKey, string externalSubject)
    {
        var identity = await _dataService.GetFederatedIdentityAsync(providerKey, externalSubject);
        if (identity != null)
        {
            await _dataService.UpdateLastSeenAsync(identity.Id);
            return identity;
        }
        return null;
    }

    public async Task<FederatedIdentity> ProvisionAsync(
        string providerKey,
        string externalSubject,
        string? email,
        string? displayName)
    {
        var vibeUserId = await _dataService.NextVibeUserIdAsync();

        var identity = new FederatedIdentity
        {
            ProviderKey = providerKey,
            ExternalSubject = externalSubject,
            VibeUserId = vibeUserId,
            Email = email,
            DisplayName = displayName
        };

        var created = await _dataService.InsertFederatedIdentityAsync(identity);
        _logger.LogInformation(
            "EDGE_IDENTITY: Auto-provisioned user {VibeUserId} for {ProviderKey}/{Subject}",
            vibeUserId, providerKey, externalSubject);

        await _eventSink.EmitSafeAsync(new EdgeSecurityEvent
        {
            EventType = EdgeEventTypes.IdentityProvisioned,
            Provider = providerKey,
            ExternalSubject = externalSubject,
            VibeUserId = vibeUserId,
            Result = "allow"
        }, _logger);

        return created;
    }
}
