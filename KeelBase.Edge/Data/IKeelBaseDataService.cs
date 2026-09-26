using KeelBase.Edge.Data.Models;

namespace KeelBase.Edge.Data;

/// <summary>
/// PAY-1852 test seam (BAPert 65136). An interface over KeelBaseDataService's existing public surface,
/// so the identity/permission/registrar chain can be driven by a mock in KeelBase.Edge.Tests without a
/// live Postgres. No behaviour change: the implementation is the same class, and every method here
/// matches an existing public method exactly.
/// </summary>
public interface IKeelBaseDataService
{
    // Schema
    Task InitializeSchemaAsync();

    // Providers
    Task<IEnumerable<OidcProvider>> GetAllProvidersAsync();
    Task<IEnumerable<OidcProvider>> GetActiveProvidersAsync();
    Task<OidcProvider?> GetProviderByKeyAsync(string providerKey);
    Task<OidcProvider?> GetProviderByIssuerAsync(string issuer);
    Task<OidcProvider> InsertProviderAsync(OidcProvider provider);
    Task<OidcProvider?> UpdateProviderAsync(string providerKey, Action<OidcProvider> applyUpdates);
    Task<bool> DisableProviderAsync(string providerKey);
    Task<bool> ProviderExistsAsync(string providerKey);

    // Role mappings
    Task<IEnumerable<OidcProviderRoleMapping>> GetRoleMappingsAsync(string providerKey);
    Task<OidcProviderRoleMapping?> GetRoleMappingByIdAsync(int id);
    Task<IEnumerable<OidcProviderRoleMapping>> GetRoleMappingsByRolesAsync(string providerKey, IEnumerable<string> roles);
    Task<OidcProviderRoleMapping> InsertRoleMappingAsync(OidcProviderRoleMapping mapping);
    Task<OidcProviderRoleMapping?> UpdateRoleMappingAsync(int id, Action<OidcProviderRoleMapping> applyUpdates);
    Task<bool> DeleteRoleMappingAsync(int id);

    // Client mappings
    Task<IEnumerable<OidcProviderClientMapping>> GetClientMappingsAsync(string providerKey);
    Task<OidcProviderClientMapping?> GetClientMappingByIdAsync(int id);
    Task<OidcProviderClientMapping?> GetActiveClientMappingAsync(string providerKey);
    Task<OidcProviderClientMapping> InsertClientMappingAsync(OidcProviderClientMapping mapping);
    Task<OidcProviderClientMapping?> UpdateClientMappingAsync(int id, Action<OidcProviderClientMapping> applyUpdates);
    Task<bool> DeleteClientMappingAsync(int id);

    // Federated identities
    Task<IEnumerable<FederatedIdentity>> GetFederatedIdentitiesAsync(int limit = 100, int offset = 0, string? providerKey = null);
    Task<FederatedIdentity?> GetFederatedIdentityByIdAsync(int id);
    Task<FederatedIdentity?> GetFederatedIdentityAsync(string providerKey, string externalSubject);
    Task<FederatedIdentity> InsertFederatedIdentityAsync(FederatedIdentity identity);
    Task UpdateLastSeenAsync(int id);
    Task<int> NextVibeUserIdAsync();

    // Credentials
    Task<IEnumerable<EdgeClientCredential>> GetAllCredentialsAsync();
    Task<EdgeClientCredential?> GetCredentialByIdAsync(int id);
    Task<EdgeClientCredential?> GetCredentialByClientIdAsync(string clientId);
    Task<EdgeClientCredential> InsertCredentialAsync(EdgeClientCredential credential);
    Task<EdgeClientCredential?> UpdateCredentialAsync(int id, Action<EdgeClientCredential> applyUpdates);
    Task<bool> DeleteCredentialAsync(int id);

    // Publishable keys
    Task<PublishableKey?> GetPublishableKeyByPrefixAsync(string keyPrefix);
    Task<PublishableKey> CreatePublishableKeyAsync(string keyPrefix, string keyHash, string tenantClientId);
    Task<bool> RevokePublishableKeyAsync(int id);
}
