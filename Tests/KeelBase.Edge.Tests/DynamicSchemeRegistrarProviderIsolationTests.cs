using FluentAssertions;
using KeelBase.Edge.Authentication;
using KeelBase.Edge.Data;
using KeelBase.Edge.Data.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace KeelBase.Edge.Tests;

/// <summary>
/// BAPert 65307 (a) / QAPert 65303: ONE bad provider must not abort scheme registration for EVERY
/// provider. JwtBearerPostConfigureOptions throws for a provider with RequireHttpsMetadata=true and an
/// http discovery URL - exactly a customer provider MUST-6 refuses. Before the per-provider guard that
/// throw propagated to the outer catch in RefreshSchemesAsync, so nothing after it ran: later providers,
/// the removal loop and UpdateMappings. A single bad admin row then meant no provider registered after
/// the next restart, every caller 401'd, and /health/ready still reported 200.
///
/// These rows drive the REAL registrar with the REAL AddJwtBearer DI (which registers
/// JwtBearerPostConfigureOptions). No network: a customer-http provider throws while BUILDING its
/// options, and a first-party http provider builds lazily (metadata is only fetched on first token).
/// </summary>
public class DynamicSchemeRegistrarProviderIsolationTests
{
    private sealed class InMemoryDataService : IKeelBaseDataService
    {
        private readonly List<OidcProvider> _providers = new();

        public void Set(params OidcProvider[] providers)
        {
            _providers.Clear();
            _providers.AddRange(providers);
        }

        public Task<IEnumerable<OidcProvider>> GetActiveProvidersAsync() =>
            Task.FromResult<IEnumerable<OidcProvider>>(_providers.Where(p => p.IsActive).ToList());

        public Task<OidcProvider?> GetProviderByKeyAsync(string providerKey) =>
            Task.FromResult(_providers.FirstOrDefault(p => p.ProviderKey == providerKey));

        public Task<bool> DisableProviderAsync(string providerKey)
        {
            var p = _providers.FirstOrDefault(x => x.ProviderKey == providerKey);
            if (p is null) return Task.FromResult(false);
            p.IsActive = false;
            return Task.FromResult(true);
        }

        // Not exercised by the registrar path under test.
        public Task InitializeSchemaAsync() => Task.CompletedTask;
        public Task<IEnumerable<OidcProvider>> GetAllProvidersAsync() => Task.FromResult<IEnumerable<OidcProvider>>(_providers);
        public Task<OidcProvider?> GetProviderByIssuerAsync(string issuer) => Task.FromResult(_providers.FirstOrDefault(p => p.Issuer == issuer));
        public Task<OidcProvider> InsertProviderAsync(OidcProvider provider)
        {
            _providers.Add(provider);
            return Task.FromResult(provider);
        }
        public Task<OidcProvider?> UpdateProviderAsync(string k, Action<OidcProvider> a) => throw new NotSupportedException();
        public Task<bool> ProviderExistsAsync(string k) => Task.FromResult(_providers.Any(p => p.ProviderKey == k));
        public Task<IEnumerable<OidcProviderRoleMapping>> GetRoleMappingsAsync(string k) => throw new NotSupportedException();
        public Task<OidcProviderRoleMapping?> GetRoleMappingByIdAsync(int id) => throw new NotSupportedException();
        public Task<IEnumerable<OidcProviderRoleMapping>> GetRoleMappingsByRolesAsync(string k, IEnumerable<string> r) => throw new NotSupportedException();
        public Task<OidcProviderRoleMapping> InsertRoleMappingAsync(OidcProviderRoleMapping m) => throw new NotSupportedException();
        public Task<OidcProviderRoleMapping?> UpdateRoleMappingAsync(int id, Action<OidcProviderRoleMapping> a) => throw new NotSupportedException();
        public Task<bool> DeleteRoleMappingAsync(int id) => throw new NotSupportedException();
        public Task<IEnumerable<OidcProviderClientMapping>> GetClientMappingsAsync(string k) => throw new NotSupportedException();
        public Task<OidcProviderClientMapping?> GetClientMappingByIdAsync(int id) => throw new NotSupportedException();
        public Task<OidcProviderClientMapping?> GetActiveClientMappingAsync(string k) => throw new NotSupportedException();
        public Task<OidcProviderClientMapping> InsertClientMappingAsync(OidcProviderClientMapping m) => throw new NotSupportedException();
        public Task<OidcProviderClientMapping?> UpdateClientMappingAsync(int id, Action<OidcProviderClientMapping> a) => throw new NotSupportedException();
        public Task<bool> DeleteClientMappingAsync(int id) => throw new NotSupportedException();
        public Task<IEnumerable<FederatedIdentity>> GetFederatedIdentitiesAsync(int limit = 100, int offset = 0, string? providerKey = null) => throw new NotSupportedException();
        public Task<FederatedIdentity?> GetFederatedIdentityByIdAsync(int id) => throw new NotSupportedException();
        public Task<FederatedIdentity?> GetFederatedIdentityAsync(string providerKey, string externalSubject) => throw new NotSupportedException();
        public Task<FederatedIdentity> InsertFederatedIdentityAsync(FederatedIdentity identity) => throw new NotSupportedException();
        public Task UpdateLastSeenAsync(int id) => throw new NotSupportedException();
        public Task<int> NextVibeUserIdAsync() => throw new NotSupportedException();
        public Task<IEnumerable<EdgeClientCredential>> GetAllCredentialsAsync() => throw new NotSupportedException();
        public Task<EdgeClientCredential?> GetCredentialByIdAsync(int id) => throw new NotSupportedException();
        public Task<EdgeClientCredential?> GetCredentialByClientIdAsync(string clientId) => throw new NotSupportedException();
        public Task<EdgeClientCredential> InsertCredentialAsync(EdgeClientCredential credential) => throw new NotSupportedException();
        public Task<EdgeClientCredential?> UpdateCredentialAsync(int id, Action<EdgeClientCredential> a) => throw new NotSupportedException();
        public Task<bool> DeleteCredentialAsync(int id) => throw new NotSupportedException();
        public Task<PublishableKey?> GetPublishableKeyByPrefixAsync(string keyPrefix) => throw new NotSupportedException();
        public Task<PublishableKey> CreatePublishableKeyAsync(string keyPrefix, string keyHash, string tenantClientId) => throw new NotSupportedException();
        public Task<bool> RevokePublishableKeyAsync(int id) => throw new NotSupportedException();
    }

    private static OidcProvider Provider(string key, string url, bool firstParty) => new()
    {
        ProviderKey = key,
        DisplayName = key,
        Issuer = url,
        DiscoveryUrl = url + "/.well-known/openid-configuration",
        Audience = "acp",
        IsActive = true,
        IsFirstParty = firstParty,
        SubjectClaimPath = "sub",
        RoleClaimPath = "roles",
        ClockSkewSeconds = 60
    };

    private static (ServiceProvider sp, InMemoryDataService data, DynamicSchemeRegistrar registrar) BuildHost()
    {
        var data = new InMemoryDataService();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IKeelBaseDataService>(data);
        // R17 knob off so a first-party http provider is permitted (metadata is still lazy).
        services.AddSingleton<IConfiguration>(new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?> { ["KeelEdge:KeelAuth:RequireHttpsMetadata"] = "false" }).Build());

        // Real AddJwtBearer -> registers JwtBearerPostConfigureOptions, the thrower for http + requireHttps.
        services.AddAuthentication().AddJwtBearer("FrameworkDefault", _ => { });
        services.AddSingleton<MultiProviderSelector>();
        services.AddSingleton<DynamicSchemeRegistrar>();

        var sp = services.BuildServiceProvider();
        return (sp, data, sp.GetRequiredService<DynamicSchemeRegistrar>());
    }

    private static async Task<bool> SchemeRegistered(ServiceProvider sp, string scheme) =>
        await sp.GetRequiredService<IAuthenticationSchemeProvider>().GetSchemeAsync(scheme) is not null;

    [Fact]
    public async Task A_65307_a_bad_customer_http_provider_listed_FIRST_does_not_stop_a_valid_first_party_provider()
    {
        var (sp, data, registrar) = BuildHost();
        await using var _ = sp;

        // A customer provider with an http discovery URL (requireHttps=true -> PostConfigure throws),
        // listed BEFORE the valid first-party provider, is the exact hostile ordering from QAPert 65303.
        data.Set(
            Provider("customer-http", "http://customer.example.com", firstParty: false),
            Provider("firstparty-http", "http://idp.local.test", firstParty: true));

        await registrar.StartAsync(CancellationToken.None);

        (await SchemeRegistered(sp, "Edge_firstparty-http")).Should().BeTrue(
            "BAPert 65307 (a): a bad provider must be skipped per-provider, not abort the whole refresh");
        (await SchemeRegistered(sp, "Edge_customer-http")).Should().BeFalse(
            "the bad customer-http provider must NOT be registered");
    }

    [Fact]
    public async Task A_65307_a_rejected_provider_is_not_routed_by_the_selector()
    {
        var (sp, data, registrar) = BuildHost();
        await using var _ = sp;

        const string badIssuer = "http://customer.example.com";
        data.Set(
            Provider("customer-http", badIssuer, firstParty: false),
            Provider("firstparty-http", "http://idp.local.test", firstParty: true));

        await registrar.StartAsync(CancellationToken.None);

        // A rejected provider must never enter the issuer->scheme mapping: if it did, a token from that
        // issuer would be routed to a scheme that was never added.
        var selector = sp.GetRequiredService<MultiProviderSelector>();
        var context = new Microsoft.AspNetCore.Http.DefaultHttpContext();
        context.Request.Headers.Authorization = "Bearer " + MakeUnsignedToken(badIssuer);
        selector.SelectScheme(context).Should().Be("FallbackReject",
            "a rejected provider's issuer must not resolve to a live scheme");
    }

    [Fact]
    public async Task A_65307_disable_still_removes_the_scheme_when_a_bad_provider_is_present()
    {
        var (sp, data, registrar) = BuildHost();
        await using var _ = sp;

        data.Set(
            Provider("firstparty-http", "http://idp.local.test", firstParty: true),
            Provider("customer-http", "http://customer.example.com", firstParty: false));

        await registrar.StartAsync(CancellationToken.None);
        (await SchemeRegistered(sp, "Edge_firstparty-http")).Should().BeTrue();

        // A bad provider is present at the SAME time the good one is disabled (DELETE -> disable + refresh).
        await data.DisableProviderAsync("firstparty-http");
        await registrar.ForceRefreshAsync();

        (await SchemeRegistered(sp, "Edge_firstparty-http")).Should().BeFalse(
            "BAPert 65307: the removal loop must always run, so DELETE is not silently disabled by a bad row");
    }

    /// <summary>An unsigned token is enough to read the `iss` claim; the selector only parses the issuer.</summary>
    private static string MakeUnsignedToken(string issuer)
    {
        static string B64(string s) => Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(s))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var header = B64("{\"alg\":\"none\",\"typ\":\"JWT\"}");
        var payload = B64($"{{\"iss\":\"{issuer}\",\"aud\":\"acp\",\"sub\":\"x\"}}");
        return $"{header}.{payload}.";
    }
}
