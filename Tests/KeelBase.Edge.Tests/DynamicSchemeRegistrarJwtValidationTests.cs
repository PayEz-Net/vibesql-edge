using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Encodings.Web;
using System.Text.Json;
using FluentAssertions;
using KeelBase.Edge.Authentication;
using KeelBase.Edge.Data;
using KeelBase.Edge.Data.Models;
using KeelBase.Edge.Tests.Integration;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Moq;

namespace KeelBase.Edge.Tests;

/// <summary>
/// PAY-1853 / QAPert 65279 (PRODUCT MUST). Before the fix, DynamicSchemeRegistrar built a
/// JwtBearerOptions by hand and put it straight into IOptionsMonitorCache, so the options never passed
/// through JwtBearerPostConfigureOptions: Options.ConfigurationManager (and Backchannel) stayed null.
/// JwtBearerHandler therefore never fetched the discovery document or the JWKS and validated with no
/// IssuerSigningKeys, so it refused EVERY token from EVERY provider - and every refusal was silent,
/// because the handler logs it at Information while appsettings overrides Microsoft.AspNetCore to Warning.
///
/// This row drives the REAL pipeline: the real registrar registers the provider scheme, the REAL
/// JwtBearerHandler authenticates a REAL RS256 token signed by TestJwtGenerator, over a REAL loopback
/// metadata server (discovery + JWKS). Before the fix the valid-token row is RED; the mutant proof is to
/// remove the PostConfigure/ConfigurationManager block and watch it go RED again.
/// </summary>
public class DynamicSchemeRegistrarJwtValidationTests
{
    private const string ProviderKey = "test-idp";
    private const string Audience = "test-api";
    private const string SchemeName = "Edge_" + ProviderKey;

    private sealed class InMemoryDataService : IKeelBaseDataService
    {
        private readonly List<OidcProvider> _providers = new();

        public void Add(OidcProvider p) => _providers.Add(p);

        public Task<IEnumerable<OidcProvider>> GetActiveProvidersAsync() =>
            Task.FromResult<IEnumerable<OidcProvider>>(_providers.Where(p => p.IsActive).ToList());

        public Task<OidcProvider?> GetProviderByKeyAsync(string providerKey) =>
            Task.FromResult(_providers.FirstOrDefault(p => p.ProviderKey == providerKey));

        public Task<OidcProvider> InsertProviderAsync(OidcProvider provider)
        {
            _providers.Add(provider);
            return Task.FromResult(provider);
        }

        public Task InitializeSchemaAsync() => Task.CompletedTask;
        public Task<IEnumerable<OidcProvider>> GetAllProvidersAsync() => Task.FromResult<IEnumerable<OidcProvider>>(_providers);
        public Task<OidcProvider?> GetProviderByIssuerAsync(string issuer) => Task.FromResult(_providers.FirstOrDefault(p => p.Issuer == issuer));
        public Task<OidcProvider?> UpdateProviderAsync(string k, Action<OidcProvider> a) => throw new NotSupportedException();
        public Task<bool> DisableProviderAsync(string k) => throw new NotSupportedException();
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

    /// <summary>A real loopback OIDC discovery + JWKS server on a free port. A plain HttpListener (not
    /// WebApplication) so the test-host's copied appsettings.json - which pins Kestrel to 0.0.0.0:5100 -
    /// cannot hijack the bind. Real socket on purpose: the defect is that Edge never dials metadata at
    /// all, and a real listener observes whatever HttpClient the registered options end up carrying.</summary>
    private sealed class LoopbackMetadataServer : IDisposable
    {
        private readonly HttpListener _listener;
        private readonly CancellationTokenSource _cts = new();
        private readonly Task _loop;

        public string BaseUrl { get; }

        private LoopbackMetadataServer(HttpListener listener, string baseUrl)
        {
            _listener = listener;
            BaseUrl = baseUrl;
            _loop = Task.Run(AcceptLoopAsync);
        }

        public static LoopbackMetadataServer Start()
        {
            var port = FreePort();
            var prefix = $"http://127.0.0.1:{port}/";
            var listener = new HttpListener();
            listener.Prefixes.Add(prefix);
            listener.Start();
            return new LoopbackMetadataServer(listener, prefix.TrimEnd('/'));
        }

        private static int FreePort()
        {
            var l = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
            l.Start();
            var port = ((IPEndPoint)l.LocalEndpoint).Port;
            l.Stop();
            return port;
        }

        private async Task AcceptLoopAsync()
        {
            while (!_cts.IsCancellationRequested)
            {
                HttpListenerContext ctx;
                try
                {
                    ctx = await _listener.GetContextAsync();
                }
                catch (Exception)
                {
                    return;
                }

                var path = ctx.Request.Url?.AbsolutePath ?? "";
                var (status, payload) = path switch
                {
                    "/.well-known/openid-configuration" => (200, DiscoveryJson(BaseUrl)),
                    "/.well-known/jwks" => (200, JwksJson()),
                    _ => (404, "{}")
                };

                try
                {
                    ctx.Response.StatusCode = status;
                    ctx.Response.ContentType = "application/json";
                    var bytes = System.Text.Encoding.UTF8.GetBytes(payload);
                    await ctx.Response.OutputStream.WriteAsync(bytes);
                    ctx.Response.Close();
                }
                catch (Exception)
                {
                    // client went away; keep serving
                }
            }
        }

        private static string DiscoveryJson(string issuer) => JsonSerializer.Serialize(new
        {
            issuer,
            jwks_uri = $"{issuer}/.well-known/jwks",
            token_endpoint = $"{issuer}/oauth/token",
            authorization_endpoint = $"{issuer}/oauth/authorize",
            response_types_supported = new[] { "code", "token" },
            subject_types_supported = new[] { "public" },
            id_token_signing_alg_values_supported = new[] { "RS256" }
        });

        private static string JwksJson()
        {
            var jwk = TestJwtGenerator.JsonWebKey;
            var jwks = new { keys = new[] { new { kty = jwk.Kty, n = jwk.N, e = jwk.E, kid = jwk.Kid, use = jwk.Use, alg = jwk.Alg } } };
            return JsonSerializer.Serialize(jwks);
        }

        public void Dispose()
        {
            _cts.Cancel();
            try { _listener.Stop(); } catch { }
            try { _listener.Close(); } catch { }
        }
    }

    private static async Task<(ServiceProvider sp, IOptionsMonitor<JwtBearerOptions> monitor, string baseUrl, LoopbackMetadataServer metadata)>
        HostWithRegisteredProviderAsync()
    {
        var metadata = LoopbackMetadataServer.Start();

        var provider = new OidcProvider
        {
            ProviderKey = ProviderKey,
            DisplayName = "Test IDP",
            Issuer = metadata.BaseUrl,
            DiscoveryUrl = $"{metadata.BaseUrl}/.well-known/openid-configuration",
            Audience = Audience,
            IsActive = true,
            IsFirstParty = true,
            SubjectClaimPath = "sub",
            RoleClaimPath = "roles",
            ClockSkewSeconds = 60
        };

        var data = new InMemoryDataService();
        data.Add(provider);

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IKeelBaseDataService>(data);
        services.AddSingleton<IConfiguration>(new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?> { ["KeelEdge:KeelAuth:RequireHttpsMetadata"] = "false" }).Build());

        // Mirror production DI: AddJwtBearer registers JwtBearerPostConfigureOptions as an
        // IPostConfigureOptions<JwtBearerOptions> - the exact service the registrar used to bypass.
        services.AddAuthentication().AddJwtBearer("FrameworkDefault", _ => { });

        services.AddSingleton<MultiProviderSelector>();
        services.AddSingleton<DynamicSchemeRegistrar>();

        var sp = services.BuildServiceProvider();
        await sp.GetRequiredService<DynamicSchemeRegistrar>().StartAsync(CancellationToken.None);

        return (sp, sp.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>(), metadata.BaseUrl, metadata);
    }

    private static async Task<AuthenticateResult> AuthenticateAsync(
        ServiceProvider sp, IOptionsMonitor<JwtBearerOptions> monitor, string token)
    {
        var handler = new JwtBearerHandler(monitor, NullLoggerFactory.Instance, UrlEncoder.Default);
        var context = new DefaultHttpContext { RequestServices = sp };
        context.Request.Headers.Authorization = "Bearer " + token;

        await handler.InitializeAsync(
            new AuthenticationScheme(SchemeName, null, typeof(JwtBearerHandler)), context);
        return await handler.AuthenticateAsync();
    }

    [Fact]
    public async Task M_65279_the_registrar_leaves_the_scheme_able_to_resolve_signing_keys()
    {
        var (sp, monitor, _, metadata) = await HostWithRegisteredProviderAsync();
        await using var _ = sp;
        using var __ = metadata;

        var options = monitor.Get(SchemeName);
        var hasKeys = options.ConfigurationManager is not null ||
                      options.TokenValidationParameters.IssuerSigningKey is not null ||
                      (options.TokenValidationParameters.IssuerSigningKeys?.Any() ?? false);

        hasKeys.Should().BeTrue(
            "QAPert 65279: hand-built options cached without running PostConfigure have no way to obtain " +
            "signing keys, so no token from any provider can validate");
    }

    [Fact]
    public async Task M_65279_a_valid_token_signed_by_the_provider_key_authenticates()
    {
        var (sp, monitor, baseUrl, metadata) = await HostWithRegisteredProviderAsync();
        await using var _ = sp;
        using var __ = metadata;

        var token = TestJwtGenerator.GenerateToken(baseUrl, Audience, "1022");

        var result = await AuthenticateAsync(sp, monitor, token);

        result.Succeeded.Should().BeTrue(
            "a token signed by the provider's published key must authenticate through the dynamic scheme");
    }

    [Fact]
    public async Task M_65279_a_token_signed_by_a_different_key_is_refused()
    {
        var (sp, monitor, baseUrl, metadata) = await HostWithRegisteredProviderAsync();
        await using var _ = sp;
        using var __ = metadata;

        using var otherRsa = RSA.Create(2048);
        var otherKey = new RsaSecurityKey(otherRsa) { KeyId = "test-key-1" };
        var forged = new JwtSecurityToken(
            issuer: baseUrl,
            audience: Audience,
            claims: new[] { new Claim("sub", "1022") },
            notBefore: DateTime.UtcNow.AddMinutes(-1),
            expires: DateTime.UtcNow.AddMinutes(30),
            signingCredentials: new SigningCredentials(otherKey, SecurityAlgorithms.RsaSha256));
        var forgedToken = new JwtSecurityTokenHandler().WriteToken(forged);

        var result = await AuthenticateAsync(sp, monitor, forgedToken);

        result.Succeeded.Should().BeFalse("a token whose signature does not match the published key must be refused");
    }
}
