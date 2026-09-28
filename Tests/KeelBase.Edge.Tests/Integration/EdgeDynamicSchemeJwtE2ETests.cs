using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Sockets;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Encodings.Web;
using FluentAssertions;
using KeelBase.Edge.Authentication;
using KeelBase.Edge.Data;
using KeelBase.Edge.Data.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace KeelBase.Edge.Tests.Integration;

/// <summary>
/// PAY-1853 R18 (QAPert 65279, the 2d 93-walk FAIL): the END-TO-END JWT row the suite was missing.
///
/// The walk proved Edge 401s EVERY provider token because DynamicSchemeRegistrar hand-builds a
/// JwtBearerOptions and puts it straight into IOptionsMonitorCache, so JwtBearerPostConfigureOptions
/// never runs and options.ConfigurationManager stays null - Edge then never fetches the discovery
/// document or JWKS and validates with no IssuerSigningKeys. The whole auth front door had zero
/// coverage: TestJwtGenerator/FakeJwksHandler existed but no test used them.
///
/// This row drives the REAL pipeline a token takes:
///   real DynamicSchemeRegistrar (StartAsync -> RefreshSchemesAsync) registers the provider scheme,
///   the REAL JwtBearerHandler authenticates a REAL RS256 token signed by TestJwtGenerator,
///   over a REAL loopback metadata server (discovery + JWKS) reached by whatever HttpClient the
///   registered options end up with - so the row does not encode the shape of the fix.
///
/// RED today (no ConfigurationManager -> no keys -> not authenticated). GREEN once DotNetPert lands
/// either fix shape from QAPert 65279: apply the registered IPostConfigureOptions&lt;JwtBearerOptions&gt;
/// to the built options, or set ConfigurationManager explicitly.
/// </summary>
public class EdgeDynamicSchemeJwtE2ETests
{
    private const string ProviderKey = "e2e-idp";
    private const string Audience = "test-api";

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

        // Not exercised by the registrar/authentication path under test.
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

    /// <summary>BAPert 65280 item 2: the silent 401 was the defect, so the fix must emit an
    /// EDGE_AUTH warning with the exception type and provider key - and never the token. This captures
    /// Warning-level messages so the row can assert both halves.</summary>
    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        public List<string> Messages { get; } = new();

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(Messages);
        public void Dispose() { }

        private sealed class CapturingLogger : ILogger
        {
            private readonly List<string> _sink;
            private readonly object _gate = new();

            public CapturingLogger(List<string> sink) => _sink = sink;

            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                if (logLevel == LogLevel.Warning)
                {
                    lock (_gate) _sink.Add(formatter(state, exception));
                }
            }
        }
    }

    /// <summary>
    /// A real loopback HTTP server serving the OIDC discovery document + JWKS for TestJwtGenerator's
    /// public key. Real socket on purpose: the defect is that Edge never dials metadata at all, and a
    /// real listener lets the row observe whatever HttpClient the registered options carry.
    /// </summary>
    private sealed class LoopbackMetadataServer : IAsyncDisposable
    {
        private readonly WebApplication _app;
        public string BaseUrl { get; }
        public List<string> Requests { get; } = new();

        private LoopbackMetadataServer(WebApplication app, string baseUrl)
        {
            _app = app;
            BaseUrl = baseUrl;
        }

        public static async Task<LoopbackMetadataServer> StartAsync()
        {
            // Bind an explicit free loopback port. The rig sets ASPNETCORE_URLS (Edge's dev 5100) in the
            // environment, so UseUrls/IServerAddressesFeature are NOT a reliable source of the real
            // address - the test must choose and know its own port.
            var probe = new TcpListener(IPAddress.Loopback, 0);
            probe.Start();
            var port = ((IPEndPoint)probe.LocalEndpoint).Port;
            probe.Stop();

            var baseUrlExplicit = $"http://127.0.0.1:{port}";

            var builder = WebApplication.CreateSlimBuilder();
            builder.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.Loopback, port));
            builder.Logging.ClearProviders();

            LoopbackMetadataServer? self = null;

            var app = builder.Build();
            app.MapGet("/.well-known/openid-configuration", () =>
            {
                self?.Requests.Add("discovery");
                return Results.Text(FakeJwksHandler.DiscoveryJson(baseUrlExplicit), "application/json");
            });
            app.MapGet("/.well-known/jwks", () =>
            {
                self?.Requests.Add("jwks");
                return Results.Text(FakeJwksHandler.JwksJson(), "application/json");
            });

            await app.StartAsync();

            self = new LoopbackMetadataServer(app, baseUrlExplicit);
            return self;
        }

        public ValueTask DisposeAsync() => _app.DisposeAsync();
    }

    private sealed class TestHost : IAsyncDisposable
    {
        private readonly LoopbackMetadataServer _metadata;

        public ServiceProvider Services { get; }
        public IOptionsMonitor<JwtBearerOptions> Monitor { get; }
        public string Scheme { get; }
        public string BaseUrl => _metadata.BaseUrl;
        public IReadOnlyList<string> MetadataRequests => _metadata.Requests;
        public CapturingLoggerProvider Logs { get; }

        public TestHost(ServiceProvider sp, LoopbackMetadataServer metadata, IOptionsMonitor<JwtBearerOptions> monitor, string scheme, CapturingLoggerProvider logs)
        {
            Services = sp;
            _metadata = metadata;
            Monitor = monitor;
            Scheme = scheme;
            Logs = logs;
        }

        public async ValueTask DisposeAsync()
        {
            await _metadata.DisposeAsync();
            await Services.DisposeAsync();
        }
    }

    private static async Task<TestHost> HostWithRegisteredProviderAsync()
    {
        var metadata = await LoopbackMetadataServer.StartAsync();

        var provider = new OidcProvider
        {
            ProviderKey = ProviderKey,
            DisplayName = "E2E IDP",
            Issuer = metadata.BaseUrl,
            DiscoveryUrl = $"{metadata.BaseUrl}/.well-known/openid-configuration",
            Audience = Audience,
            IsActive = true,
            // First-party + the R17 knob off, so the registrar permits http metadata to the loopback IP.
            IsFirstParty = true,
            SubjectClaimPath = "sub",
            RoleClaimPath = "roles",
            ClockSkewSeconds = 60
        };

        var data = new InMemoryDataService();
        data.Add(provider);

        var logs = new CapturingLoggerProvider();
        var services = new ServiceCollection();
        services.AddLogging(b => b.AddProvider(logs));
        services.AddSingleton<IKeelBaseDataService>(data);
        services.AddSingleton<IConfiguration>(new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?> { ["KeelEdge:KeelAuth:RequireHttpsMetadata"] = "false" }).Build());

        // Mirror production DI: AddJwtBearer registers JwtBearerPostConfigureOptions as an
        // IPostConfigureOptions<JwtBearerOptions>, which is exactly the service the registrar bypasses.
        services.AddAuthentication().AddJwtBearer("FrameworkDefault", _ => { });

        services.AddSingleton<MultiProviderSelector>();
        services.AddSingleton<DynamicSchemeRegistrar>();

        var sp = services.BuildServiceProvider();
        var registrar = sp.GetRequiredService<DynamicSchemeRegistrar>();
        await registrar.StartAsync(CancellationToken.None);

        var scheme = $"Edge_{ProviderKey}";
        var monitor = sp.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>();
        return new TestHost(sp, metadata, monitor, scheme, logs);
    }

    private static async Task<AuthenticateResult> AuthenticateAsync(
        TestHost host, string token)
    {
        var handler = new JwtBearerHandler(host.Monitor, NullLoggerFactory.Instance, UrlEncoder.Default);
        var context = new DefaultHttpContext { RequestServices = host.Services };
        context.Request.Headers.Authorization = $"Bearer {token}";

        await handler.InitializeAsync(
            new AuthenticationScheme(host.Scheme, null, typeof(JwtBearerHandler)), context);
        return await handler.AuthenticateAsync();
    }

    [Fact]
    public async Task R18_a_valid_token_signed_by_the_registered_provider_authenticates()
    {
        await using var host = await HostWithRegisteredProviderAsync();

        var token = TestJwtGenerator.GenerateToken(host.BaseUrl, Audience, "e2e-user");

        var result = await AuthenticateAsync(host, token);

        result.Succeeded.Should().BeTrue(
            "a token signed by the provider under test must validate; the 2d walk proved Edge 401s every " +
            "provider token because the hand-built options never got a ConfigurationManager and so never " +
            "fetched the JWKS (QAPert 65279). Failure: " + result.Failure +
            "; metadata server saw [" + string.Join(",", host.MetadataRequests) + "]");
    }

    [Fact]
    public async Task R18_the_registered_options_can_actually_resolve_signing_keys()
    {
        await using var host = await HostWithRegisteredProviderAsync();

        var options = host.Monitor.Get(host.Scheme);
        var hasKeys = options.ConfigurationManager is not null ||
                      options.TokenValidationParameters.IssuerSigningKey is not null ||
                      (options.TokenValidationParameters.IssuerSigningKeys?.Any() ?? false);

        hasKeys.Should().BeTrue(
            "the registrar must leave the scheme able to obtain signing keys - via a ConfigurationManager " +
            "(the PostConfigure path) or an explicit IssuerSigningKey(s); a scheme with none validates no " +
            "token from any provider and fails silently");
    }

    [Fact]
    public async Task R18_a_token_signed_by_a_different_key_is_rejected()
    {
        await using var host = await HostWithRegisteredProviderAsync();

        var rogue = SignWithDifferentKey(host.BaseUrl, Audience, "e2e-user");

        var result = await AuthenticateAsync(host, rogue);

        result.Succeeded.Should().BeFalse(
            "the dynamic scheme must bind to the JWKS it fetched: a token signed by an unrelated key is " +
            "never authenticated");
    }

    [Fact]
    public async Task R18_an_expired_token_is_rejected_and_emits_an_EDGE_AUTH_warning_without_the_token()
    {
        await using var host = await HostWithRegisteredProviderAsync();

        // NB: TestJwtGenerator.GenerateExpiredToken is itself broken - its nbf is now-1m and exp now-5m,
        // so the JwtSecurityToken ctor throws IDX12401 (exp before nbf). Build a correctly-ordered expired
        // token (nbf well before exp, both in the past) here.
        var expired = SignExpired(host.BaseUrl, Audience, "e2e-user");

        var result = await AuthenticateAsync(host, expired);

        result.Succeeded.Should().BeFalse("an expired token must never authenticate");

        // BAPert 65280 item 2: the failure must NOT be silent. The warning names the exception type and
        // the provider scheme, and never carries the token.
        var warnings = host.Logs.Messages.Where(m => m.Contains("EDGE_AUTH")).ToList();
        warnings.Should().NotBeEmpty(
            "a rejected token must emit an EDGE_AUTH warning - the silent 401 was the defect (QAPert 65279)");
        warnings.Should().Contain(w =>
            w.Contains("SecurityTokenExpiredException") || w.Contains("Expired"),
            "the warning must name the exception type so the next failure is diagnosable");
        warnings.Should().NotContain(w => w.Contains(expired),
            "the warning must NEVER log the token or its claims");
    }

    private static string SignExpired(string issuer, string audience, string subject)
    {
        var credentials = new SigningCredentials(TestJwtGenerator.SecurityKey, SecurityAlgorithms.RsaSha256)
        {
            Key = { KeyId = "test-key-1" }
        };

        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: new[] { new Claim("sub", subject) },
            notBefore: DateTime.UtcNow.AddHours(-2),
            expires: DateTime.UtcNow.AddHours(-1),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static string SignWithDifferentKey(string issuer, string audience, string subject)
    {
        using var rsa = RSA.Create(2048);
        var credentials = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256)
        {
            Key = { KeyId = "rogue-key" }
        };

        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: new[] { new Claim("sub", subject) },
            notBefore: DateTime.UtcNow.AddMinutes(-1),
            expires: DateTime.UtcNow.AddMinutes(30),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
