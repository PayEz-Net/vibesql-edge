using System.Collections.Concurrent;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using KeelBase.Edge.Data;
using KeelBase.Edge.Data.Models;
using KeelBase.Edge.Models;

namespace KeelBase.Edge.Authentication;

public class DynamicSchemeRegistrar : IHostedService, IDisposable
{
    private readonly IServiceProvider _serviceProvider;
    private readonly MultiProviderSelector _selector;
    private readonly IConfiguration _configuration;
    private readonly ILogger<DynamicSchemeRegistrar> _logger;
    private Timer? _refreshTimer;
    private readonly ConcurrentDictionary<string, byte> _registeredSchemes = new();
    private readonly SemaphoreSlim _refreshLock = new(1, 1);

    public DynamicSchemeRegistrar(
        IServiceProvider serviceProvider,
        MultiProviderSelector selector,
        IConfiguration configuration,
        ILogger<DynamicSchemeRegistrar> logger)
    {
        _serviceProvider = serviceProvider;
        _selector = selector;
        _configuration = configuration;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("EDGE_SCHEMES: Starting dynamic scheme registrar...");
        var keelAuthConfig = _configuration.GetSection(KeelAuthOptions.SectionName).Get<KeelAuthOptions>();
        if (keelAuthConfig != null && keelAuthConfig.IsConfigured &&
            (string.IsNullOrWhiteSpace(keelAuthConfig.Issuer) ||
             string.IsNullOrWhiteSpace(keelAuthConfig.Audience) ||
             string.IsNullOrWhiteSpace(keelAuthConfig.DiscoveryUrl)))
        {
            throw new InvalidOperationException(
                "EDGE_KEELAUTH_CONFIG_INVALID: KeelEdge:KeelAuth is configured but Issuer, Audience and DiscoveryUrl must all be set.");
        }

        // M1 (NightHawk 65081): when KeelAuth is configured, a missing AgentClaim used to only log an
        // Information line, after which agent recognition is off and every agent is treated as a User -
        // with AllowAllSchemaGovernor, DDL is then ALLOWED. Fail startup instead, like the check above.
        if (keelAuthConfig != null && keelAuthConfig.IsConfigured && string.IsNullOrWhiteSpace(keelAuthConfig.AgentClaim))
        {
            throw new InvalidOperationException(
                "EDGE_KEELAUTH_CONFIG_INVALID: KeelEdge:KeelAuth is configured but AgentClaim is not set. " +
                "Without it no token can be recognised as an agent, so agent DDL would not be refused. " +
                "Set KeelEdge:KeelAuth:AgentClaim (and AgentOwnerClaim) or leave KeelAuth unconfigured.");
        }

        if (keelAuthConfig == null || !keelAuthConfig.IsConfigured)
        {
            _logger.LogInformation(
                "EDGE_KEELAUTH: not configured - agent recognition is off (no token will be treated as an agent).");
        }

        // MUST-4 (NightHawk 65130 SHOULD, promoted BAPert 65133): a first-party/agents provider added via
        // KeelBase:BootstrapProviders while KeelEdge:KeelAuth is unset leaves AgentClaim null, so every
        // agent token resolves as a User - and with AllowAllSchemaGovernor that means DDL is ALLOWED. This
        // is the R14 outcome by another route, so it fails startup rather than running open.
        if (string.IsNullOrWhiteSpace(keelAuthConfig?.AgentClaim)
            && (_configuration.GetSection("KeelBase:BootstrapProviders").Get<BootstrapProviderConfig[]>() ?? [])
                .Any(c => c.IsFirstParty))
        {
            throw new InvalidOperationException(
                "EDGE_AGENT_RECOGNITION_UNCONFIGURED: a first-party provider is configured " +
                "(KeelBase:BootstrapProviders with IsFirstParty=true) but KeelEdge:KeelAuth:AgentClaim is not " +
                "set, so no token can be recognised as an agent and agent DDL would not be refused. Set " +
                "KeelEdge:KeelAuth:AgentClaim (and AgentOwnerClaim), or remove the first-party flag.");
        }


        await SeedBootstrapProvidersAsync();
        await RefreshSchemesAsync();

        var intervalMinutes = _configuration.GetValue("KeelBase:RefreshIntervalMinutes", 30);
        _refreshTimer = new Timer(_ => _ = RefreshSchemesAsync(), null,
            TimeSpan.FromMinutes(intervalMinutes),
            TimeSpan.FromMinutes(intervalMinutes));
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _refreshTimer?.Change(Timeout.Infinite, 0);
        return Task.CompletedTask;
    }

    public void Dispose()
    {
        _refreshTimer?.Dispose();
    }

    public async Task ForceRefreshAsync()
    {
        await RefreshSchemesAsync();
    }

    /// <summary>MUST-6 (BAPert 65125 item 6): http metadata is allowed ONLY for a first-party/bootstrap
    /// provider (dev-93's IdP, in-cluster Azure). A customer IdP stays https-only in every environment,
    /// regardless of the knob - so the knob cannot be used to weaken a tenant's TLS.</summary>
    private bool AllowHttpMetadata(string discoveryUrl, bool isFirstParty)
    {
        if (discoveryUrl.StartsWith("http://localhost", StringComparison.OrdinalIgnoreCase))
            return true;
        if (!isFirstParty)
            return false;
        return _configuration.GetValue("KeelEdge:KeelAuth:RequireHttpsMetadata", true) == false;
    }

    private async Task SeedBootstrapProvidersAsync()
    {
        try
        {
            using var scope = _serviceProvider.CreateScope();
            var dataService = scope.ServiceProvider.GetRequiredService<IKeelBaseDataService>();

            var bootstrapConfigs = _configuration.GetSection("KeelBase:BootstrapProviders")
                .Get<BootstrapProviderConfig[]>() ?? [];

            // TS-09: KeelAuth is the built-in identity provider, seeded through this same
            // bootstrap path (the single loop below inserts it) instead of a second seeding path.
            var keelAuthConfig = _configuration.GetSection(KeelAuthOptions.SectionName).Get<KeelAuthOptions>();
            if (keelAuthConfig != null && keelAuthConfig.IsConfigured)
            {
                bootstrapConfigs = bootstrapConfigs
                    .Where(c => !string.Equals(c.ProviderKey, KeelAuthOptions.ProviderKey, StringComparison.Ordinal))
                    .Append(new BootstrapProviderConfig
                    {
                        ProviderKey = KeelAuthOptions.ProviderKey,
                        DisplayName = "KeelAuth",
                        Issuer = keelAuthConfig.Issuer,
                        DiscoveryUrl = keelAuthConfig.DiscoveryUrl,
                        Audience = keelAuthConfig.Audience,
                        IsBootstrap = true,
                        // KeelAuth is first-party by construction (MUST-2).
                        IsFirstParty = true
                    })
                    .ToArray();
            }

            foreach (var config in bootstrapConfigs)
            {
                if (string.IsNullOrEmpty(config.ProviderKey) || string.IsNullOrEmpty(config.Issuer))
                    continue;

                var existing = await dataService.GetProviderByKeyAsync(config.ProviderKey);
                if (existing != null)
                    continue;

                var provider = new OidcProvider
                {
                    ProviderKey = config.ProviderKey,
                    DisplayName = config.DisplayName,
                    Issuer = config.Issuer,
                    DiscoveryUrl = config.DiscoveryUrl,
                    Audience = config.Audience,
                    IsBootstrap = config.IsBootstrap,
                    IsFirstParty = config.IsFirstParty,
                    IsActive = true,
                    ClockSkewSeconds = config.ClockSkewSeconds
                };

                await dataService.InsertProviderAsync(provider);
                _logger.LogInformation("EDGE_SCHEMES: Seeded bootstrap provider {ProviderKey}", config.ProviderKey);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "EDGE_SCHEMES: Failed to seed bootstrap providers");
        }
    }

    private async Task RefreshSchemesAsync()
    {
        if (!await _refreshLock.WaitAsync(0))
            return;
        try
        {
            using var scope = _serviceProvider.CreateScope();
            var dataService = scope.ServiceProvider.GetRequiredService<IKeelBaseDataService>();
            var schemeProvider = scope.ServiceProvider.GetRequiredService<IAuthenticationSchemeProvider>();
            var optionsCache = scope.ServiceProvider.GetRequiredService<IOptionsMonitorCache<JwtBearerOptions>>();

            var providers = (await dataService.GetActiveProvidersAsync()).ToList();

            var issuerToScheme = new Dictionary<string, string>();
            var activeSchemes = new HashSet<string>();

            foreach (var provider in providers)
            {
                var schemeName = $"Edge_{provider.ProviderKey}";
                activeSchemes.Add(schemeName);
                issuerToScheme[provider.Issuer] = schemeName;

                var existing = await schemeProvider.GetSchemeAsync(schemeName);
                if (existing != null)
                    continue;

                var jwtOptions = new JwtBearerOptions
                {
                    Authority = provider.DiscoveryUrl.EndsWith("/.well-known/openid-configuration")
                        ? provider.DiscoveryUrl[..provider.DiscoveryUrl.LastIndexOf("/.well-known/openid-configuration", StringComparison.Ordinal)]
                        : provider.Issuer,
                    MetadataAddress = provider.DiscoveryUrl,
                    TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidIssuer = provider.Issuer,
                        ValidateAudience = true,
                        ValidAudience = provider.Audience,
                        ValidateLifetime = true,
                        ClockSkew = TimeSpan.FromSeconds(provider.ClockSkewSeconds),
                        NameClaimType = provider.SubjectClaimPath,
                        RoleClaimType = provider.RoleClaimPath,
                        AuthenticationType = schemeName
                    },
                    // MUST-6 (BAPert 65125 item 6): http metadata only for a first-party provider.
                    RequireHttpsMetadata = !AllowHttpMetadata(provider.DiscoveryUrl, provider.IsFirstParty)
                };

                optionsCache.TryRemove(schemeName);
                optionsCache.TryAdd(schemeName, jwtOptions);

                var scheme = new AuthenticationScheme(schemeName, provider.DisplayName,
                    typeof(JwtBearerHandler));
                schemeProvider.AddScheme(scheme);

                _registeredSchemes.TryAdd(schemeName, 0);

                _logger.LogInformation("EDGE_SCHEMES: Registered scheme {Scheme} for issuer {Issuer}",
                    schemeName, provider.Issuer);
            }

            foreach (var oldScheme in _registeredSchemes.Keys.Except(activeSchemes).ToList())
            {
                schemeProvider.RemoveScheme(oldScheme);
                optionsCache.TryRemove(oldScheme);
                _registeredSchemes.TryRemove(oldScheme, out _);
                _logger.LogInformation("EDGE_SCHEMES: Removed scheme {Scheme}", oldScheme);
            }

            _selector.UpdateMappings(issuerToScheme);

            _logger.LogInformation("EDGE_SCHEMES: Refreshed {Count} provider schemes", providers.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "EDGE_SCHEMES: Failed to refresh schemes, keeping existing");
        }
        finally
        {
            _refreshLock.Release();
        }
    }
}
