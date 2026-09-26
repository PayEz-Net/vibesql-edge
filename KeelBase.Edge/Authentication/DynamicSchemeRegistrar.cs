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

    /// <summary>R17 (QAPert 65084): http metadata is allowed when the operator sets the knob, or for localhost.
    /// This is what lets dev-93 (http://10.0.0.93:32785) and in-cluster Azure validate tokens.</summary>
    private bool AllowHttpMetadata(string discoveryUrl)
    {
        if (_configuration.GetValue("KeelEdge:KeelAuth:RequireHttpsMetadata", true) == false)
            return true;
        return discoveryUrl.StartsWith("http://localhost", StringComparison.OrdinalIgnoreCase);
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
                        IsBootstrap = true
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
                    // R17 (QAPert 65084): HTTPS enforcement was keyed on the literal "http://localhost".
                    // dev-93's IdP is http://10.0.0.93:32785 and in-cluster Azure is http too, so every
                    // token was rejected before the walk. Allow http when the knob is set OR for localhost.
                    RequireHttpsMetadata = !AllowHttpMetadata(provider.DiscoveryUrl)
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
