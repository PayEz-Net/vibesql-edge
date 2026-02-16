using System.Collections.Concurrent;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Vibe.Edge.Data;
using Vibe.Edge.Data.Models;
using Vibe.Edge.Models;

namespace Vibe.Edge.Authentication;

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

        await SeedBootstrapProvidersAsync();
        await RefreshSchemesAsync();

        var intervalMinutes = _configuration.GetValue("VibeEdge:RefreshIntervalMinutes", 30);
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

    private async Task SeedBootstrapProvidersAsync()
    {
        try
        {
            using var scope = _serviceProvider.CreateScope();
            var dataService = scope.ServiceProvider.GetRequiredService<VibeDataService>();

            var bootstrapConfigs = _configuration.GetSection("VibeEdge:BootstrapProviders")
                .Get<BootstrapProviderConfig[]>() ?? [];

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
            var dataService = scope.ServiceProvider.GetRequiredService<VibeDataService>();
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
                    RequireHttpsMetadata = !provider.DiscoveryUrl.StartsWith("http://localhost", StringComparison.OrdinalIgnoreCase)
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
