using FluentAssertions;
using KeelBase.Edge.Authentication;
using KeelBase.Edge.Data;
using KeelBase.Edge.Data.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;

namespace KeelBase.Edge.Tests;

/// <summary>
/// PAY-1853 R17 (QAPert 65084, MUST-6 BAPert 65125 item 6): the RequireHttpsMetadata knob.
///
/// Driven through the real DynamicSchemeRegistrar.StartAsync -> RefreshSchemesAsync, then read back the
/// JwtBearerOptions it cached for the provider's scheme. This is the actual decision the registrar makes,
/// not a re-implementation of it.
///
///   - first-party provider + http + knob=false  -> metadata over http allowed (RequireHttpsMetadata=false)
///   - first-party provider + http + knob unset  -> https required (the default)
///   - CUSTOMER provider + http + knob=false     -> https STILL required (MUST-6: the knob cannot weaken a tenant)
///   - http://localhost is always allowed
/// </summary>
public class DynamicSchemeRegistrarR17HttpMetadataTests
{
    private static JwtBearerOptions? RegisteredOptions(bool isFirstParty, string discoveryUrl, bool? knob)
    {
        var provider = new OidcProvider
        {
            ProviderKey = isFirstParty ? "agents-issuer" : "customer-idp",
            DisplayName = "p",
            Issuer = "https://issuer.example.com",
            DiscoveryUrl = discoveryUrl,
            Audience = "acp",
            IsActive = true,
            IsFirstParty = isFirstParty
        };

        var data = new Mock<IKeelBaseDataService>();
        data.Setup(d => d.GetActiveProvidersAsync()).ReturnsAsync(new[] { provider });
        data.Setup(d => d.ProviderExistsAsync(It.IsAny<string>())).ReturnsAsync(true);

        var cfg = new Dictionary<string, string?>();
        if (knob is not null) cfg["KeelEdge:KeelAuth:RequireHttpsMetadata"] = knob.Value ? "true" : "false";
        var config = new ConfigurationBuilder().AddInMemoryCollection(cfg).Build();

        var services = new ServiceCollection();
        services.AddSingleton(data.Object);
        services.AddSingleton<IAuthenticationSchemeProvider>(
            new AuthenticationSchemeProvider(Options.Create(new AuthenticationOptions())));
        services.AddSingleton<IOptionsMonitorCache<JwtBearerOptions>>(new OptionsCache<JwtBearerOptions>());
        var sp = services.BuildServiceProvider();

        var registrar = new DynamicSchemeRegistrar(
            sp, new MultiProviderSelector(NullLogger<MultiProviderSelector>.Instance),
            config, NullLogger<DynamicSchemeRegistrar>.Instance);

        registrar.StartAsync(CancellationToken.None).GetAwaiter().GetResult();

        // Read the cached options back. RegisterOptions uses the ctor's own TryGet/Add on the cache;
        // here we read via a fresh IOptionsMonitor over the same cache type the registrar populated.
        var monitor = new OptionsMonitor<JwtBearerOptions>(
            new OptionsFactory<JwtBearerOptions>(Array.Empty<IConfigureOptions<JwtBearerOptions>>(),
                Array.Empty<IPostConfigureOptions<JwtBearerOptions>>()),
            Array.Empty<IOptionsChangeTokenSource<JwtBearerOptions>>(),
            sp.GetRequiredService<IOptionsMonitorCache<JwtBearerOptions>>());

        // The registrar populated the cache directly, so the monitor's Get returns whatever it holds.
        try
        {
            return monitor.Get($"Edge_{provider.ProviderKey}");
        }
        catch
        {
            return null;
        }
    }

    [Fact]
    public void R17_first_party_http_with_knob_false_allows_http_metadata()
    {
        var opts = RegisteredOptions(isFirstParty: true, "http://10.0.0.93:32785/.well-known/openid-configuration", knob: false);
        opts.Should().NotBeNull("the scheme must be registered");
        opts!.RequireHttpsMetadata.Should().BeFalse(
            "the knob is the dev-93 / in-cluster path: http is allowed for a first-party provider when explicitly set");
    }

    [Fact]
    public void R17_first_party_http_without_the_knob_requires_https()
    {
        var opts = RegisteredOptions(isFirstParty: true, "http://10.0.0.93:32785/.well-known/openid-configuration", knob: null);
        opts.Should().NotBeNull();
        opts!.RequireHttpsMetadata.Should().BeTrue(
            "the knob defaults to true, so http is refused unless the operator opts in");
    }

    [Fact]
    public void R17_customer_http_with_knob_false_STILL_requires_https()
    {
        var opts = RegisteredOptions(isFirstParty: false, "http://customer.example.com/.well-known/openid-configuration", knob: false);
        opts.Should().NotBeNull();
        opts!.RequireHttpsMetadata.Should().BeTrue(
            "MUST-6: the knob applies ONLY to a first-party provider; a customer IdP stays https-only in every environment");
    }

    [Fact]
    public void R17_localhost_http_is_allowed_even_for_a_customer()
    {
        var opts = RegisteredOptions(isFirstParty: false, "http://localhost:5000/.well-known/openid-configuration", knob: null);
        opts.Should().NotBeNull();
        opts!.RequireHttpsMetadata.Should().BeFalse("http://localhost is always permitted for local development");
    }

    [Fact]
    public void R17_https_is_required_by_default_for_a_first_party_provider()
    {
        var opts = RegisteredOptions(isFirstParty: true, "https://idp.payez.net/.well-known/openid-configuration", knob: null);
        opts.Should().NotBeNull();
        opts!.RequireHttpsMetadata.Should().BeTrue("an https discovery URL is unaffected");
    }
}
