using FluentAssertions;
using KeelBase.Edge.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;

namespace KeelBase.Edge.Tests;

/// <summary>
/// PAY-1853 R1 + MUST-4: the two STARTUP refusals. Both throw from DynamicSchemeRegistrar.StartAsync
/// BEFORE any service resolution or seeding, so they are unit-testable with an in-memory configuration
/// and a stub IServiceProvider - no host, no database.
///
///   R1 (M1, NightHawk 65081): KeelAuth configured but AgentClaim unset -> refuse to start. Without it
///      agent recognition is silently off and, with AllowAllSchemaGovernor, agent DDL would be ALLOWED.
///   MUST-4 (NightHawk 65130 promoted by BAPert 65133): a first-party BootstrapProviders entry while the
///      KeelEdge:KeelAuth section is unset -> refuse to start. Same outcome as R14, reached via config.
/// </summary>
public class DynamicSchemeRegistrarStartupGuardTests
{
    private static DynamicSchemeRegistrar Registrar(Dictionary<string, string?> cfg)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(cfg).Build();
        // The MUST-4/R1 throws happen before the service provider is used, so an empty stub is enough.
        return new DynamicSchemeRegistrar(
            new StubServiceProvider(), new MultiProviderSelector(NullLogger<MultiProviderSelector>.Instance),
            config, NullLogger<DynamicSchemeRegistrar>.Instance);
    }

    private sealed class StubServiceProvider : IServiceProvider
    {
        public object? GetService(Type serviceType) => null;
    }

    // ── R1 ────────────────────────────────────────────────────────────────────────────────────────────
    [Fact]
    public async Task R1_keelAuth_configured_without_AgentClaim_refuses_startup()
    {
        var reg = Registrar(new()
        {
            ["KeelEdge:KeelAuth:Issuer"] = "https://idp.payez.net",
            ["KeelEdge:KeelAuth:Audience"] = "acp",
            ["KeelEdge:KeelAuth:DiscoveryUrl"] = "https://idp.payez.net/.well-known/openid-configuration",
            // AgentClaim deliberately omitted
        });

        var act = async () => await reg.StartAsync(CancellationToken.None);

        var ex = await act.Should().ThrowAsync<InvalidOperationException>(
            "M1: a configured KeelAuth with no AgentClaim means no token can be an agent, so DDL would be allowed");
        ex.Which.Message.Should().Contain("EDGE_KEELAUTH_CONFIG_INVALID");
    }

    [Fact]
    public async Task R1_control_keelAuth_configured_with_AgentClaim_does_not_throw_that_error()
    {
        var reg = Registrar(new()
        {
            ["KeelEdge:KeelAuth:Issuer"] = "https://idp.payez.net",
            ["KeelEdge:KeelAuth:Audience"] = "acp",
            ["KeelEdge:KeelAuth:DiscoveryUrl"] = "https://idp.payez.net/.well-known/openid-configuration",
            ["KeelEdge:KeelAuth:AgentClaim"] = "user_type",
            ["KeelEdge:KeelAuth:AgentOwnerClaim"] = "owner_user_id",
        });

        // It proceeds past the guard and fails later on real seeding (no host); assert only that the
        // STARTUP-GUARD exception is not the one raised.
        try
        {
            await reg.StartAsync(CancellationToken.None);
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("EDGE_KEELAUTH_CONFIG_INVALID"))
        {
            Assert.Fail("control: with AgentClaim set the R1 guard must not fire; got: " + ex.Message);
        }
        catch
        {
            // any other failure (no provider / no host) is expected and irrelevant to the R1 guard
        }
    }

    // ── MUST-4 ────────────────────────────────────────────────────────────────────────────────────────
    [Fact]
    public async Task MUST4_first_party_bootstrap_provider_without_KeelAuth_refuses_startup()
    {
        var reg = Registrar(new()
        {
            // KeelEdge:KeelAuth section deliberately absent
            ["KeelBase:BootstrapProviders:0:ProviderKey"] = "agents-issuer",
            ["KeelBase:BootstrapProviders:0:Issuer"] = "https://idp.payez.net/agents",
            ["KeelBase:BootstrapProviders:0:Audience"] = "acp",
            ["KeelBase:BootstrapProviders:0:DiscoveryUrl"] = "https://idp.payez.net/agents/.well-known/openid-configuration",
            ["KeelBase:BootstrapProviders:0:IsFirstParty"] = "true",
        });

        var act = async () => await reg.StartAsync(CancellationToken.None);

        var ex = await act.Should().ThrowAsync<InvalidOperationException>(
            "MUST-4: a first-party provider with no AgentClaim leaves agent recognition off, which is the " +
            "R14 outcome by another route - startup must refuse rather than run open");
        ex.Which.Message.Should().Contain("EDGE_AGENT_RECOGNITION_UNCONFIGURED");
    }

    [Fact]
    public async Task MUST4_control_a_non_first_party_bootstrap_provider_does_not_trip_it()
    {
        var reg = Registrar(new()
        {
            ["KeelBase:BootstrapProviders:0:ProviderKey"] = "customer-idp",
            ["KeelBase:BootstrapProviders:0:Issuer"] = "https://customer.example.com",
            ["KeelBase:BootstrapProviders:0:Audience"] = "acp",
            ["KeelBase:BootstrapProviders:0:DiscoveryUrl"] = "https://customer.example.com/.well-known/openid-configuration",
            ["KeelBase:BootstrapProviders:0:IsFirstParty"] = "false",
        });

        try
        {
            await reg.StartAsync(CancellationToken.None);
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("EDGE_AGENT_RECOGNITION_UNCONFIGURED"))
        {
            Assert.Fail("control: a customer (non-first-party) provider must not trip the MUST-4 guard");
        }
        catch
        {
            // expected: seeding fails with no host
        }
    }
}
