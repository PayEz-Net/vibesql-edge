using System.Security.Claims;
using System.Text.Json;
using FluentAssertions;
using KeelBase.Edge.Authentication;
using KeelBase.Edge.Data;
using KeelBase.Edge.Data.Models;
using KeelBase.Edge.Identity;
using KeelBase.Edge.Security;
using KeelBase.Edge.Tenancy;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;

namespace KeelBase.Edge.Tests;

/// <summary>
/// PAY-1853 R9 / R14 / R15 and the owner-forgery guard, hosted through IdentityResolutionMiddleware via
/// the IKeelBaseDataService seam (BAPert 65136). These are the rows that could not be written before the
/// seam existed. Each drives the middleware directly with an authenticated ClaimsPrincipal - no Postgres.
/// </summary>
public class IdentityResolutionMiddlewareTests
{
    private const string KeelAuthKey = "KeelAuth";

    private static KeelAuthOptions Options_(string agentClaim = "user_type", string claimValue = "agent",
        string? ownerClaim = "owner_user_id", string? idClaim = "agent_profile_id") => new()
    {
        Issuer = "https://idp.payez.net",
        Audience = "acp",
        DiscoveryUrl = "https://idp.payez.net/.well-known/openid-configuration",
        AgentClaim = agentClaim,
        AgentClaimValue = claimValue,
        AgentOwnerClaim = ownerClaim,
        AgentIdClaim = idClaim
    };

    private static HttpContext Context(
        IEnumerable<Claim> claims,
        string authType = "Edge_" + KeelAuthKey,
        string path = "/v1/query")
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Path = path;
        ctx.Request.Method = "POST";
        ctx.User = new ClaimsPrincipal(new ClaimsIdentity(claims, authType));
        return ctx;
    }

    private static (IdentityResolutionMiddleware mw, Mock<IKeelBaseDataService> data, Mock<ISecurityEventSink> sink)
        Build(KeelAuthOptions opts, OidcProvider? provider = null, FederatedIdentity? identity = null)
    {
        var data = new Mock<IKeelBaseDataService>();
        data.Setup(d => d.GetProviderByKeyAsync(It.IsAny<string>())).ReturnsAsync(provider);
        data.Setup(d => d.GetFederatedIdentityAsync(It.IsAny<string>(), It.IsAny<string>())).ReturnsAsync(identity);
        var sink = new Mock<ISecurityEventSink>();
        var router = new Mock<ITenantRouter>();
        router.Setup(r => r.ResolveAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
              .ReturnsAsync(new TenantRoute(KeelAuthKey, true, StorageKind.SharedSchema));

        var mw = new IdentityResolutionMiddleware(
            _ => Task.CompletedTask,
            NullLogger<IdentityResolutionMiddleware>.Instance,
            sink.Object,
            router.Object,
            Options.Create(opts));
        return (mw, data, sink);
    }

    private static OidcProvider Provider(bool firstParty = true) => new()
    {
        ProviderKey = KeelAuthKey,
        Issuer = "https://idp.payez.net",
        Audience = "acp",
        IsActive = true,
        AutoProvision = false,
        // MUST-2 (DotNetPert 0f43cb9): agent recognition + the owner claim are honoured only from a
        // FIRST-PARTY provider. KeelAuth is auto-flagged first-party, so the default fixture is first-party.
        IsFirstParty = firstParty,
        SubjectClaimPath = "sub",
        RoleClaimPath = "roles",
        EmailClaimPath = "email"
    };

    private static FederatedIdentity Identity(int userId = 42) => new()
    {
        ProviderKey = KeelAuthKey,
        ExternalSubject = "subject-1",
        VibeUserId = userId,
        IsActive = true
    };

    private static void Wire(HttpContext ctx, Mock<IKeelBaseDataService> data, Mock<ISecurityEventSink> sink)
    {
        var services = new Mock<IServiceProvider>();
        services.Setup(s => s.GetService(typeof(IKeelBaseDataService))).Returns(data.Object);
        services.Setup(s => s.GetService(typeof(FederatedIdentityResolver)))
                .Returns(new FederatedIdentityResolver(data.Object, sink.Object,
                    NullLogger<FederatedIdentityResolver>.Instance));
        ctx.RequestServices = services.Object;
    }

    private static async Task<(int status, string body)> Run(IdentityResolutionMiddleware mw, HttpContext ctx)
    {
        await mw.InvokeAsync(ctx);
        var body = await ReadBody(ctx);
        return (ctx.Response.StatusCode, body);
    }

    private static async Task<string> ReadBody(HttpContext ctx)
    {
        if (ctx.Response.Body is MemoryStream ms) { ms.Position = 0; return await new StreamReader(ms).ReadToEndAsync(); }
        return string.Empty;
    }

    private static void BufferBody(HttpContext ctx) => ctx.Response.Body = new MemoryStream();

    // ── R9 (NightHawk 65081 S7): an agent token with no owner claim -> 403 AGENT_OWNER_MISSING ─────────

    [Fact]
    public async Task R9_agent_without_owner_claim_is_denied_403()
    {
        var opts = Options_(ownerClaim: "owner_user_id");
        var (mw, data, sink) = Build(opts, Provider(), Identity());
        var ctx = Context(new[]
        {
            new Claim("sub", "subject-1"),
            new Claim("user_type", "agent"),          // agent, but NO owner_user_id
            new Claim("agent_profile_id", "agent-9")
        });
        BufferBody(ctx);
        Wire(ctx, data, sink);

        await mw.InvokeAsync(ctx);

        ctx.Response.StatusCode.Should().Be(403);
        var body = await ReadBody(ctx);
        body.Should().Contain("AGENT_OWNER_MISSING");
    }

    // ── R15 (NightHawk 65081): recognition is VALUE-matched, not presence-only. A service token carrying
    // user_type=service must NOT be an agent; an agent token with no agent_profile_id IS still an agent. ──

    [Fact]
    public async Task R15_service_token_is_not_an_agent()
    {
        var opts = Options_();
        var (mw, data, sink) = Build(opts, Provider(), Identity());
        var ctx = Context(new[]
        {
            new Claim("sub", "subject-1"),
            new Claim("user_type", "service")         // NOT the agent claim VALUE
        }, path: "/v1/query");
        BufferBody(ctx);
        Wire(ctx, data, sink);

        await mw.InvokeAsync(ctx);

        var caller = ctx.Items["EdgeCaller"] as ResolvedCaller;
        caller.Should().NotBeNull();
        caller!.CallerType.Should().Be(CallerType.User, "user_type=service is not the agent claim VALUE");
    }

    [Fact]
    public async Task R15_agent_without_profile_id_is_still_an_agent()
    {
        var opts = Options_();
        var (mw, data, sink) = Build(opts, Provider(), Identity());
        var ctx = Context(new[]
        {
            new Claim("sub", "subject-1"),
            new Claim("user_type", "agent"),
            new Claim("owner_user_id", "42")          // owner present, but NO agent_profile_id
        });
        BufferBody(ctx);
        Wire(ctx, data, sink);

        await mw.InvokeAsync(ctx);

        var caller = ctx.Items["EdgeCaller"] as ResolvedCaller;
        caller.Should().NotBeNull();
        caller!.CallerType.Should().Be(CallerType.Agent);
        caller.AgentId.Should().BeNull("the agent id is optional when AgentIdClaim is absent from the token");
        ctx.Response.StatusCode.Should().NotBe(403);
    }

    // Positive control: a well-formed agent token resolves as Agent with the owner as the caller user id.
    [Fact]
    public async Task Control_full_agent_token_resolves_as_Agent_with_owner()
    {
        var opts = Options_();
        var (mw, data, sink) = Build(opts, Provider(), Identity());
        var ctx = Context(new[]
        {
            new Claim("sub", "subject-1"),
            new Claim("user_type", "agent"),
            new Claim("owner_user_id", "42"),
            new Claim("agent_profile_id", "agent-9")
        });
        BufferBody(ctx);
        Wire(ctx, data, sink);

        await mw.InvokeAsync(ctx);

        var caller = ctx.Items["EdgeCaller"] as ResolvedCaller;
        caller.Should().NotBeNull();
        caller!.CallerType.Should().Be(CallerType.Agent);
        caller.UserId.Should().Be("42");
        caller.AgentId.Should().Be("agent-9");
        ctx.Response.StatusCode.Should().NotBe(403);
    }

    // ── R14 (NightHawk 65081): recognition ran ONLY when providerKey == the literal "KeelAuth", so an
    // agents-issuer provider added under any OTHER key resolved every agent as CallerType.User, and with
    // AllowAllSchemaGovernor DDL was then allowed. The fix keys on the CLAIM VALUE, for ANY provider. ─────

    [Fact]
    public async Task R14_agent_token_from_a_non_KeelAuth_provider_is_still_an_Agent()
    {
        const string agentsKey = "agents-issuer";
        var provider = new OidcProvider
        {
            ProviderKey = agentsKey,
            Issuer = "https://idp.payez.net/agents",
            Audience = "acp",
            IsActive = true,
            AutoProvision = false,
            IsFirstParty = true,
            SubjectClaimPath = "sub",
            RoleClaimPath = "roles",
            EmailClaimPath = "email"
        };
        var identity = new FederatedIdentity
        {
            ProviderKey = agentsKey, ExternalSubject = "agent-sub", VibeUserId = 7, IsActive = true
        };
        var opts = Options_();
        var (mw, data, sink) = Build(opts, provider, identity);
        var ctx = Context(new[]
        {
            new Claim("sub", "agent-sub"),
            new Claim("user_type", "agent"),
            new Claim("owner_user_id", "42"),
            new Claim("agent_profile_id", "agent-9")
        }, authType: "Edge_" + agentsKey);
        BufferBody(ctx);
        Wire(ctx, data, sink);

        await mw.InvokeAsync(ctx);

        var caller = ctx.Items["EdgeCaller"] as ResolvedCaller;
        caller.Should().NotBeNull();
        caller!.CallerType.Should().Be(CallerType.Agent,
            "R14: recognition must not be gated on the literal provider key 'KeelAuth'");
        caller.ProviderKey.Should().Be(agentsKey);
    }

    // ── MUST-2 (DotNetPert 65143/65151): agent recognition AND the owner claim are honoured ONLY from a
    // FIRST-PARTY provider. Otherwise a tenant-configured customer OIDC provider can mint {user_type:agent,
    // owner_user_id:<any KeelAuth user>} and Edge asserts that owner upstream (X-Keel-User). ─────────────

    [Fact]
    public async Task MUST2_customer_provider_agent_owner_is_refused()
    {
        const string customerKey = "customer-idp";
        var provider = new OidcProvider
        {
            ProviderKey = customerKey,
            Issuer = "https://customer.example.com",
            Audience = "acp",
            IsActive = true,
            AutoProvision = false,
            IsFirstParty = false,                       // a CUSTOMER provider
            SubjectClaimPath = "sub",
            RoleClaimPath = "roles",
            EmailClaimPath = "email"
        };
        var identity = new FederatedIdentity
        {
            ProviderKey = customerKey, ExternalSubject = "cust-sub", VibeUserId = 5, IsActive = true
        };
        var opts = Options_();
        var (mw, data, sink) = Build(opts, provider, identity);
        var ctx = Context(new[]
        {
            new Claim("sub", "cust-sub"),
            new Claim("user_type", "agent"),          // forged agent claim
            new Claim("owner_user_id", "22")          // forged owner (a KeelAuth user id)
        }, authType: "Edge_" + customerKey);
        BufferBody(ctx);
        Wire(ctx, data, sink);

        await mw.InvokeAsync(ctx);

        ctx.Response.StatusCode.Should().Be(403);
        var body = await ReadBody(ctx);
        body.Should().Contain("AGENT_PROVIDER_NOT_TRUSTED");
    }

    // MUST-2 control: the SAME token shape from a FIRST-PARTY provider resolves as Agent with the owner.
    [Fact]
    public async Task MUST2_control_first_party_provider_agent_is_trusted()
    {
        var opts = Options_();
        var (mw, data, sink) = Build(opts, Provider(firstParty: true), Identity());
        var ctx = Context(new[]
        {
            new Claim("sub", "subject-1"),
            new Claim("user_type", "agent"),
            new Claim("owner_user_id", "22")
        });
        BufferBody(ctx);
        Wire(ctx, data, sink);

        await mw.InvokeAsync(ctx);

        var caller = ctx.Items["EdgeCaller"] as ResolvedCaller;
        caller.Should().NotBeNull();
        caller!.CallerType.Should().Be(CallerType.Agent);
        caller.UserId.Should().Be("22");
        ctx.Response.StatusCode.Should().NotBe(403);
    }
}
