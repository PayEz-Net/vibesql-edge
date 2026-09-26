using FluentAssertions;
using KeelBase.Edge.Identity;
using KeelBase.Edge.Models;
using KeelBase.Edge.Proxy;
using Microsoft.AspNetCore.Http;

namespace KeelBase.Edge.Tests;

/// <summary>
/// PAY-1853 R11 + F4: X-Keel-* header propagation. Client-supplied X-Keel-* must NEVER reach upstream
/// (NightHawk 65081 - verified in source; this pins it), and the authoritative values upstream sees are
/// the RESOLVED caller's, matching what the middleware established.
/// </summary>
public class ProxyRequestBuilderTests
{
    private static HttpRequest Request(params (string name, string value)[] headers)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Method = "POST";
        ctx.Request.Path = "/v1/query";
        foreach (var (name, value) in headers)
            ctx.Request.Headers[name] = value;
        return ctx.Request;
    }

    private static ResolvedCaller Caller(CallerType type, string? userId, string? agentId = null,
        string? tenant = null, string providerKey = "KeelAuth") => new(
        type, providerKey, "sub-1", userId, agentId, tenant, PermissionLevel.Read, new List<string>());

    // ── R11: a client cannot forge identity to the data server ────────────────────────────────────────
    [Fact]
    public void R11_client_sent_XKeel_headers_are_stripped_and_replaced()
    {
        var req = Request(
            ("X-Keel-User", "9999"),          // forged
            ("X-Keel-Tenant", "someone-else"), // forged
            ("X-Keel-Agent", "agent-forged"),  // forged
            ("Authorization", "Bearer forged.jwt.token"));
        var caller = Caller(CallerType.User, "42", tenant: "KeelAuth");

        var built = ProxyRequestBuilder.Build(req, "http://upstream/v1/query", "vibe_client",
            "1700000000", "sig", 42, "idp-proxy", caller: caller);

        built.Headers.GetValues("X-Keel-User").Should().ContainSingle().Which.Should().Be("42");
        built.Headers.GetValues("X-Keel-Tenant").Should().ContainSingle().Which.Should().Be("KeelAuth");
        built.Headers.Contains("X-Keel-Agent").Should().BeFalse("the resolved caller has no agent id");
        built.Headers.Contains("Authorization").Should().BeFalse("S6: Bearer must not be forwarded in HMAC mode");
    }

    [Fact]
    public void R11_forged_agent_header_does_not_survive()
    {
        var req = Request(("X-Keel-Agent", "agent-forged"));
        var caller = Caller(CallerType.User, "42");

        var built = ProxyRequestBuilder.Build(req, "http://upstream/v1/query", "c", "t", "s", 42, "via", caller: caller);

        built.Headers.Contains("X-Keel-Agent").Should().BeFalse("a user caller sets no agent header upstream");
    }

    // ── F4: upstream sees the RESOLVED caller's values, for a user and for an agent ───────────────────
    [Fact]
    public void F4_user_caller_sets_tenant_user_role_callertype()
    {
        var built = ProxyRequestBuilder.Build(Request(), "http://upstream/v1/query", "c", "t", "s", 42, "via",
            caller: Caller(CallerType.User, "42", tenant: "acme"));

        built.Headers.GetValues("X-Keel-Tenant").Single().Should().Be("acme");
        built.Headers.GetValues("X-Keel-User").Single().Should().Be("42");
        built.Headers.GetValues("X-Keel-Role").Single().Should().Be("authenticated");
        built.Headers.GetValues("X-Keel-Caller-Type").Single().Should().Be("user");
    }

    [Fact]
    public void F4_agent_caller_sets_agent_and_owner_user()
    {
        var built = ProxyRequestBuilder.Build(Request(), "http://upstream/v1/query", "c", "t", "s", 42, "via",
            caller: Caller(CallerType.Agent, "42", agentId: "agent-9", tenant: "KeelAuth"));

        built.Headers.GetValues("X-Keel-User").Single().Should().Be("42", "the OWNER is the caller user id");
        built.Headers.GetValues("X-Keel-Agent").Single().Should().Be("agent-9");
        built.Headers.GetValues("X-Keel-Caller-Type").Single().Should().Be("agent");
    }

    [Fact]
    public void F4_secret_mode_also_strips_client_XKeel_headers()
    {
        var req = Request(("X-Keel-User", "9999"));
        var built = ProxyRequestBuilder.BuildWithSecret(req, "http://upstream/v1/query", "container-secret",
            "c", 42, "via", caller: Caller(CallerType.User, "42", tenant: "acme"));

        built.Headers.GetValues("X-Keel-User").Single().Should().Be("42");
        built.Headers.Contains("X-Keel-User").Should().BeTrue();
    }
}
