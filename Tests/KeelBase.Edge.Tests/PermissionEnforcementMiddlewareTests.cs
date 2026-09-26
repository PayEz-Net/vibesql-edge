using System.Security.Claims;
using FluentAssertions;
using KeelBase.Edge.Authorization;
using KeelBase.Edge.Data;
using KeelBase.Edge.Data.Models;
using KeelBase.Edge.Governance;
using KeelBase.Edge.Identity;
using KeelBase.Edge.Middleware;
using KeelBase.Edge.Models;
using KeelBase.Edge.Security;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;

namespace KeelBase.Edge.Tests;

/// <summary>
/// PAY-1853 R2/R3/R4 (M2 body), R6 (M4 DDL set), R7 (M5 trailing slash), R8 (S1 verbs) - through
/// PermissionEnforcementMiddleware on the IKeelBaseDataService seam (ba5f11e). No Postgres.
///
/// Each test seeds a real PermissionResolver over a mocked data service, and sets the same context Items
/// IdentityResolutionMiddleware would set (EdgeProviderKey, EdgeRoles, EdgeCaller).
/// </summary>
public class PermissionEnforcementMiddlewareTests
{
    private const string Provider = "KeelAuth";

    private static (PermissionResolver resolver, Mock<IKeelBaseDataService> data) Resolver(
        string vibePermission, string[]? denied = null)
    {
        var data = new Mock<IKeelBaseDataService>();
        data.Setup(d => d.GetRoleMappingsByRolesAsync(Provider, It.IsAny<IEnumerable<string>>()))
            .ReturnsAsync(new[]
            {
                new OidcProviderRoleMapping
                {
                    ProviderKey = Provider, ExternalRole = "r", VibePermission = vibePermission,
                    DeniedStatements = denied
                }
            });
        // no active client mapping -> no cap
        data.Setup(d => d.GetActiveClientMappingAsync(Provider))
            .ReturnsAsync((OidcProviderClientMapping?)null);
        return (new PermissionResolver(data.Object, NullLogger<PermissionResolver>.Instance), data);
    }

    private static PermissionEnforcementMiddleware Middleware(Mock<ISecurityEventSink> sink)
        => new(_ => Task.CompletedTask, NullLogger<PermissionEnforcementMiddleware>.Instance, sink.Object);

    private static HttpContext Context(string method, string path, string? body, CallerType callerType)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Method = method;
        ctx.Request.Path = path;
        if (body is not null)
        {
            ctx.Request.Body = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(body));
            ctx.Request.ContentType = "application/json";
        }
        ctx.User = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("sub", "s") }, "Edge_" + Provider));
        ctx.Items["EdgeProviderKey"] = Provider;
        ctx.Items["EdgeRoles"] = new List<string> { "r" };
        ctx.Items["EdgeCaller"] = new ResolvedCaller(
            callerType, Provider, "s", "42", callerType == CallerType.Agent ? "a1" : null,
            null, PermissionLevel.Read, new List<string> { "r" });
        ctx.Response.Body = new MemoryStream();
        return ctx;
    }

    private static void Wire(HttpContext ctx, PermissionResolver resolver)
    {
        var services = new Mock<IServiceProvider>();
        services.Setup(s => s.GetService(typeof(PermissionResolver))).Returns(resolver);
        services.Setup(s => s.GetService(typeof(ISchemaGovernor))).Returns(new AllowAllSchemaGovernor());
        ctx.RequestServices = services.Object;
    }

    private static async Task<string> Body(HttpContext ctx)
    {
        ctx.Response.Body.Position = 0;
        return await new StreamReader(ctx.Response.Body).ReadToEndAsync();
    }

    // ── R2 (M2): a case-variant "Sql" key must not be read as null and skipped to Read ─────────────────
    [Fact]
    public async Task R2_casevariant_Sql_key_still_classifies_and_denies_agent_ddl()
    {
        // Agent with an admin-mapped role, body {"Sql":"DROP TABLE t"} (capital S).
        var (resolver, _) = Resolver("admin");
        var sink = new Mock<ISecurityEventSink>();
        var ctx = Context("POST", "/v1/query", "{\"Sql\":\"DROP TABLE t\"}", CallerType.Agent);
        ctx.Items["EdgeRoles"] = new List<string> { "r" };
        Wire(ctx, resolver);

        await Middleware(sink).InvokeAsync(ctx);

        ctx.Response.StatusCode.Should().Be(403, "M2: the Sql key must be matched case-insensitively");
        var body = await Body(ctx);
        body.Should().Contain("DDL_NOT_GRANTED_TO_AGENT");
    }

    // ── R3 (M2): duplicate sql/Sql keys -> SQL_MALFORMED, not a leading-keyword pass ──────────────────
    [Fact]
    public async Task R3_duplicate_sql_keys_are_malformed()
    {
        var (resolver, _) = Resolver("admin");
        var sink = new Mock<ISecurityEventSink>();
        var ctx = Context("POST", "/v1/query", "{\"sql\":\"SELECT 1\",\"Sql\":\"DROP TABLE t\"}", CallerType.User);
        Wire(ctx, resolver);

        await Middleware(sink).InvokeAsync(ctx);

        ctx.Response.StatusCode.Should().Be(403);
        (await Body(ctx)).Should().Contain("SQL_MALFORMED");
    }

    // ── R4 (M2): an empty or {} body -> SQL_MALFORMED (was Read) ──────────────────────────────────────
    [Theory]
    [InlineData("")]
    [InlineData("{}")]
    [InlineData("{\"not_sql\":1}")]
    public async Task R4_empty_or_non_sql_body_is_malformed(string body)
    {
        var (resolver, _) = Resolver("read");
        var sink = new Mock<ISecurityEventSink>();
        var ctx = Context("POST", "/v1/query", body, CallerType.User);
        Wire(ctx, resolver);

        await Middleware(sink).InvokeAsync(ctx);

        ctx.Response.StatusCode.Should().Be(403);
        (await Body(ctx)).Should().Contain("SQL_MALFORMED");
    }

    // ── R6 (M4): TRUNCATE/DROP SCHEMA (Admin) hit the agent DDL refusal, not just Schema ──────────────
    [Theory]
    [InlineData("TRUNCATE TABLE t")]
    [InlineData("DROP SCHEMA s")]
    [InlineData("GRANT SELECT ON t TO r")]
    public async Task R6_agent_admin_ddl_is_refused(string sql)
    {
        var (resolver, _) = Resolver("admin");
        var sink = new Mock<ISecurityEventSink>();
        var ctx = Context("POST", "/v1/query", "{\"sql\":\"" + sql + "\"}", CallerType.Agent);
        Wire(ctx, resolver);

        await Middleware(sink).InvokeAsync(ctx);

        ctx.Response.StatusCode.Should().Be(403);
        (await Body(ctx)).Should().Contain("DDL_NOT_GRANTED_TO_AGENT");
    }

    // ── R7 (M5): a trailing slash on /v1/query/ must still classify the SQL ───────────────────────────
    [Fact]
    public async Task R7_trailing_slash_query_still_classifies()
    {
        var (resolver, _) = Resolver("admin");
        var sink = new Mock<ISecurityEventSink>();
        var ctx = Context("POST", "/v1/query/", "{\"sql\":\"DROP TABLE t\"}", CallerType.Agent);
        Wire(ctx, resolver);

        await Middleware(sink).InvokeAsync(ctx);

        ctx.Response.StatusCode.Should().Be(403);
        (await Body(ctx)).Should().Contain("DDL_NOT_GRANTED_TO_AGENT");
    }

    // ── R8 (S1): HEAD/OPTIONS must be denied, never proxied ───────────────────────────────────────────
    [Theory]
    [InlineData("HEAD")]
    [InlineData("OPTIONS")]
    public async Task R8_unclassifiable_verbs_are_denied(string method)
    {
        var (resolver, _) = Resolver("read");
        var sink = new Mock<ISecurityEventSink>();
        var ctx = Context(method, "/v1/anything", null, CallerType.User);
        Wire(ctx, resolver);

        await Middleware(sink).InvokeAsync(ctx);

        ctx.Response.StatusCode.Should().Be(403, "S1: an unclassifiable verb must deny, not forward");
    }

    // ── Positive control: a plain read by a user passes the gate ──────────────────────────────────────
    [Fact]
    public async Task Control_user_read_is_allowed_through()
    {
        var (resolver, _) = Resolver("read");
        var sink = new Mock<ISecurityEventSink>();
        var ctx = Context("POST", "/v1/query", "{\"sql\":\"SELECT 1\"}", CallerType.User);
        Wire(ctx, resolver);

        await Middleware(sink).InvokeAsync(ctx);

        ctx.Response.StatusCode.Should().NotBe(403);
        ctx.Items["EdgePermission"].Should().Be(KeelBase.Edge.Models.PermissionLevel.Read);
    }
}
