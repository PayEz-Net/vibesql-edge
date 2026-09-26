using FluentAssertions;
using KeelBase.Edge.Limits;
using KeelBase.Edge.Middleware;
using KeelBase.Edge.Tenancy;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace KeelBase.Edge.Tests;

/// <summary>
/// PAY-1853 F5: ApiCallsPerDay trips at N+1 -> 429, and the per-class counters (S3 wiring, EdgeStatementClass)
/// trip too. Uses the real InMemoryTierLimitStore, so the counting is genuine, not mocked.
/// </summary>
public class TierLimitMiddlewareTests
{
    private static readonly RequestDelegate Noop = _ => Task.CompletedTask;

    private static HttpContext Context(TierLimitOptions options, TenantRoute? route,
        string? statementClass, ITierLimitStore store)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Method = "POST";
        ctx.Request.Path = "/v1/query";
        ctx.Response.Body = new MemoryStream();
        if (route != null) ctx.Items["EdgeTenantRoute"] = route;
        if (statementClass != null) ctx.Items["EdgeStatementClass"] = statementClass;

        var sc = new ServiceCollection();
        sc.AddSingleton(store);
        sc.AddSingleton<IOptions<TierLimitOptions>>(Options.Create(options));
        ctx.RequestServices = sc.BuildServiceProvider();
        return ctx;
    }

    private static TierLimitMiddleware Middleware(RequestDelegate next)
        => new(next, NullLogger<TierLimitMiddleware>.Instance);

    private static TenantRoute Route(string id = "tenant-x")
        => new(id, true, StorageKind.SharedSchema);

    [Fact]
    public async Task F5_api_calls_trip_at_N_plus_1()
    {
        var options = new TierLimitOptions { ApiCallsPerDay = 3 };
        var store = new InMemoryTierLimitStore();
        var passed = 0;
        var next = new RequestDelegate(_ => { passed++; return Task.CompletedTask; });

        for (var i = 1; i <= 3; i++)
        {
            var ctx = Context(options, Route(), "read", store);
            await Middleware(next).InvokeAsync(ctx);
            ctx.Response.StatusCode.Should().NotBe(429, $"call {i} is within the limit");
        }

        var fourth = Context(options, Route(), "read", store);
        await Middleware(next).InvokeAsync(fourth);

        fourth.Response.StatusCode.Should().Be(429);
        passed.Should().Be(3, "the 4th call must not reach the next middleware");
        fourth.Response.Body.Position = 0;
        (await new StreamReader(fourth.Response.Body).ReadToEndAsync()).Should().Contain("TIER_LIMIT_REACHED");
    }

    [Fact]
    public async Task F5_schema_ops_trip_using_EdgeStatementClass()
    {
        var options = new TierLimitOptions { SchemaOpsPerDay = 2, ApiCallsPerDay = 1000 };
        var store = new InMemoryTierLimitStore();
        var next = Noop;

        for (var i = 1; i <= 2; i++)
        {
            var ctx = Context(options, Route(), "ddl", store);
            await Middleware(next).InvokeAsync(ctx);
            ctx.Response.StatusCode.Should().NotBe(429);
        }

        var third = Context(options, Route(), "ddl", store);
        await Middleware(next).InvokeAsync(third);
        third.Response.StatusCode.Should().Be(429,
            "S3: the per-class SchemaOps counter must trip once EdgeStatementClass is set");
    }

    [Fact]
    public async Task F5_control_different_tenants_have_separate_buckets()
    {
        var options = new TierLimitOptions { ApiCallsPerDay = 1 };
        var store = new InMemoryTierLimitStore();

        var a = Context(options, Route("tenant-a"), "read", store);
        await Middleware(Noop).InvokeAsync(a);
        var b = Context(options, Route("tenant-b"), "read", store);
        await Middleware(Noop).InvokeAsync(b);

        a.Response.StatusCode.Should().NotBe(429);
        b.Response.StatusCode.Should().NotBe(429, "tenant-b has its own bucket");
    }

    [Fact]
    public async Task F5_control_no_tenant_route_is_not_counted()
    {
        var options = new TierLimitOptions { ApiCallsPerDay = 0 };
        var store = new InMemoryTierLimitStore();
        var ctx = Context(options, route: null, statementClass: "read", store);

        await Middleware(Noop).InvokeAsync(ctx);

        ctx.Response.StatusCode.Should().NotBe(429, "a request with no resolved tenant route is not tiered here");
    }
}
