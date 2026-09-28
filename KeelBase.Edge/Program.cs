using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.RateLimiting;
using Serilog;
using KeelBase.Edge.Authentication;
using KeelBase.Edge.Tenancy;
using KeelBase.Edge.Credentials;
using KeelBase.Edge.Data;
using KeelBase.Edge.Identity;
using KeelBase.Edge.Authorization;
using KeelBase.Edge.Tenancy.Implementations;
using KeelBase.Edge.Middleware;
using KeelBase.Edge.Security;
using KeelBase.Edge.Governance;
using KeelBase.Edge.Limits;
using Microsoft.Extensions.Options;

Dapper.DefaultTypeMap.MatchNamesWithUnderscores = true;

var builder = WebApplication.CreateBuilder(args);

builder.Host.UseSerilog((context, config) =>
{
    config
        .ReadFrom.Configuration(context.Configuration)
        .Enrich.FromLogContext()
        .Enrich.WithMachineName()
        .Enrich.WithThreadId()
        .WriteTo.Console();
});

builder.Services.AddSingleton<KeelBaseDataService>();
// PAY-1852 test seam (BAPert 65136): the same singleton is the IKeelBaseDataService implementation,
// so middleware/controllers depend on the interface and KeelBase.Edge.Tests can substitute a mock.
builder.Services.AddSingleton<IKeelBaseDataService>(sp => sp.GetRequiredService<KeelBaseDataService>());
builder.Services.AddSingleton<MultiProviderSelector>();
builder.Services.AddSingleton<DynamicSchemeRegistrar>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<DynamicSchemeRegistrar>());

builder.Services.AddSingleton<FederatedIdentityResolver>();
builder.Services.AddSingleton<PermissionResolver>();

builder.Services.AddSingleton<IClientCredentialProvider, DefaultClientCredentialProvider>();
builder.Services.AddSingleton<ITenantRouter, SharedSchemaTenantRouter>();
builder.Services.AddSingleton<ISecurityEventSink, ConsoleSecurityEventSink>();
builder.Services.AddSingleton<ITierLimitStore, InMemoryTierLimitStore>();
builder.Services.Configure<TierLimitOptions>(builder.Configuration.GetSection("KeelEdge:TierLimits"));
builder.Services.Configure<KeelAuthOptions>(builder.Configuration.GetSection(KeelAuthOptions.SectionName));
builder.Services.AddSingleton<ISchemaGovernor, AllowAllSchemaGovernor>();

builder.Services.AddHttpClient("PublicApi", (sp, client) =>
{
    var config = sp.GetRequiredService<IConfiguration>();
    var baseUrl = config["KeelBase:PublicApiUrl"] ?? "http://localhost:5000";
    client.BaseAddress = new Uri(baseUrl);
    client.Timeout = TimeSpan.FromMinutes(5);
});
builder.Services.AddHttpClient();

builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = "MultiProvider";
    options.DefaultChallengeScheme = "MultiProvider";
})
.AddPolicyScheme("MultiProvider", "Multi-Provider Selector", options =>
{
    options.ForwardDefaultSelector = context =>
    {
        var selector = context.RequestServices.GetRequiredService<MultiProviderSelector>();
        return selector.SelectScheme(context);
    };
})
.AddJwtBearer("FallbackReject", options =>
{
    // Swept for BAPert 65328 item 3 (the duplicate-pattern miss). This is the only OTHER JwtBearer
    // registration in KeelBase.Edge besides the dynamic schemes. MapInboundClaims is deliberately NOT
    // set here: this scheme never produces a principal - OnMessageReceived calls NoResult() so it always
    // fails with no result - so JwtBearer's MapInboundClaims default cannot rename a claim that is never
    // built and no ClaimExtractor path reads it. The dynamic schemes, which DO authenticate, set
    // MapInboundClaims=false in DynamicSchemeRegistrar.
    options.Events = new JwtBearerEvents
    {
        OnMessageReceived = context =>
        {
            context.NoResult();
            return Task.CompletedTask;
        }
    };
});

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = 429;

    options.AddPolicy("proxy", context =>
    {
        var providerKey = context.Items["EdgeProviderKey"] as string ?? context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        return RateLimitPartition.GetSlidingWindowLimiter(providerKey, _ => new SlidingWindowRateLimiterOptions
        {
            PermitLimit = 200,
            Window = TimeSpan.FromMinutes(1),
            SegmentsPerWindow = 4,
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
            QueueLimit = 0
        });
    });

    options.AddPolicy("admin", context =>
    {
        var ip = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        return RateLimitPartition.GetFixedWindowLimiter(ip, _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 30,
            Window = TimeSpan.FromMinutes(1),
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
            QueueLimit = 0
        });
    });

    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
    {
        var ip = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        return RateLimitPartition.GetFixedWindowLimiter(ip, _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 500,
            Window = TimeSpan.FromMinutes(1),
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
            QueueLimit = 0
        });
    });
});

builder.Services.AddControllers()
    .AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.PropertyNamingPolicy =
            System.Text.Json.JsonNamingPolicy.SnakeCaseLower;
        options.JsonSerializerOptions.DefaultIgnoreCondition =
            System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull;
    });

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new Microsoft.OpenApi.Models.OpenApiInfo
    {
        Title = "KeelBase.Edge API",
        Version = "v1",
        Description = "Pluggable Token Auth Harness for KeelBaseSQL"
    });
});

builder.Services.AddHealthChecks().AddCheck("edgedb", new KeelBase.Edge.Health.EdgeDbHealthCheck(builder.Configuration.GetConnectionString("EdgeDb") ?? string.Empty));

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var dataService = scope.ServiceProvider.GetRequiredService<KeelBaseDataService>();
    await dataService.InitializeSchemaAsync();
}

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseRouting();
app.UseRateLimiter();
app.UseAuthentication();
app.UseMiddleware<IdentityResolutionMiddleware>();
app.UseMiddleware<PermissionEnforcementMiddleware>();
app.UseMiddleware<TierLimitMiddleware>();
app.UseMiddleware<AuditMiddleware>();
app.UseAuthorization();
app.MapHealthChecks("/health/live", new Microsoft.AspNetCore.Diagnostics.HealthChecks.HealthCheckOptions
{
    Predicate = _ => false,
    ResponseWriter = static (context, _) =>
    {
        context.Response.ContentType = "application/json";
        return context.Response.WriteAsync("{\"status\":\"alive\"}");
    }
}).AllowAnonymous();

app.MapHealthChecks("/health/ready", new Microsoft.AspNetCore.Diagnostics.HealthChecks.HealthCheckOptions
{
    Predicate = _ => true,
    ResponseWriter = static (context, report) =>
    {
        context.Response.ContentType = "application/json";
        var payload = report.Status == Microsoft.Extensions.Diagnostics.HealthChecks.HealthStatus.Healthy
            ? "{\"status\":\"ready\"}"
            : "{\"status\":\"degraded\",\"reason\":\"db\"}";
        return context.Response.WriteAsync(payload);
    }
}).AllowAnonymous();

app.MapControllers();

app.Run();

// PAY-1852 test seam (BAPert 65136): WebApplicationFactory<Program> in KeelBase.Edge.Tests needs a
// public Program type. Top-level statements generate an internal one, so declare it explicitly.
public partial class Program { }
