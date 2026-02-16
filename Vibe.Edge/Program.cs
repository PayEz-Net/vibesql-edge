using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Serilog;
using Vibe.Edge.Authentication;
using Vibe.Edge.Authorization;
using Vibe.Edge.Credentials;
using Vibe.Edge.Data;
using Vibe.Edge.Identity;
using Vibe.Edge.Middleware;
using Vibe.Edge.Security;

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

builder.Services.AddSingleton<VibeDataService>();
builder.Services.AddSingleton<MultiProviderSelector>();
builder.Services.AddSingleton<DynamicSchemeRegistrar>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<DynamicSchemeRegistrar>());

builder.Services.AddScoped<FederatedIdentityResolver>();
builder.Services.AddScoped<PermissionResolver>();

builder.Services.AddSingleton<IClientCredentialProvider, DefaultClientCredentialProvider>();
builder.Services.AddSingleton<ISecurityEventSink, ConsoleSecurityEventSink>();

builder.Services.AddHttpClient("PublicApi", (sp, client) =>
{
    var config = sp.GetRequiredService<IConfiguration>();
    var baseUrl = config["VibeEdge:PublicApiUrl"] ?? "http://localhost:5000";
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
    options.Events = new JwtBearerEvents
    {
        OnMessageReceived = context =>
        {
            context.NoResult();
            return Task.CompletedTask;
        }
    };
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
        Title = "Vibe.Edge API",
        Version = "v1",
        Description = "Pluggable Token Auth Harness for VibeSQL"
    });
});

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var dataService = scope.ServiceProvider.GetRequiredService<VibeDataService>();
    await dataService.InitializeSchemaAsync();
}

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseRouting();
app.UseAuthentication();
app.UseMiddleware<IdentityResolutionMiddleware>();
app.UseMiddleware<PermissionEnforcementMiddleware>();
app.UseMiddleware<AuditMiddleware>();
app.UseAuthorization();
app.MapControllers();

app.Run();
