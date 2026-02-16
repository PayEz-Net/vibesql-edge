using System.Text.Json;
using Vibe.Edge.Authentication;
using Vibe.Edge.Data;
using Vibe.Edge.Models;
using Vibe.Edge.Security;

namespace Vibe.Edge.Identity;

public class IdentityResolutionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<IdentityResolutionMiddleware> _logger;
    private readonly ISecurityEventSink _eventSink;

    public IdentityResolutionMiddleware(RequestDelegate next, ILogger<IdentityResolutionMiddleware> logger, ISecurityEventSink eventSink)
    {
        _next = next;
        _logger = logger;
        _eventSink = eventSink;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path.Value ?? "";
        if (path.StartsWith("/health", StringComparison.OrdinalIgnoreCase))
        {
            await _next(context);
            return;
        }

        if (context.User.Identity?.IsAuthenticated != true)
        {
            await _next(context);
            return;
        }

        var providerKey = ResolveProviderKey(context);
        if (string.IsNullOrEmpty(providerKey))
        {
            _logger.LogWarning("EDGE_IDENTITY: Could not resolve provider key from authenticated user");
            context.Response.StatusCode = 401;
            context.Response.ContentType = "application/json";
            var response = ApiResponse<object>.FailureResponse(
                "Could not resolve identity provider", "PROVIDER_UNKNOWN",
                requestId: context.TraceIdentifier);
            await context.Response.WriteAsync(JsonSerializer.Serialize(response));
            return;
        }

        context.Items["EdgeProviderKey"] = providerKey;

        var dataService = context.RequestServices.GetRequiredService<VibeDataService>();
        var resolver = context.RequestServices.GetRequiredService<FederatedIdentityResolver>();

        var provider = await dataService.GetProviderByKeyAsync(providerKey);
        if (provider == null)
        {
            context.Response.StatusCode = 401;
            context.Response.ContentType = "application/json";
            var response = ApiResponse<object>.FailureResponse(
                "Identity provider not found", "PROVIDER_NOT_FOUND",
                requestId: context.TraceIdentifier);
            await context.Response.WriteAsync(JsonSerializer.Serialize(response));
            return;
        }

        var subject = ClaimExtractor.ExtractClaim(context.User, provider.SubjectClaimPath);
        if (string.IsNullOrEmpty(subject))
        {
            _logger.LogWarning("EDGE_IDENTITY: Missing subject claim ({ClaimPath}) for provider {Provider}",
                provider.SubjectClaimPath, providerKey);
            context.Response.StatusCode = 401;
            context.Response.ContentType = "application/json";
            var response = ApiResponse<object>.FailureResponse(
                "Missing subject claim in token", "SUBJECT_MISSING",
                requestId: context.TraceIdentifier);
            await context.Response.WriteAsync(JsonSerializer.Serialize(response));
            return;
        }

        var roles = ClaimExtractor.ExtractRoles(context.User, provider.RoleClaimPath).ToList();
        var email = ClaimExtractor.ExtractClaim(context.User, provider.EmailClaimPath);

        var identity = await resolver.ResolveAsync(providerKey, subject);
        if (identity == null)
        {
            if (provider.AutoProvision)
            {
                identity = await resolver.ProvisionAsync(providerKey, subject, email, null);
            }
            else
            {
                _logger.LogWarning("EDGE_IDENTITY: Unknown subject {Subject} for provider {Provider}, auto-provision disabled",
                    subject, providerKey);
                await _eventSink.EmitSafeAsync(new EdgeSecurityEvent
                {
                    EventType = EdgeEventTypes.AuthFailure,
                    Provider = providerKey,
                    ExternalSubject = subject,
                    Result = "deny",
                    DenyReason = EdgeDenyReasons.IdentityNotFound,
                    IpAddress = context.Connection.RemoteIpAddress?.ToString(),
                    RequestPath = context.Request.Path.Value,
                    RequestMethod = context.Request.Method
                }, _logger);
                context.Response.StatusCode = 403;
                context.Response.ContentType = "application/json";
                var response = ApiResponse<object>.FailureResponse(
                    "Identity not provisioned", "IDENTITY_NOT_PROVISIONED",
                    detail: "Contact your administrator to provision access",
                    requestId: context.TraceIdentifier);
                await context.Response.WriteAsync(JsonSerializer.Serialize(response));
                return;
            }
        }

        context.Items["EdgeUserId"] = identity.VibeUserId;
        context.Items["EdgeRoles"] = roles;
        context.Items["EdgeEmail"] = email;

        await _next(context);
    }

    private static string? ResolveProviderKey(HttpContext context)
    {
        var scheme = context.User.Identity?.AuthenticationType;
        if (scheme != null && scheme.StartsWith("Edge_"))
        {
            return scheme["Edge_".Length..];
        }
        return null;
    }
}
