using System.Text.Json;

using KeelBase.Edge.Data;
using KeelBase.Edge.Models;
using System.Security.Cryptography;
using KeelBase.Edge.Data.Models;
using KeelBase.Edge.Authentication;
using KeelBase.Edge.Security;
using KeelBase.Edge.Tenancy;
using Microsoft.Extensions.Options;

namespace KeelBase.Edge.Identity;

public class IdentityResolutionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<IdentityResolutionMiddleware> _logger;
    private readonly ISecurityEventSink _eventSink;
    private readonly ITenantRouter _tenantRouter;
    private readonly KeelAuthOptions _keelAuth;

    public IdentityResolutionMiddleware(RequestDelegate next, ILogger<IdentityResolutionMiddleware> logger, ISecurityEventSink eventSink, ITenantRouter tenantRouter, IOptions<KeelAuthOptions> keelAuth)
    {
        _next = next;
        _logger = logger;
        _eventSink = eventSink;
        _tenantRouter = tenantRouter;
        _keelAuth = keelAuth.Value;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path.Value ?? "";
        if (path.StartsWith("/v1/admin/", StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith("/health", StringComparison.OrdinalIgnoreCase))
        {
            await _next(context);
            return;
        }

        if (context.User.Identity?.IsAuthenticated != true)
        {
            var pubKey = context.Request.Headers["X-Keel-Publishable-Key"].FirstOrDefault();
            if (!string.IsNullOrEmpty(pubKey))
            {
                await HandlePublishableKeyAsync(context, pubKey);
                return;
            }
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

        var dataService = context.RequestServices.GetRequiredService<IKeelBaseDataService>();
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

                if (!string.IsNullOrEmpty(provider.ProvisionDefaultRole))
                {
                    var existingMapping = (await dataService.GetRoleMappingsByRolesAsync(
                        providerKey, new[] { provider.ProvisionDefaultRole })).FirstOrDefault();
                    if (existingMapping != null)
                    {
                        roles = new List<string> { provider.ProvisionDefaultRole };
                    }
                }
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

        var callerType = CallerType.User;
        string? callerUserId = identity.VibeUserId.ToString();
        string? agentId = null;

        // R14 (NightHawk 65081): agent recognition was gated on the LITERAL provider key "KeelAuth", so an
        // agents-issuer provider added under any other key resolved every agent as CallerType.User, and
        // with AllowAllSchemaGovernor DDL was then allowed. R15: recognition was presence-only, so a service
        // token carrying user_type also matched. Recognise on the CLAIM VALUE, for ANY provider.
        if (!string.IsNullOrEmpty(_keelAuth.AgentClaim))
        {
            var agentClaimValue = ClaimExtractor.ExtractClaim(context.User, _keelAuth.AgentClaim);
            var isAgent = !string.IsNullOrEmpty(agentClaimValue) &&
                          string.Equals(agentClaimValue, _keelAuth.AgentClaimValue, StringComparison.OrdinalIgnoreCase);

            if (isAgent)
            {
                callerType = CallerType.Agent;
                // R15: an agent token with NO agent_profile_id is still an Agent - the id is optional.
                agentId = string.IsNullOrEmpty(_keelAuth.AgentIdClaim)
                    ? null
                    : ClaimExtractor.ExtractClaim(context.User, _keelAuth.AgentIdClaim);
                callerUserId = string.IsNullOrEmpty(_keelAuth.AgentOwnerClaim)
                    ? null
                    : ClaimExtractor.ExtractClaim(context.User, _keelAuth.AgentOwnerClaim);

                // S7 (NightHawk 65081): an agent token with no owner claim used to log a warning and proceed
                // with no X-Keel-User. Deny instead - an ownerless agent has no identity upstream can trust.
                if (string.IsNullOrEmpty(_keelAuth.AgentOwnerClaim) || string.IsNullOrEmpty(callerUserId))
                {
                    _logger.LogWarning(
                        "EDGE_IDENTITY: Agent token for provider {Provider} has no owner claim {OwnerClaim} - denied (S7)",
                        providerKey, _keelAuth.AgentOwnerClaim);
                    await _eventSink.EmitSafeAsync(new EdgeSecurityEvent
                    {
                        EventType = EdgeEventTypes.AuthFailure,
                        Provider = providerKey,
                        ExternalSubject = subject,
                        Result = "deny",
                        DenyReason = EdgeDenyReasons.AgentOwnerMissing,
                        IpAddress = context.Connection.RemoteIpAddress?.ToString(),
                        RequestPath = context.Request.Path.Value,
                        RequestMethod = context.Request.Method
                    }, _logger);
                    context.Response.StatusCode = 403;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(JsonSerializer.Serialize(
                        ApiResponse<object>.FailureResponse(
                            "Agent token has no owning user", "AGENT_OWNER_MISSING",
                            requestId: context.TraceIdentifier)));
                    return;
                }
            }
        }

        // Build ResolvedCaller and store in context
        var resolvedCaller = new ResolvedCaller(
            callerType,
            providerKey,
            subject,
            callerUserId,
            agentId,
            null,
            PermissionLevel.None,
            roles);
        context.Items["EdgeCaller"] = resolvedCaller;

        var route = await _tenantRouter.ResolveAsync(providerKey, context.RequestAborted);
        if (!route.IsActive)
        {
            _logger.LogWarning("EDGE_IDENTITY: Tenant {TenantClientId} is inactive", providerKey);
            context.Response.StatusCode = 403;
            context.Response.ContentType = "application/json";
            var tenantResponse = ApiResponse<object>.FailureResponse(
                "This app (tenant) is not active yet. An admin must activate it.",
                "TENANT_INACTIVE",
                requestId: context.TraceIdentifier);
            await context.Response.WriteAsync(JsonSerializer.Serialize(tenantResponse));
            return;
        }
        context.Items["EdgeTenantRoute"] = route;

        await _next(context);
    }

    private async Task HandlePublishableKeyAsync(HttpContext context, string pubKey)
    {
        if (!pubKey.StartsWith("kb_pub_") || pubKey.Length < 15)
        {
            context.Response.StatusCode = 401;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(System.Text.Json.JsonSerializer.Serialize(
                ApiResponse<object>.FailureResponse("Invalid publishable key.", "PUBLISHABLE_KEY_INVALID", requestId: context.TraceIdentifier)));
            return;
        }

        var random32 = pubKey["kb_pub_".Length..];
        var keyPrefix = random32.Length >= 8 ? random32[..8] : random32;

        var dataService = context.RequestServices.GetRequiredService<IKeelBaseDataService>();
        var record = await dataService.GetPublishableKeyByPrefixAsync(keyPrefix);

        if (record == null)
        {
            context.Response.StatusCode = 401;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(System.Text.Json.JsonSerializer.Serialize(
                ApiResponse<object>.FailureResponse("Unknown or revoked publishable key.", "PUBLISHABLE_KEY_INVALID", requestId: context.TraceIdentifier)));
            return;
        }

        var hash = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(pubKey))).ToLowerInvariant();
        if (hash != record.KeyHash)
        {
            context.Response.StatusCode = 401;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(System.Text.Json.JsonSerializer.Serialize(
                ApiResponse<object>.FailureResponse("Unknown or revoked publishable key.", "PUBLISHABLE_KEY_INVALID", requestId: context.TraceIdentifier)));
            return;
        }

        var caller = new ResolvedCaller(
            CallerType.Anonymous,
            null, null, null, null,
            record.TenantClientId,
            PermissionLevel.None,
            Array.Empty<string>());

        context.Items["EdgeCaller"] = caller;
        context.Items["EdgeProviderKey"] = record.TenantClientId;

        var tenantRouter = context.RequestServices.GetRequiredService<KeelBase.Edge.Tenancy.ITenantRouter>();
        var route = await tenantRouter.ResolveAsync(record.TenantClientId, context.RequestAborted);
        if (!route.IsActive)
        {
            context.Response.StatusCode = 403;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(System.Text.Json.JsonSerializer.Serialize(
                ApiResponse<object>.FailureResponse("This app (tenant) is not active yet.", "TENANT_INACTIVE", requestId: context.TraceIdentifier)));
            return;
        }
        context.Items["EdgeTenantRoute"] = route;

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
