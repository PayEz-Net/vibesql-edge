using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Vibe.Edge.Authorization;
using Vibe.Edge.Data;
using Vibe.Edge.Models;

namespace Vibe.Edge.Admin;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public class RequireAdminPermissionAttribute : Attribute, IAsyncActionFilter
{
    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        var httpContext = context.HttpContext;
        var config = httpContext.RequestServices.GetRequiredService<IConfiguration>();
        var configuredKey = config["VibeEdge:AdminApiKey"];

        if (ValidateAdminApiKey(httpContext, configuredKey))
        {
            await next();
            return;
        }

        var env = httpContext.RequestServices.GetRequiredService<IWebHostEnvironment>();

        if (env.IsDevelopment() && string.IsNullOrEmpty(configuredKey))
        {
            await next();
            return;
        }

        if (!string.IsNullOrEmpty(configuredKey))
        {
            context.Result = new UnauthorizedObjectResult(ApiResponse<object>.FailureResponse(
                "Invalid or missing X-Edge-Admin-Key", "ADMIN_KEY_INVALID",
                requestId: httpContext.TraceIdentifier));
            return;
        }

        if (httpContext.User.Identity?.IsAuthenticated != true)
        {
            context.Result = new UnauthorizedObjectResult(ApiResponse<object>.FailureResponse(
                "Authentication required", "AUTH_REQUIRED",
                requestId: httpContext.TraceIdentifier));
            return;
        }

        var providerKey = httpContext.Items["EdgeProviderKey"] as string;
        var roles = httpContext.Items["EdgeRoles"] as List<string> ?? [];

        if (string.IsNullOrEmpty(providerKey))
        {
            context.Result = new ObjectResult(ApiResponse<object>.FailureResponse(
                "Provider not resolved", "PROVIDER_UNKNOWN",
                requestId: httpContext.TraceIdentifier))
            { StatusCode = 403 };
            return;
        }

        var resolver = httpContext.RequestServices.GetRequiredService<PermissionResolver>();
        var permResult = await resolver.ResolveWithCapAsync(providerKey, roles);

        if (permResult.EffectiveLevel < PermissionLevel.Admin)
        {
            context.Result = new ObjectResult(ApiResponse<object>.FailureResponse(
                "Admin permission required", "ADMIN_REQUIRED",
                detail: $"Your effective permission is '{permResult.EffectiveLevel.ToDbValue()}', admin required",
                requestId: httpContext.TraceIdentifier))
            { StatusCode = 403 };
            return;
        }

        await next();
    }

    private static bool ValidateAdminApiKey(HttpContext httpContext, string? configuredKey)
    {
        if (string.IsNullOrEmpty(configuredKey))
            return false;

        if (!httpContext.Request.Headers.TryGetValue("X-Edge-Admin-Key", out var headerValue))
            return false;

        var provided = headerValue.FirstOrDefault();
        if (string.IsNullOrEmpty(provided))
            return false;

        return CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.UTF8.GetBytes(configuredKey),
            System.Text.Encoding.UTF8.GetBytes(provided));
    }
}
