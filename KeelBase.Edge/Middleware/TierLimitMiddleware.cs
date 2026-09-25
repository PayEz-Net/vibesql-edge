using System.Text.Json;
using KeelBase.Edge.Limits;
using KeelBase.Edge.Models;
using KeelBase.Edge.Tenancy;
using Microsoft.Extensions.Options;

namespace KeelBase.Edge.Middleware;

public class TierLimitMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<TierLimitMiddleware> _logger;

    public TierLimitMiddleware(RequestDelegate next, ILogger<TierLimitMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var store = context.RequestServices.GetRequiredService<ITierLimitStore>();
        var options = context.RequestServices.GetRequiredService<IOptions<TierLimitOptions>>().Value;
        var route = context.Items["EdgeTenantRoute"] as TenantRoute;
        if (route == null)
        {
            await _next(context);
            return;
        }

        var tenantId = route.TenantClientId;
        var statementClass = context.Items["EdgeStatementClass"] as string; // read/write/ddl/admin/unknown/null

        // Count API call
        var resetTime = DateTime.UtcNow.Date.AddDays(1).ToString("o");
        if (!await store.TryIncrementAsync(tenantId, "ApiCallsPerDay", options.ApiCallsPerDay, context.RequestAborted))
        {
            await WriteLimitExceeded(context, "ApiCallsPerDay", resetTime);
            return;
        }

        // Count by statement class
        string? limitName = statementClass switch
        {
            "read"  => "DocumentReadsPerDay",
            "write" => "DocumentWritesPerDay",
            "ddl"   => "SchemaOpsPerDay",
            _       => null
        };

        if (limitName != null)
        {
            var classLimit = limitName switch
            {
                "DocumentReadsPerDay"  => options.DocumentReadsPerDay,
                "DocumentWritesPerDay" => options.DocumentWritesPerDay,
                "SchemaOpsPerDay"      => options.SchemaOpsPerDay,
                _                      => long.MaxValue
            };
            if (!await store.TryIncrementAsync(tenantId, limitName, classLimit, context.RequestAborted))
            {
                await WriteLimitExceeded(context, limitName, resetTime);
                return;
            }
        }

        await _next(context);
    }

    private static async Task WriteLimitExceeded(HttpContext context, string limitName, string resetTime)
    {
        context.Response.StatusCode = 429;
        context.Response.ContentType = "application/json";
        var resp = ApiResponse<object>.FailureResponse(
            $"Tier limit reached: {limitName}. Resets at {resetTime}.",
            "TIER_LIMIT_REACHED",
            requestId: context.TraceIdentifier);
        await context.Response.WriteAsync(JsonSerializer.Serialize(resp));
    }
}
