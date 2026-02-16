using System.Text.Json;
using Vibe.Edge.Models;
using Vibe.Edge.Security;

namespace Vibe.Edge.Authorization;

public class PermissionEnforcementMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<PermissionEnforcementMiddleware> _logger;
    private readonly ISecurityEventSink _eventSink;

    private static readonly PermissionLevel SentinelMultiStatement = (PermissionLevel)(-1);
    private static readonly PermissionLevel SentinelUnrecognized = (PermissionLevel)(-2);

    public PermissionEnforcementMiddleware(RequestDelegate next, ILogger<PermissionEnforcementMiddleware> logger, ISecurityEventSink eventSink)
    {
        _next = next;
        _logger = logger;
        _eventSink = eventSink;
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
            await _next(context);
            return;
        }

        var providerKey = context.Items["EdgeProviderKey"] as string;
        var roles = context.Items["EdgeRoles"] as List<string> ?? [];

        if (string.IsNullOrEmpty(providerKey))
        {
            await _next(context);
            return;
        }

        var resolver = context.RequestServices.GetRequiredService<PermissionResolver>();
        var permResult = await resolver.ResolveWithCapAsync(providerKey, roles);

        var requiredLevel = await ClassifyOperationAsync(context);
        if (requiredLevel == null)
        {
            await _next(context);
            return;
        }

        if (requiredLevel == SentinelMultiStatement)
        {
            await EmitDeniedAsync(context, providerKey, permResult.EffectiveLevel, "multi_statement", EdgeDenyReasons.MultiStatementRejected);
            context.Response.StatusCode = 400;
            context.Response.ContentType = "application/json";
            var badReq = ApiResponse<object>.FailureResponse(
                "Multi-statement SQL batches are not allowed", "MULTI_STATEMENT_REJECTED",
                requestId: context.TraceIdentifier);
            await context.Response.WriteAsync(JsonSerializer.Serialize(badReq));
            return;
        }

        if (requiredLevel == SentinelUnrecognized)
        {
            await EmitDeniedAsync(context, providerKey, permResult.EffectiveLevel, "unrecognized", EdgeDenyReasons.UnrecognizedStatement);
            context.Response.StatusCode = 403;
            context.Response.ContentType = "application/json";
            var denied = ApiResponse<object>.FailureResponse(
                "Unrecognized SQL statement type — denied by default", "SQL_UNRECOGNIZED",
                requestId: context.TraceIdentifier);
            await context.Response.WriteAsync(JsonSerializer.Serialize(denied));
            return;
        }

        if (permResult.EffectiveLevel < requiredLevel.Value)
        {
            _logger.LogWarning(
                "EDGE_PERMISSION: Denied — user has {Actual}, needs {Required} for {Path}",
                permResult.EffectiveLevel, requiredLevel.Value, path);
            await EmitDeniedAsync(context, providerKey, permResult.EffectiveLevel, requiredLevel.Value.ToDbValue(), EdgeDenyReasons.PermissionInsufficient);
            context.Response.StatusCode = 403;
            context.Response.ContentType = "application/json";
            var resp = ApiResponse<object>.FailureResponse(
                "Insufficient permissions", "PERMISSION_DENIED",
                detail: $"Requires {requiredLevel.Value.ToDbValue()} permission",
                requestId: context.TraceIdentifier);
            await context.Response.WriteAsync(JsonSerializer.Serialize(resp));
            return;
        }

        var sqlKeyword = context.Items["EdgeSqlKeyword"] as string;
        if (sqlKeyword != null && permResult.DeniedStatements.Contains(sqlKeyword))
        {
            _logger.LogWarning(
                "EDGE_PERMISSION: Denied statement {Keyword} for provider {Provider}",
                sqlKeyword, providerKey);
            await EmitDeniedAsync(context, providerKey, permResult.EffectiveLevel, sqlKeyword, EdgeDenyReasons.DeniedStatement);
            context.Response.StatusCode = 403;
            context.Response.ContentType = "application/json";
            var resp = ApiResponse<object>.FailureResponse(
                "Statement type denied", "STATEMENT_DENIED",
                detail: $"{sqlKeyword} statements are denied by your role configuration",
                requestId: context.TraceIdentifier);
            await context.Response.WriteAsync(JsonSerializer.Serialize(resp));
            return;
        }

        context.Items["EdgePermission"] = permResult.EffectiveLevel;

        await _eventSink.EmitSafeAsync(new EdgeSecurityEvent
        {
            EventType = EdgeEventTypes.PermissionGranted,
            Provider = providerKey,
            VibeUserId = context.Items.TryGetValue("EdgeUserId", out var uid) && uid is int id ? id : null,
            PermissionLevel = permResult.EffectiveLevel.ToDbValue(),
            Operation = $"{context.Request.Method} {path}",
            Result = "allow",
            IpAddress = context.Connection.RemoteIpAddress?.ToString(),
            RequestPath = path,
            RequestMethod = context.Request.Method
        }, _logger);

        await _next(context);
    }

    private async Task EmitDeniedAsync(HttpContext context, string? providerKey, PermissionLevel effectiveLevel, string operation, string denyReason)
    {
        await _eventSink.EmitSafeAsync(new EdgeSecurityEvent
        {
            EventType = EdgeEventTypes.PermissionDenied,
            Provider = providerKey,
            VibeUserId = context.Items.TryGetValue("EdgeUserId", out var uid) && uid is int id ? id : null,
            PermissionLevel = effectiveLevel.ToDbValue(),
            Operation = operation,
            Result = "deny",
            DenyReason = denyReason,
            IpAddress = context.Connection.RemoteIpAddress?.ToString(),
            RequestPath = context.Request.Path.Value,
            RequestMethod = context.Request.Method
        }, _logger);
    }

    private async Task<PermissionLevel?> ClassifyOperationAsync(HttpContext context)
    {
        var path = context.Request.Path.Value ?? "";
        var method = context.Request.Method.ToUpperInvariant();

        if (method == "POST" && path.EndsWith("/query", StringComparison.OrdinalIgnoreCase))
        {
            return await ClassifySqlFromBodyAsync(context);
        }

        if (path.StartsWith("/v1/schemas", StringComparison.OrdinalIgnoreCase))
            return PermissionLevel.Schema;

        return method switch
        {
            "GET" => PermissionLevel.Read,
            "POST" => PermissionLevel.Write,
            "PUT" => PermissionLevel.Write,
            "PATCH" => PermissionLevel.Write,
            "DELETE" => PermissionLevel.Write,
            _ => null
        };
    }

    private async Task<PermissionLevel?> ClassifySqlFromBodyAsync(HttpContext context)
    {
        context.Request.EnableBuffering();

        using var reader = new StreamReader(context.Request.Body, leaveOpen: true);
        var body = await reader.ReadToEndAsync();
        context.Request.Body.Position = 0;

        if (string.IsNullOrWhiteSpace(body))
            return PermissionLevel.Read;

        string? sql = null;
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("sql", out var sqlProp))
                sql = sqlProp.GetString();
            else if (doc.RootElement.TryGetProperty("query", out var queryProp))
                sql = queryProp.GetString();
        }
        catch
        {
            sql = body;
        }

        if (string.IsNullOrWhiteSpace(sql))
            return PermissionLevel.Read;

        var (result, level, keyword) = SqlStatementClassifier.Classify(sql);
        context.Items["EdgeSqlKeyword"] = keyword;

        return result switch
        {
            SqlStatementClassifier.ClassifyResult.Ok => level,
            SqlStatementClassifier.ClassifyResult.MultiStatement => SentinelMultiStatement,
            SqlStatementClassifier.ClassifyResult.Unrecognized => SentinelUnrecognized,
            _ => SentinelUnrecognized
        };
    }
}
