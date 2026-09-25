using System.Text.Json;
using KeelBase.Edge.Models;
using KeelBase.Edge.Governance;
using KeelBase.Edge.Identity;
using KeelBase.Edge.Security;

namespace KeelBase.Edge.Authorization;

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

        // Anonymous publishable-key callers are refused everything (checked before IsAuthenticated gate)
        var callerCheck = ResolvedCallerExtensions.From(context);
        if (callerCheck?.CallerType == CallerType.Anonymous)
        {
            await EmitDeniedAsync(context, context.Items["EdgeProviderKey"] as string, PermissionLevel.None, "ANON_NOT_ALLOWED", EdgeDenyReasons.AnonNotAllowed);
            context.Response.StatusCode = 403;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(System.Text.Json.JsonSerializer.Serialize(
                ApiResponse<object>.FailureResponse(
                    "Anonymous callers are not permitted to execute queries.",
                    "ANON_NOT_ALLOWED",
                    requestId: context.TraceIdentifier)));
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

        // DDL gate logic added per TS-04
        var caller = ResolvedCallerExtensions.From(context);
        if (caller == null)
        {
            // If we cannot resolve caller, fallback to existing logic (deny?)
            await _next(context);
            return;
        }

        // Determine if the statement is DDL based on requiredLevel mapping (Schema permission)
        bool isDdl = requiredLevel == PermissionLevel.Schema;
        if (isDdl)
        {
            // Agent not allowed DDL
            if (caller.CallerType == CallerType.Agent)
            {
                await EmitDeniedAsync(context, providerKey, permResult.EffectiveLevel, "DDL_NOT_GRANTED_TO_AGENT", EdgeDenyReasons.DdlNotGrantedToAgent);
                context.Response.StatusCode = 403;
                context.Response.ContentType = "application/json";
                var denied = ApiResponse<object>.FailureResponse(
                    "DDL not granted to agents", "DDL_NOT_GRANTED_TO_AGENT",
                    requestId: context.TraceIdentifier);
                await context.Response.WriteAsync(JsonSerializer.Serialize(denied));
                return;
            }
            // Non-user non-agent (e.g., Service, Anonymous) not allowed DDL
            if (caller.CallerType != CallerType.User)
            {
                await EmitDeniedAsync(context, providerKey, permResult.EffectiveLevel, "DDL_REQUIRES_USER", EdgeDenyReasons.DdlRequiresUser);
                context.Response.StatusCode = 403;
                context.Response.ContentType = "application/json";
                var denied = ApiResponse<object>.FailureResponse(
                    "DDL requires a signed‑in user", "DDL_REQUIRES_USER",
                    requestId: context.TraceIdentifier);
                await context.Response.WriteAsync(JsonSerializer.Serialize(denied));
                return;
            }
            // User caller – invoke governor
            var governor = context.RequestServices.GetRequiredService<ISchemaGovernor>();
            var decision = await governor.CheckDdlAsync(caller, ct: context.RequestAborted);
            if (!decision.Allowed)
            {
                await EmitDeniedAsync(context, providerKey, permResult.EffectiveLevel, "DDL_REFUSED_BY_GOVERNANCE", EdgeDenyReasons.DdlRefusedByGovernance);
                context.Response.StatusCode = 403;
                context.Response.ContentType = "application/json";
                var denied = ApiResponse<object>.FailureResponse(
                    decision.Reason ?? "DDL refused by governance", "DDL_REFUSED_BY_GOVERNANCE",
                    requestId: context.TraceIdentifier);
                await context.Response.WriteAsync(JsonSerializer.Serialize(denied));
                return;
            }
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
