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
    private static readonly PermissionLevel SentinelMalformed = (PermissionLevel)(-3);

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

        // S1: fail CLOSED. An authenticated caller with no resolvable provider key must not be proxied.
        if (string.IsNullOrEmpty(providerKey))
        {
            _logger.LogWarning("EDGE_PERMISSION: authenticated caller with no provider key - denied (S1)");
            await EmitDeniedAsync(context, providerKey, PermissionLevel.None, "provider_unknown", EdgeDenyReasons.ProviderUnknown);
            context.Response.StatusCode = 403;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(JsonSerializer.Serialize(
                ApiResponse<object>.FailureResponse("Could not resolve identity provider", "PROVIDER_UNKNOWN",
                    requestId: context.TraceIdentifier)));
            return;
        }

        var resolver = context.RequestServices.GetRequiredService<PermissionResolver>();
        var permResult = await resolver.ResolveWithCapAsync(providerKey, roles);

        var requiredLevel = await ClassifyOperationAsync(context);
        if (requiredLevel == null)
        {
            // S1: fail CLOSED. A verb/route we cannot classify (HEAD, OPTIONS, custom verbs, an
            // unknown path shape) must be denied, never forwarded unchecked.
            _logger.LogWarning("EDGE_PERMISSION: unclassifiable operation {Method} {Path} - denied (S1)",
                context.Request.Method, path);
            await EmitDeniedAsync(context, providerKey, permResult.EffectiveLevel, "unclassifiable", EdgeDenyReasons.OperationUnclassifiable);
            context.Response.StatusCode = 403;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(JsonSerializer.Serialize(
                ApiResponse<object>.FailureResponse(
                    "Request could not be classified and is denied by default", "OPERATION_NOT_CLASSIFIED",
                    requestId: context.TraceIdentifier)));
            return;
        }

        if (requiredLevel == SentinelMalformed)
        {
            await EmitDeniedAsync(context, providerKey, permResult.EffectiveLevel, "malformed", EdgeDenyReasons.MalformedSql);
            context.Response.StatusCode = 403;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(JsonSerializer.Serialize(
                ApiResponse<object>.FailureResponse(
                    "SQL query could not be read unambiguously", "SQL_MALFORMED",
                    requestId: context.TraceIdentifier)));
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

        // Statement class for the tier counter (S3): set once, read by TierLimitMiddleware. Without this
        // nothing sets EdgeStatementClass and the per-class limits never trip.
        context.Items["EdgeStatementClass"] = requiredLevel.Value switch
        {
            PermissionLevel.Read => "read",
            PermissionLevel.Write => "write",
            PermissionLevel.Schema => "ddl",
            PermissionLevel.Admin => "admin",
            _ => "unknown"
        };

        // DDL gate logic added per TS-04
        var caller = ResolvedCallerExtensions.From(context);
        if (caller == null)
        {
            // S1: fail CLOSED. If we cannot resolve the caller we must not forward.
            _logger.LogWarning("EDGE_PERMISSION: caller could not be resolved - denied (S1)");
            await EmitDeniedAsync(context, providerKey, permResult.EffectiveLevel, "caller_unresolved", EdgeDenyReasons.ProviderUnknown);
            context.Response.StatusCode = 403;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(JsonSerializer.Serialize(
                ApiResponse<object>.FailureResponse("Caller could not be resolved", "CALLER_UNRESOLVED",
                    requestId: context.TraceIdentifier)));
            return;
        }

        // Determine if the statement is DDL. M4 (NightHawk 65081): this was `== Schema`, so TRUNCATE,
        // GRANT, REVOKE, DROP SCHEMA and CREATE SCHEMA (all Admin) skipped the agent DDL refusal.
        bool isDdl = requiredLevel.Value >= PermissionLevel.Schema;
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

        // M5 (NightHawk 65081): normalise the path before matching. POST /v1/query/ (trailing slash)
        // used to fall through to the method map (POST = Write), so no SQL was classified and a
        // Write-level agent could send DROP TABLE.
        var normalised = path.Length > 1 ? path.TrimEnd('/') : path;
        if (normalised.Length == 0) normalised = "/";

        if (method == "POST" && normalised.EndsWith("/query", StringComparison.OrdinalIgnoreCase))
        {
            return await ClassifySqlFromBodyAsync(context);
        }

        if (normalised.StartsWith("/v1/schemas", StringComparison.OrdinalIgnoreCase))
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

        // M2 (NightHawk 65081): an empty body is MALFORMED, not Read. Previously it returned Read,
        // which let an unclassifiable request through as a read.
        if (string.IsNullOrWhiteSpace(body))
            return SentinelMalformed;

        string? sql = null;
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                return SentinelMalformed;

            // M2: match the field CASE-INSENSITIVELY (upstream binds Sql case-insensitively) and reject
            // the duplicate-key form {"sql":"SELECT 1","Sql":"DROP TABLE t"} rather than choosing one.
            var matches = 0;
            foreach (var prop in doc.RootElement.EnumerateObject())
            {
                if (prop.Name.Equals("sql", StringComparison.OrdinalIgnoreCase) ||
                    prop.Name.Equals("query", StringComparison.OrdinalIgnoreCase))
                {
                    matches++;
                    if (prop.Value.ValueKind == JsonValueKind.String && sql == null)
                        sql = prop.Value.GetString();
                    else if (prop.Value.ValueKind != JsonValueKind.String)
                        return SentinelMalformed;
                }
            }

            if (matches != 1)
                return SentinelMalformed;
        }
        catch
        {
            // A body that is not JSON at all: classify it as raw SQL text (upstream accepts text/plain).
            sql = body;
        }

        if (string.IsNullOrWhiteSpace(sql))
            return SentinelMalformed;

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
