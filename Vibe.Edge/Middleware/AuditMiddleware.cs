using System.Diagnostics;
using Vibe.Edge.Models;
using Vibe.Edge.Security;

namespace Vibe.Edge.Middleware;

public class AuditMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<AuditMiddleware> _logger;
    private readonly ISecurityEventSink _eventSink;

    public AuditMiddleware(RequestDelegate next, ILogger<AuditMiddleware> logger, ISecurityEventSink eventSink)
    {
        _next = next;
        _logger = logger;
        _eventSink = eventSink;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var sw = Stopwatch.StartNew();

        await _next(context);

        sw.Stop();

        var providerKey = context.Items["EdgeProviderKey"] as string;
        if (providerKey == null)
            return;

        var userId = context.Items.TryGetValue("EdgeUserId", out var uid) && uid is int id ? (int?)id : null;
        var permission = context.Items.TryGetValue("EdgePermission", out var perm) && perm is PermissionLevel pl ? (PermissionLevel?)pl : null;
        var method = context.Request.Method;
        var path = context.Request.Path.Value;
        var statusCode = context.Response.StatusCode;
        var allowed = statusCode < 400;

        _logger.LogInformation(
            "EDGE_AUDIT: {Result} | provider={Provider} user={UserId} permission={Permission} " +
            "method={Method} path={Path} status={StatusCode} elapsed={ElapsedMs}ms",
            allowed ? "ALLOW" : "DENY",
            providerKey,
            userId,
            permission?.ToDbValue() ?? "none",
            method,
            path,
            statusCode,
            sw.ElapsedMilliseconds);

        var secEvent = new EdgeSecurityEvent
        {
            EventType = allowed ? EdgeEventTypes.AuthSuccess : EdgeEventTypes.AuthFailure,
            Provider = providerKey,
            VibeUserId = userId,
            PermissionLevel = permission?.ToDbValue(),
            Operation = $"{method} {path}",
            Result = allowed ? "allow" : "deny",
            IpAddress = context.Connection.RemoteIpAddress?.ToString(),
            UserAgent = context.Request.Headers.UserAgent.FirstOrDefault(),
            RequestPath = path,
            RequestMethod = method,
            Metadata = new Dictionary<string, object>
            {
                ["status_code"] = statusCode,
                ["elapsed_ms"] = sw.ElapsedMilliseconds
            }
        };

        await _eventSink.EmitSafeAsync(secEvent, _logger);
    }
}
