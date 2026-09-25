namespace Vibe.Edge.Identity;

using Vibe.Edge.Models;
using Microsoft.AspNetCore.Http;

public enum CallerType
{
    User,
    Agent,
    Service,
    Anonymous
}

public sealed record ResolvedCaller(
    CallerType CallerType,
    string? ProviderKey,
    string? Subject,
    string? UserId,
    string? AgentId,
    string? TenantClientId,
    PermissionLevel PermissionLevel,
    IReadOnlyList<string> Roles
);

public static class ResolvedCallerExtensions
{
    public static ResolvedCaller? From(HttpContext ctx)
    {
        return ctx.Items["EdgeCaller"] as ResolvedCaller;
    }
}
