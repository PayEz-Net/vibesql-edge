using System.Security.Claims;

namespace Vibe.Edge.Identity;

public static class ClaimExtractor
{
    public static string? ExtractClaim(ClaimsPrincipal principal, string claimPath)
    {
        return principal.FindFirst(claimPath)?.Value;
    }

    public static IEnumerable<string> ExtractRoles(ClaimsPrincipal principal, string roleClaimPath)
    {
        var roles = principal.FindAll(roleClaimPath).Select(c => c.Value).ToList();
        if (roles.Count == 0)
        {
            var roleClaim = principal.FindFirst(roleClaimPath)?.Value;
            if (!string.IsNullOrEmpty(roleClaim))
            {
                if (roleClaim.StartsWith('['))
                {
                    try
                    {
                        var parsed = System.Text.Json.JsonSerializer.Deserialize<string[]>(roleClaim);
                        if (parsed != null)
                            return parsed;
                    }
                    catch
                    {
                        return [roleClaim];
                    }
                }
                return [roleClaim];
            }
        }
        return roles;
    }
}
