using System.IdentityModel.Tokens.Jwt;

namespace Vibe.Edge.Authentication;

public class MultiProviderSelector
{
    private volatile IReadOnlyDictionary<string, string> _issuerToScheme = new Dictionary<string, string>();
    private readonly ILogger<MultiProviderSelector> _logger;

    public MultiProviderSelector(ILogger<MultiProviderSelector> logger)
    {
        _logger = logger;
    }

    public void UpdateMappings(IReadOnlyDictionary<string, string> issuerToScheme)
    {
        Interlocked.Exchange(ref _issuerToScheme, issuerToScheme);
    }

    public string? SelectScheme(HttpContext context)
    {
        var token = ExtractBearerToken(context);
        if (string.IsNullOrEmpty(token))
            return null;

        if (token.Length > 16384)
        {
            _logger.LogWarning("EDGE_AUTH: Oversized JWT token ({Length} chars)", token.Length);
            return null;
        }

        try
        {
            var handler = new JwtSecurityTokenHandler();
            if (!handler.CanReadToken(token))
            {
                _logger.LogWarning("EDGE_AUTH: Malformed JWT token");
                return null;
            }

            var jwt = handler.ReadJwtToken(token);
            var issuer = jwt.Issuer;

            if (string.IsNullOrEmpty(issuer))
            {
                _logger.LogWarning("EDGE_AUTH: JWT missing iss claim");
                return null;
            }

            var mappings = _issuerToScheme;
            if (mappings.TryGetValue(issuer, out var scheme))
            {
                return scheme;
            }

            _logger.LogWarning("EDGE_AUTH: Unknown issuer {Issuer}", issuer);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "EDGE_AUTH: Failed to read JWT issuer");
            return null;
        }
    }

    private static string? ExtractBearerToken(HttpContext context)
    {
        var authHeader = context.Request.Headers.Authorization.FirstOrDefault();
        if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return null;

        return authHeader["Bearer ".Length..].Trim();
    }
}
