using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace KeelBase.Edge.Tests.Integration;

/// <summary>
/// PAY-1853 F1 support: an RSA-signed JWT generator for the JWT matrix rows, so a test can vary
/// issuer / audience / expiry / signature / kid independently. Ported from
/// vibesql-server/tests/VibeSQL.Edge.Tests/Integration/TestJwtGenerator.cs (no type adaptation needed).
/// </summary>
public static class TestJwtGenerator
{
    private static readonly RSA Rsa = RSA.Create(2048);

    public static RsaSecurityKey SecurityKey { get; } = new(Rsa);

    public static JsonWebKey JsonWebKey
    {
        get
        {
            var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(SecurityKey);
            jwk.Use = "sig";
            jwk.Alg = SecurityAlgorithms.RsaSha256;
            jwk.Kid = "test-key-1";
            return jwk;
        }
    }

    public static string GenerateToken(
        string issuer,
        string audience,
        string subject,
        string[]? roles = null,
        string? email = null,
        TimeSpan? lifetime = null,
        string? kid = null)
    {
        var credentials = new SigningCredentials(SecurityKey, SecurityAlgorithms.RsaSha256)
        {
            Key = { KeyId = kid ?? "test-key-1" }
        };

        var claims = new List<Claim>
        {
            new("sub", subject),
            new("aud", audience)
        };

        if (email is not null)
            claims.Add(new Claim("email", email));

        if (roles is not null)
        {
            foreach (var role in roles)
                claims.Add(new Claim("roles", role));
        }

        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            notBefore: DateTime.UtcNow.AddMinutes(-1),
            expires: DateTime.UtcNow.Add(lifetime ?? TimeSpan.FromMinutes(30)),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public static string GenerateExpiredToken(string issuer, string audience, string subject)
    {
        return GenerateToken(issuer, audience, subject, lifetime: TimeSpan.FromMinutes(-5));
    }

    /// <summary>PAY-1853 F1: alg=none. A token whose header declares no signature algorithm must be refused.</summary>
    public static string GenerateUnsignedAlgNoneToken(string issuer, string audience, string subject)
    {
        var header = Base64UrlEncoder.Encode("{\"alg\":\"none\",\"typ\":\"JWT\"}");
        var payload = Base64UrlEncoder.Encode(
            $"{{\"iss\":\"{issuer}\",\"aud\":\"{audience}\",\"sub\":\"{subject}\"," +
            $"\"exp\":{DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds()}}}");
        return $"{header}.{payload}.";
    }
}
