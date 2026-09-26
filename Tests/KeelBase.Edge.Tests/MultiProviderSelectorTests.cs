using System.IdentityModel.Tokens.Jwt;
using FluentAssertions;
using KeelBase.Edge.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;

namespace KeelBase.Edge.Tests;

/// <summary>
/// PAY-1853 F1 (routing leg): MultiProviderSelector picks a scheme by the token's ISSUER, and falls back to
/// "FallbackReject" for no token, a malformed token, an oversized token and an unknown issuer. The
/// signature/expiry/audience/alg=validity legs are the JwtBearer pipeline's job and need a host.
/// </summary>
public class MultiProviderSelectorTests
{
    private static MultiProviderSelector Selector(params (string issuer, string scheme)[] mappings)
    {
        var s = new MultiProviderSelector(NullLogger<MultiProviderSelector>.Instance);
        s.UpdateMappings(mappings.ToDictionary(m => m.issuer, m => m.scheme, StringComparer.Ordinal));
        return s;
    }

    private static HttpContext WithBearer(string? token)
    {
        var ctx = new DefaultHttpContext();
        if (token != null) ctx.Request.Headers.Authorization = "Bearer " + token;
        return ctx;
    }

    private static string TokenFromIssuer(string issuer)
    {
        var handler = new JwtSecurityTokenHandler();
        var descriptor = new Microsoft.IdentityModel.Tokens.SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = "acp",
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(
                new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(new byte[32]),
                Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256)
        };
        return handler.WriteToken(handler.CreateToken(descriptor));
    }

    [Fact]
    public void F1_no_token_goes_to_FallbackReject()
    {
        Selector(("https://idp.payez.net", "Edge_KeelAuth")).SelectScheme(WithBearer(null))
            .Should().Be("FallbackReject");
    }

    [Fact]
    public void F1_non_bearer_header_goes_to_FallbackReject()
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Headers.Authorization = "Basic abc";
        Selector(("https://idp.payez.net", "Edge_KeelAuth")).SelectScheme(ctx)
            .Should().Be("FallbackReject");
    }

    [Fact]
    public void F1_malformed_token_goes_to_FallbackReject()
    {
        Selector(("https://idp.payez.net", "Edge_KeelAuth")).SelectScheme(WithBearer("not.a.jwt"))
            .Should().Be("FallbackReject");
    }

    [Fact]
    public void F1_oversized_token_goes_to_FallbackReject()
    {
        var huge = new string('a', 16385);
        Selector(("https://idp.payez.net", "Edge_KeelAuth")).SelectScheme(WithBearer(huge))
            .Should().Be("FallbackReject");
    }

    [Fact]
    public void F1_unknown_issuer_goes_to_FallbackReject()
    {
        var token = TokenFromIssuer("https://evil.example.com");
        Selector(("https://idp.payez.net", "Edge_KeelAuth")).SelectScheme(WithBearer(token))
            .Should().Be("FallbackReject");
    }

    [Fact]
    public void F1_known_issuer_selects_its_scheme()
    {
        var token = TokenFromIssuer("https://idp.payez.net");
        Selector(("https://idp.payez.net", "Edge_KeelAuth")).SelectScheme(WithBearer(token))
            .Should().Be("Edge_KeelAuth");
    }

    [Fact]
    public void F1_empty_registry_goes_to_FallbackReject()
    {
        var token = TokenFromIssuer("https://idp.payez.net");
        Selector().SelectScheme(WithBearer(token)).Should().Be("FallbackReject");
    }
}
