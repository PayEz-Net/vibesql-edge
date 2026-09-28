using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace KeelBase.Edge.Tests.Integration;

/// <summary>
/// PAY-1853 F1 support: serves a fake OIDC discovery document + JWKS for <see cref="TestJwtGenerator"/>'s
/// signing key, so a host can validate test tokens without network. Ported from
/// vibesql-server/tests/VibeSQL.Edge.Tests/Integration/FakeJwksHandler.cs.
/// </summary>
public class FakeJwksHandler : DelegatingHandler
{
    private readonly string _issuer;

    public FakeJwksHandler(string issuer)
    {
        _issuer = issuer;
        InnerHandler = new HttpClientHandler();
    }

    /// <summary>
    /// PAY-1853 R18: the discovery document served for <paramref name="issuer"/>. Exposed so a test can
    /// serve the identical document over a real loopback socket (the end-to-end JWT row), not only via
    /// this in-process handler - both must describe the same JWKS as <see cref="TestJwtGenerator"/> signs with.
    /// </summary>
    public static string DiscoveryJson(string issuer)
    {
        var discovery = new
        {
            issuer,
            jwks_uri = $"{issuer}/.well-known/jwks",
            token_endpoint = $"{issuer}/oauth/token",
            authorization_endpoint = $"{issuer}/oauth/authorize",
            response_types_supported = new[] { "code", "token" },
            subject_types_supported = new[] { "public" },
            id_token_signing_alg_values_supported = new[] { "RS256" }
        };

        return JsonSerializer.Serialize(discovery);
    }

    /// <summary>PAY-1853 R18: the JWKS document carrying <see cref="TestJwtGenerator"/>'s public key.</summary>
    public static string JwksJson()
    {
        var jwk = TestJwtGenerator.JsonWebKey;
        var jwks = new { keys = new[] { new { kty = jwk.Kty, n = jwk.N, e = jwk.E, kid = jwk.Kid, use = jwk.Use, alg = jwk.Alg } } };
        return JsonSerializer.Serialize(jwks);
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var url = request.RequestUri?.ToString() ?? "";

        if (url.Contains(".well-known/openid-configuration"))
            return Json(DiscoveryJson(_issuer));

        if (url.Contains("jwks"))
            return Json(JwksJson());

        return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.NotFound));
    }

    private static Task<HttpResponseMessage> Json(string payload) =>
        Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK)
        {
            Content = new StringContent(payload, System.Text.Encoding.UTF8, "application/json")
        });
}
