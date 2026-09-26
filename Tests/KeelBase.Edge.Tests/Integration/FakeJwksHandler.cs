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

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var url = request.RequestUri?.ToString() ?? "";

        if (url.Contains(".well-known/openid-configuration"))
        {
            var discovery = new
            {
                issuer = _issuer,
                jwks_uri = $"{_issuer}/.well-known/jwks",
                token_endpoint = $"{_issuer}/oauth/token",
                authorization_endpoint = $"{_issuer}/oauth/authorize",
                response_types_supported = new[] { "code", "token" },
                subject_types_supported = new[] { "public" },
                id_token_signing_alg_values_supported = new[] { "RS256" }
            };

            return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(discovery), System.Text.Encoding.UTF8, "application/json")
            });
        }

        if (url.Contains("jwks"))
        {
            var jwk = TestJwtGenerator.JsonWebKey;
            var jwks = new { keys = new[] { new { kty = jwk.Kty, n = jwk.N, e = jwk.E, kid = jwk.Kid, use = jwk.Use, alg = jwk.Alg } } };

            return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(jwks), System.Text.Encoding.UTF8, "application/json")
            });
        }

        return Task.FromResult(new HttpResponseMessage(System.Net.HttpStatusCode.NotFound));
    }
}
