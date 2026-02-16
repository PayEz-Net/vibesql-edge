using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Vibe.Edge.Data;
using Vibe.Edge.Models;

namespace Vibe.Edge.Health;

[ApiController]
[Route("health")]
[AllowAnonymous]
public class ProviderHealthCheck : ControllerBase
{
    private readonly VibeDataService _dataService;
    private readonly IHttpClientFactory _httpClientFactory;

    public ProviderHealthCheck(VibeDataService dataService, IHttpClientFactory httpClientFactory)
    {
        _dataService = dataService;
        _httpClientFactory = httpClientFactory;
    }

    [HttpGet("providers")]
    public async Task<IActionResult> GetProviderHealth()
    {
        var providers = await _dataService.GetAllProvidersAsync();
        var results = new List<ProviderHealthStatus>();

        var httpClient = _httpClientFactory.CreateClient();
        httpClient.Timeout = TimeSpan.FromSeconds(5);

        foreach (var provider in providers)
        {
            var status = new ProviderHealthStatus
            {
                ProviderKey = provider.ProviderKey,
                DisplayName = provider.DisplayName,
                IsActive = provider.IsActive
            };

            try
            {
                var response = await httpClient.GetAsync(provider.DiscoveryUrl);
                status.DiscoveryReachable = response.IsSuccessStatusCode;

                if (response.IsSuccessStatusCode)
                {
                    var disco = await response.Content.ReadAsStringAsync();
                    var doc = System.Text.Json.JsonDocument.Parse(disco);
                    if (doc.RootElement.TryGetProperty("jwks_uri", out var jwksUri))
                    {
                        var jwksResponse = await httpClient.GetAsync(jwksUri.GetString());
                        status.JwksReachable = jwksResponse.IsSuccessStatusCode;
                    }
                }
            }
            catch (Exception ex)
            {
                status.Error = ex.Message;
            }

            results.Add(status);
        }

        return Ok(ApiResponse<object>.SuccessResponse(
            results, "Provider health status", "PROVIDER_HEALTH",
            HttpContext.TraceIdentifier));
    }
}
