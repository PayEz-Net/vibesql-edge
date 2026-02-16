using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Vibe.Edge.Authentication;
using Vibe.Edge.Data;
using Vibe.Edge.Data.Models;
using Vibe.Edge.Models;
using Vibe.Edge.Security;

namespace Vibe.Edge.Admin;

[ApiController]
[Route("v1/admin/oidc-providers")]
[Authorize]
[RequireAdminPermission]
public class OidcProvidersController : ControllerBase
{
    private readonly VibeDataService _dataService;
    private readonly DynamicSchemeRegistrar _registrar;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ISecurityEventSink _eventSink;
    private readonly ILogger<OidcProvidersController> _logger;

    public OidcProvidersController(
        VibeDataService dataService,
        DynamicSchemeRegistrar registrar,
        IHttpClientFactory httpClientFactory,
        ISecurityEventSink eventSink,
        ILogger<OidcProvidersController> logger)
    {
        _dataService = dataService;
        _registrar = registrar;
        _httpClientFactory = httpClientFactory;
        _eventSink = eventSink;
        _logger = logger;
    }

    [HttpGet]
    public async Task<IActionResult> List()
    {
        var providers = await _dataService.GetAllProvidersAsync();
        return Ok(ApiResponse<object>.SuccessResponse(
            providers, "Providers retrieved", "PROVIDERS_LISTED",
            HttpContext.TraceIdentifier));
    }

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] CreateOidcProviderRequest request)
    {
        if (await _dataService.ProviderExistsAsync(request.ProviderKey))
        {
            return Conflict(ApiResponse<object>.FailureResponse(
                "Provider key already exists", "DUPLICATE_PROVIDER",
                detail: $"A provider with key '{request.ProviderKey}' already exists",
                requestId: HttpContext.TraceIdentifier));
        }

        var provider = new OidcProvider
        {
            ProviderKey = request.ProviderKey,
            DisplayName = request.DisplayName,
            Issuer = request.Issuer,
            DiscoveryUrl = request.DiscoveryUrl,
            Audience = request.Audience,
            AutoProvision = request.AutoProvision,
            ProvisionDefaultRole = request.ProvisionDefaultRole,
            SubjectClaimPath = request.SubjectClaimPath,
            RoleClaimPath = request.RoleClaimPath,
            EmailClaimPath = request.EmailClaimPath,
            ClockSkewSeconds = request.ClockSkewSeconds,
            IsActive = true
        };

        var created = await _dataService.InsertProviderAsync(provider);
        await _registrar.ForceRefreshAsync();

        await _eventSink.EmitSafeAsync(new EdgeSecurityEvent
        {
            EventType = EdgeEventTypes.ProviderRegistered,
            Provider = created.ProviderKey,
            Result = "allow",
            Metadata = new Dictionary<string, object> { ["issuer"] = created.Issuer }
        }, _logger);

        return Created($"/v1/admin/oidc-providers/{created.ProviderKey}",
            ApiResponse<object>.SuccessResponse(
                created, "Provider registered", "PROVIDER_CREATED",
                HttpContext.TraceIdentifier));
    }

    [HttpGet("{key}")]
    public async Task<IActionResult> Get(string key)
    {
        var provider = await _dataService.GetProviderByKeyAsync(key);
        if (provider == null)
            return NotFound(ApiResponse<object>.FailureResponse(
                "Provider not found", "PROVIDER_NOT_FOUND",
                requestId: HttpContext.TraceIdentifier));

        return Ok(ApiResponse<object>.SuccessResponse(
            provider, "Provider retrieved", "PROVIDER_GET",
            HttpContext.TraceIdentifier));
    }

    [HttpPut("{key}")]
    public async Task<IActionResult> Update(string key, [FromBody] UpdateOidcProviderRequest request)
    {
        var updated = await _dataService.UpdateProviderAsync(key, p =>
        {
            if (request.DisplayName != null) p.DisplayName = request.DisplayName;
            if (request.DiscoveryUrl != null) p.DiscoveryUrl = request.DiscoveryUrl;
            if (request.Audience != null) p.Audience = request.Audience;
            if (request.AutoProvision.HasValue) p.AutoProvision = request.AutoProvision.Value;
            if (request.ProvisionDefaultRole != null) p.ProvisionDefaultRole = request.ProvisionDefaultRole;
            if (request.SubjectClaimPath != null) p.SubjectClaimPath = request.SubjectClaimPath;
            if (request.RoleClaimPath != null) p.RoleClaimPath = request.RoleClaimPath;
            if (request.EmailClaimPath != null) p.EmailClaimPath = request.EmailClaimPath;
            if (request.ClockSkewSeconds.HasValue) p.ClockSkewSeconds = request.ClockSkewSeconds.Value;
        });

        if (updated == null)
            return NotFound(ApiResponse<object>.FailureResponse(
                "Provider not found", "PROVIDER_NOT_FOUND",
                requestId: HttpContext.TraceIdentifier));

        await _registrar.ForceRefreshAsync();

        return Ok(ApiResponse<object>.SuccessResponse(
            updated, "Provider updated", "PROVIDER_UPDATED",
            HttpContext.TraceIdentifier));
    }

    [HttpDelete("{key}")]
    public async Task<IActionResult> Delete(string key)
    {
        var disabled = await _dataService.DisableProviderAsync(key);
        if (!disabled)
            return NotFound(ApiResponse<object>.FailureResponse(
                "Provider not found or is a bootstrap provider", "PROVIDER_NOT_FOUND",
                requestId: HttpContext.TraceIdentifier));

        await _registrar.ForceRefreshAsync();

        await _eventSink.EmitSafeAsync(new EdgeSecurityEvent
        {
            EventType = EdgeEventTypes.ProviderDisabled,
            Provider = key,
            Result = "allow"
        }, _logger);

        return Ok(ApiResponse<object>.SuccessResponse(
            new { provider_key = key }, "Provider disabled", "PROVIDER_DISABLED",
            HttpContext.TraceIdentifier));
    }

    [HttpPost("{key}/test")]
    public async Task<IActionResult> Test(string key)
    {
        var provider = await _dataService.GetProviderByKeyAsync(key);
        if (provider == null)
            return NotFound(ApiResponse<object>.FailureResponse(
                "Provider not found", "PROVIDER_NOT_FOUND",
                requestId: HttpContext.TraceIdentifier));

        var status = new ProviderHealthStatus
        {
            ProviderKey = provider.ProviderKey,
            DisplayName = provider.DisplayName,
            IsActive = provider.IsActive
        };

        try
        {
            using var httpClient = _httpClientFactory.CreateClient();
            httpClient.Timeout = TimeSpan.FromSeconds(10);
            var discoveryResponse = await httpClient.GetAsync(provider.DiscoveryUrl);
            status.DiscoveryReachable = discoveryResponse.IsSuccessStatusCode;

            if (discoveryResponse.IsSuccessStatusCode)
            {
                var disco = await discoveryResponse.Content.ReadAsStringAsync();
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

        return Ok(ApiResponse<object>.SuccessResponse(
            status, "Provider test complete", "PROVIDER_TESTED",
            HttpContext.TraceIdentifier));
    }

    [HttpPost("{key}/refresh")]
    public async Task<IActionResult> Refresh(string key)
    {
        var provider = await _dataService.GetProviderByKeyAsync(key);
        if (provider == null)
            return NotFound(ApiResponse<object>.FailureResponse(
                "Provider not found", "PROVIDER_NOT_FOUND",
                requestId: HttpContext.TraceIdentifier));

        await _registrar.ForceRefreshAsync();

        return Ok(ApiResponse<object>.SuccessResponse(
            new { provider_key = key }, "Provider scheme refreshed", "PROVIDER_REFRESHED",
            HttpContext.TraceIdentifier));
    }
}
