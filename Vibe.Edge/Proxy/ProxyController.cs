using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Vibe.Edge.Credentials;
using Vibe.Edge.Data;
using Vibe.Edge.Models;
using Vibe.Edge.Security;

namespace Vibe.Edge.Proxy;

[ApiController]
[Authorize]
[EnableRateLimiting("proxy")]
public class ProxyController : ControllerBase
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IClientCredentialProvider _credentialProvider;
    private readonly VibeDataService _dataService;
    private readonly IConfiguration _configuration;
    private readonly ISecurityEventSink _eventSink;
    private readonly ILogger<ProxyController> _logger;

    public ProxyController(
        IHttpClientFactory httpClientFactory,
        IClientCredentialProvider credentialProvider,
        VibeDataService dataService,
        IConfiguration configuration,
        ISecurityEventSink eventSink,
        ILogger<ProxyController> logger)
    {
        _httpClientFactory = httpClientFactory;
        _credentialProvider = credentialProvider;
        _dataService = dataService;
        _configuration = configuration;
        _eventSink = eventSink;
        _logger = logger;
    }

    [Route("v1/{**path}")]
    public async Task<IActionResult> CatchAll(string path)
    {
        var fullPath = Request.Path.Value ?? "";

        if (fullPath.StartsWith("/v1/admin/", StringComparison.OrdinalIgnoreCase) ||
            fullPath.StartsWith("/health", StringComparison.OrdinalIgnoreCase))
        {
            return NotFound();
        }

        var providerKey = HttpContext.Items["EdgeProviderKey"] as string;
        if (string.IsNullOrEmpty(providerKey))
        {
            return Unauthorized(ApiResponse<object>.FailureResponse(
                "Provider not resolved", "PROVIDER_UNKNOWN",
                requestId: HttpContext.TraceIdentifier));
        }

        var clientMapping = await _dataService.GetActiveClientMappingAsync(providerKey);
        if (clientMapping == null)
        {
            _logger.LogWarning("EDGE_PROXY: No active client mapping for provider {Provider}", providerKey);
            return StatusCode(403, ApiResponse<object>.FailureResponse(
                "No client mapping configured", "CLIENT_MAPPING_MISSING",
                detail: $"Provider '{providerKey}' has no active client mapping",
                requestId: HttpContext.TraceIdentifier));
        }

        var vibeClientId = clientMapping.VibeClientId;
        var signingKey = await _credentialProvider.GetSigningKeyAsync(vibeClientId);
        if (signingKey == null)
        {
            _logger.LogError("EDGE_PROXY: No signing key for client {ClientId}", vibeClientId);
            await _eventSink.EmitSafeAsync(new EdgeSecurityEvent
            {
                EventType = EdgeEventTypes.SigningKeyMiss,
                Provider = providerKey,
                ClientId = vibeClientId,
                Result = "error",
                DenyReason = EdgeDenyReasons.SigningKeyNotFound,
                IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
                RequestPath = fullPath,
                RequestMethod = Request.Method
            }, _logger);
            return StatusCode(502, ApiResponse<object>.FailureResponse(
                "Signing key not available", "SIGNING_KEY_MISSING",
                requestId: HttpContext.TraceIdentifier));
        }

        var vibeUserId = HttpContext.Items.TryGetValue("EdgeUserId", out var uid) && uid is int id ? id : 0;
        var viaHeader = _configuration.GetValue("VibeEdge:ProxyViaHeader", "idp-proxy")!;
        var publicApiUrl = _configuration["VibeEdge:PublicApiUrl"]
            ?? throw new InvalidOperationException("VibeEdge:PublicApiUrl is not configured");

        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
        var signingPath = Request.Path.Value ?? "";
        var stringToSign = HmacSigner.BuildStringToSign(timestamp, Request.Method, signingPath);
        var signature = HmacSigner.ComputeSignature(stringToSign, signingKey);

        var targetUrl = $"{publicApiUrl.TrimEnd('/')}{Request.Path}{Request.QueryString}";

        Request.EnableBuffering();
        Request.Body.Position = 0;

        var proxyRequest = ProxyRequestBuilder.Build(
            Request, targetUrl, vibeClientId, timestamp, signature, vibeUserId, viaHeader);

        _logger.LogInformation(
            "EDGE_PROXY: Forwarding {Method} {Path} for client {ClientId} (user {UserId})",
            Request.Method, fullPath, vibeClientId, vibeUserId);

        try
        {
            var client = _httpClientFactory.CreateClient("PublicApi");
            var response = await client.SendAsync(proxyRequest, HttpContext.RequestAborted);

            var responseBody = await response.Content.ReadAsByteArrayAsync(HttpContext.RequestAborted);
            var contentType = response.Content.Headers.ContentType?.ToString() ?? "application/json";

            Response.StatusCode = (int)response.StatusCode;
            Response.ContentType = contentType;
            await Response.Body.WriteAsync(responseBody, HttpContext.RequestAborted);
            return new EmptyResult();
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "EDGE_PROXY: Failed to reach Public.Api at {Url}", targetUrl);
            return StatusCode(502, ApiResponse<object>.FailureResponse(
                "Unable to reach upstream API", "UPSTREAM_UNREACHABLE",
                requestId: HttpContext.TraceIdentifier));
        }
    }
}
