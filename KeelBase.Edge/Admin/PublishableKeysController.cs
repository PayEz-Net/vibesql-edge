using System.Security.Cryptography;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using KeelBase.Edge.Data;
using KeelBase.Edge.Models;

namespace KeelBase.Edge.Admin;

[ApiController]
[Route("v1/admin/publishable-keys")]
[Authorize]
[RequireAdminPermission]
[EnableRateLimiting("admin")]
public class PublishableKeysController : ControllerBase
{
    private readonly KeelBaseDataService _dataService;
    private readonly ILogger<PublishableKeysController> _logger;

    public PublishableKeysController(KeelBaseDataService dataService, ILogger<PublishableKeysController> logger)
    {
        _dataService = dataService;
        _logger = logger;
    }

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] CreatePublishableKeyRequest request)
    {
        var randomBytes = RandomNumberGenerator.GetBytes(24);
        var random32 = Convert.ToBase64String(randomBytes)
            .Replace('+', '-').Replace('/', '_').TrimEnd('=')[..32];
        var fullKey = $"kb_pub_{random32}";
        var keyPrefix = random32[..8];
        var keyHash = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(fullKey))).ToLowerInvariant();

        var record = await _dataService.CreatePublishableKeyAsync(keyPrefix, keyHash, request.TenantClientId);

        return Ok(ApiResponse<object>.SuccessResponse(
            new { record.Id, record.TenantClientId, record.CreatedAt, Key = fullKey },
            "Publishable key created. Store the key now — it will not be shown again.",
            "PUBLISHABLE_KEY_CREATED",
            HttpContext.TraceIdentifier));
    }

    [HttpDelete("{id:int}")]
    public async Task<IActionResult> Revoke(int id)
    {
        var revoked = await _dataService.RevokePublishableKeyAsync(id);
        if (!revoked)
            return NotFound(ApiResponse<object>.FailureResponse(
                "Key not found or already revoked.", "PUBLISHABLE_KEY_NOT_FOUND",
                requestId: HttpContext.TraceIdentifier));

        return Ok(ApiResponse<object>.SuccessResponse(
            new { }, "Key revoked.", "PUBLISHABLE_KEY_REVOKED", HttpContext.TraceIdentifier));
    }
}

public class CreatePublishableKeyRequest
{
    public string TenantClientId { get; set; } = string.Empty;
}