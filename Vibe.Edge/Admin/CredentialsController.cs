using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Vibe.Edge.Data;
using Vibe.Edge.Data.Models;
using Vibe.Edge.Models;
using Vibe.Edge.Security;

namespace Vibe.Edge.Admin;

[ApiController]
[Route("v1/admin/credentials")]
[Authorize]
[RequireAdminPermission]
[EnableRateLimiting("admin")]
public class CredentialsController : ControllerBase
{
    private readonly VibeDataService _dataService;
    private readonly ISecurityEventSink _eventSink;
    private readonly ILogger<CredentialsController> _logger;

    public CredentialsController(VibeDataService dataService, ISecurityEventSink eventSink, ILogger<CredentialsController> logger)
    {
        _dataService = dataService;
        _eventSink = eventSink;
        _logger = logger;
    }

    [HttpGet]
    public async Task<IActionResult> List()
    {
        var credentials = await _dataService.GetAllCredentialsAsync();
        var masked = credentials.Select(c => CredentialResponse.From(c));
        return Ok(ApiResponse<object>.SuccessResponse(
            masked, "Credentials retrieved", "CREDENTIALS_LISTED",
            HttpContext.TraceIdentifier));
    }

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] CreateCredentialRequest request)
    {
        var credential = new EdgeClientCredential
        {
            ClientId = request.ClientId,
            SigningKey = request.SigningKey,
            DisplayName = request.DisplayName,
            IsActive = true
        };

        var created = await _dataService.InsertCredentialAsync(credential);

        await _eventSink.EmitSafeAsync(new EdgeSecurityEvent
        {
            EventType = "credential_created",
            ClientId = created.ClientId,
            Result = "allow",
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
            RequestPath = HttpContext.Request.Path.Value,
            RequestMethod = HttpContext.Request.Method,
            Metadata = new Dictionary<string, object> { ["credential_id"] = created.Id }
        }, _logger);

        return Created($"/v1/admin/credentials/{created.Id}",
            ApiResponse<object>.SuccessResponse(
                CredentialResponse.From(created), "Credential created", "CREDENTIAL_CREATED",
                HttpContext.TraceIdentifier));
    }

    [HttpPut("{id:int}")]
    public async Task<IActionResult> Update(int id, [FromBody] UpdateCredentialRequest request)
    {
        var updated = await _dataService.UpdateCredentialAsync(id, c =>
        {
            if (request.DisplayName != null) c.DisplayName = request.DisplayName;
            if (request.IsActive.HasValue) c.IsActive = request.IsActive.Value;
        });

        if (updated == null)
            return NotFound(ApiResponse<object>.FailureResponse(
                "Credential not found", "CREDENTIAL_NOT_FOUND",
                requestId: HttpContext.TraceIdentifier));

        await _eventSink.EmitSafeAsync(new EdgeSecurityEvent
        {
            EventType = "credential_updated",
            ClientId = updated.ClientId,
            Result = "allow",
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
            RequestPath = HttpContext.Request.Path.Value,
            RequestMethod = HttpContext.Request.Method,
            Metadata = new Dictionary<string, object> { ["credential_id"] = id }
        }, _logger);

        return Ok(ApiResponse<object>.SuccessResponse(
            CredentialResponse.From(updated), "Credential updated", "CREDENTIAL_UPDATED",
            HttpContext.TraceIdentifier));
    }

    [HttpDelete("{id:int}")]
    public async Task<IActionResult> Delete(int id)
    {
        var deleted = await _dataService.DeleteCredentialAsync(id);
        if (!deleted)
            return NotFound(ApiResponse<object>.FailureResponse(
                "Credential not found", "CREDENTIAL_NOT_FOUND",
                requestId: HttpContext.TraceIdentifier));

        await _eventSink.EmitSafeAsync(new EdgeSecurityEvent
        {
            EventType = "credential_deleted",
            Result = "allow",
            IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
            RequestPath = HttpContext.Request.Path.Value,
            RequestMethod = HttpContext.Request.Method,
            Metadata = new Dictionary<string, object> { ["credential_id"] = id }
        }, _logger);

        return Ok(ApiResponse<object>.SuccessResponse(
            new { id }, "Credential deleted", "CREDENTIAL_DELETED",
            HttpContext.TraceIdentifier));
    }
}
