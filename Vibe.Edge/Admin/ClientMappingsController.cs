using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Vibe.Edge.Data;
using Vibe.Edge.Data.Models;
using Vibe.Edge.Models;

namespace Vibe.Edge.Admin;

[ApiController]
[Route("v1/admin/oidc-providers/{key}/clients")]
[Authorize]
[RequireAdminPermission]
public class ClientMappingsController : ControllerBase
{
    private readonly VibeDataService _dataService;

    public ClientMappingsController(VibeDataService dataService)
    {
        _dataService = dataService;
    }

    [HttpGet]
    public async Task<IActionResult> List(string key)
    {
        if (!await _dataService.ProviderExistsAsync(key))
            return NotFound(ApiResponse<object>.FailureResponse(
                "Provider not found", "PROVIDER_NOT_FOUND",
                requestId: HttpContext.TraceIdentifier));

        var mappings = await _dataService.GetClientMappingsAsync(key);
        return Ok(ApiResponse<object>.SuccessResponse(
            mappings, "Client mappings retrieved", "CLIENT_MAPPINGS_LISTED",
            HttpContext.TraceIdentifier));
    }

    [HttpPost]
    public async Task<IActionResult> Create(string key, [FromBody] CreateClientMappingRequest request)
    {
        if (!await _dataService.ProviderExistsAsync(key))
            return NotFound(ApiResponse<object>.FailureResponse(
                "Provider not found", "PROVIDER_NOT_FOUND",
                requestId: HttpContext.TraceIdentifier));

        var mapping = new OidcProviderClientMapping
        {
            ProviderKey = key,
            VibeClientId = request.VibeClientId,
            MaxPermission = request.MaxPermission,
            IsActive = true
        };

        var created = await _dataService.InsertClientMappingAsync(mapping);
        return Created($"/v1/admin/oidc-providers/{key}/clients/{created.Id}",
            ApiResponse<object>.SuccessResponse(
                created, "Client mapping created", "CLIENT_MAPPING_CREATED",
                HttpContext.TraceIdentifier));
    }

    [HttpPut("{id:int}")]
    public async Task<IActionResult> Update(string key, int id, [FromBody] UpdateClientMappingRequest request)
    {
        var updated = await _dataService.UpdateClientMappingAsync(id, m =>
        {
            if (request.VibeClientId != null) m.VibeClientId = request.VibeClientId;
            if (request.IsActive.HasValue) m.IsActive = request.IsActive.Value;
            if (request.MaxPermission != null) m.MaxPermission = request.MaxPermission;
        });

        if (updated == null)
            return NotFound(ApiResponse<object>.FailureResponse(
                "Client mapping not found", "CLIENT_MAPPING_NOT_FOUND",
                requestId: HttpContext.TraceIdentifier));

        return Ok(ApiResponse<object>.SuccessResponse(
            updated, "Client mapping updated", "CLIENT_MAPPING_UPDATED",
            HttpContext.TraceIdentifier));
    }

    [HttpDelete("{id:int}")]
    public async Task<IActionResult> Delete(string key, int id)
    {
        var deleted = await _dataService.DeleteClientMappingAsync(id);
        if (!deleted)
            return NotFound(ApiResponse<object>.FailureResponse(
                "Client mapping not found", "CLIENT_MAPPING_NOT_FOUND",
                requestId: HttpContext.TraceIdentifier));

        return Ok(ApiResponse<object>.SuccessResponse(
            new { id }, "Client mapping deleted", "CLIENT_MAPPING_DELETED",
            HttpContext.TraceIdentifier));
    }
}
