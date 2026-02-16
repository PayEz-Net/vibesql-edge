using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Vibe.Edge.Data;
using Vibe.Edge.Data.Models;
using Vibe.Edge.Models;

namespace Vibe.Edge.Admin;

[ApiController]
[Route("v1/admin/oidc-providers/{key}/roles")]
[Authorize]
[RequireAdminPermission]
[EnableRateLimiting("admin")]
public class RoleMappingsController : ControllerBase
{
    private readonly VibeDataService _dataService;

    public RoleMappingsController(VibeDataService dataService)
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

        var mappings = await _dataService.GetRoleMappingsAsync(key);
        return Ok(ApiResponse<object>.SuccessResponse(
            mappings, "Role mappings retrieved", "ROLE_MAPPINGS_LISTED",
            HttpContext.TraceIdentifier));
    }

    [HttpPost]
    public async Task<IActionResult> Create(string key, [FromBody] CreateRoleMappingRequest request)
    {
        if (!await _dataService.ProviderExistsAsync(key))
            return NotFound(ApiResponse<object>.FailureResponse(
                "Provider not found", "PROVIDER_NOT_FOUND",
                requestId: HttpContext.TraceIdentifier));

        var mapping = new OidcProviderRoleMapping
        {
            ProviderKey = key,
            ExternalRole = request.ExternalRole,
            VibePermission = request.VibePermission,
            DeniedStatements = request.DeniedStatements,
            AllowedCollections = request.AllowedCollections,
            Description = request.Description
        };

        var created = await _dataService.InsertRoleMappingAsync(mapping);
        return Created($"/v1/admin/oidc-providers/{key}/roles/{created.Id}",
            ApiResponse<object>.SuccessResponse(
                created, "Role mapping created", "ROLE_MAPPING_CREATED",
                HttpContext.TraceIdentifier));
    }

    [HttpPut("{id:int}")]
    public async Task<IActionResult> Update(string key, int id, [FromBody] UpdateRoleMappingRequest request)
    {
        var updated = await _dataService.UpdateRoleMappingAsync(id, m =>
        {
            if (request.VibePermission != null) m.VibePermission = request.VibePermission;
            if (request.DeniedStatements != null) m.DeniedStatements = request.DeniedStatements;
            if (request.AllowedCollections != null) m.AllowedCollections = request.AllowedCollections;
            if (request.Description != null) m.Description = request.Description;
        });

        if (updated == null)
            return NotFound(ApiResponse<object>.FailureResponse(
                "Role mapping not found", "ROLE_MAPPING_NOT_FOUND",
                requestId: HttpContext.TraceIdentifier));

        return Ok(ApiResponse<object>.SuccessResponse(
            updated, "Role mapping updated", "ROLE_MAPPING_UPDATED",
            HttpContext.TraceIdentifier));
    }

    [HttpDelete("{id:int}")]
    public async Task<IActionResult> Delete(string key, int id)
    {
        var deleted = await _dataService.DeleteRoleMappingAsync(id);
        if (!deleted)
            return NotFound(ApiResponse<object>.FailureResponse(
                "Role mapping not found", "ROLE_MAPPING_NOT_FOUND",
                requestId: HttpContext.TraceIdentifier));

        return Ok(ApiResponse<object>.SuccessResponse(
            new { id }, "Role mapping deleted", "ROLE_MAPPING_DELETED",
            HttpContext.TraceIdentifier));
    }
}
