using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Vibe.Edge.Data;
using Vibe.Edge.Models;

namespace Vibe.Edge.Admin;

[ApiController]
[Route("v1/admin/federated-identities")]
[Authorize]
[RequireAdminPermission]
public class FederatedIdentitiesController : ControllerBase
{
    private readonly VibeDataService _dataService;

    public FederatedIdentitiesController(VibeDataService dataService)
    {
        _dataService = dataService;
    }

    [HttpGet]
    public async Task<IActionResult> List([FromQuery] int limit = 100, [FromQuery] int offset = 0)
    {
        var identities = await _dataService.GetFederatedIdentitiesAsync(limit, offset);
        return Ok(ApiResponse<object>.SuccessResponse(
            identities, "Federated identities retrieved", "FEDERATED_IDENTITIES_LISTED",
            HttpContext.TraceIdentifier));
    }

    [HttpGet("{id:int}")]
    public async Task<IActionResult> Get(int id)
    {
        var identity = await _dataService.GetFederatedIdentityByIdAsync(id);
        if (identity == null)
            return NotFound(ApiResponse<object>.FailureResponse(
                "Federated identity not found", "FEDERATED_IDENTITY_NOT_FOUND",
                requestId: HttpContext.TraceIdentifier));

        return Ok(ApiResponse<object>.SuccessResponse(
            identity, "Federated identity retrieved", "FEDERATED_IDENTITY_GET",
            HttpContext.TraceIdentifier));
    }
}
