using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using KeelBase.Edge.Identity;
using KeelBase.Edge.Tenancy;
using KeelBase.Edge.Models;

namespace KeelBase.Edge.Meta;

[ApiController]
[Authorize]
[Route("v1/[controller]")]
public class MetaController : ControllerBase
{
    [HttpGet("schemas")]
    public IActionResult GetSchemas()
    {
        // No tenant schema mapping available – return Not Implemented
        return StatusCode(501, ApiResponse<object>.FailureResponse(
            "Tenant schema mapping is not yet configured for this deployment.",
            "META_TENANT_SCHEMAS_UNKNOWN",
            requestId: HttpContext.TraceIdentifier));
    }

    [HttpGet("tables")]
    public IActionResult GetTables([FromQuery] string schema)
    {
        return StatusCode(501, ApiResponse<object>.FailureResponse(
            "Tenant schema mapping is not yet configured for this deployment.",
            "META_TENANT_SCHEMAS_UNKNOWN",
            requestId: HttpContext.TraceIdentifier));
    }

    [HttpGet("columns")]
    public IActionResult GetColumns([FromQuery] string schema, [FromQuery] string table)
    {
        return StatusCode(501, ApiResponse<object>.FailureResponse(
            "Tenant schema mapping is not yet configured for this deployment.",
            "META_TENANT_SCHEMAS_UNKNOWN",
            requestId: HttpContext.TraceIdentifier));
    }

    [HttpGet("policies")]
    public IActionResult GetPolicies([FromQuery] string schema, [FromQuery] string table)
    {
        return StatusCode(501, ApiResponse<object>.FailureResponse(
            "Tenant schema mapping is not yet configured for this deployment.",
            "META_TENANT_SCHEMAS_UNKNOWN",
            requestId: HttpContext.TraceIdentifier));
    }
}
