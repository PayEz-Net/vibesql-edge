using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using KeelBase.Edge.Models;

namespace KeelBase.Edge.Meta;

[ApiController]
[Authorize]
[Route("v1/[controller]")]
public class TypesController : ControllerBase
{
    [HttpGet]
    public IActionResult Get([FromQuery] string lang = "ts")
    {
        if (!string.Equals(lang, "ts", StringComparison.OrdinalIgnoreCase))
        {
            return BadRequest(ApiResponse<object>.FailureResponse(
                $"Language '{lang}' is not supported. Supported: ts",
                "TYPES_LANG_UNSUPPORTED",
                requestId: HttpContext.TraceIdentifier));
        }

        // Tenant schema catalog is not yet implemented (TS-06 returns META_TENANT_SCHEMAS_UNKNOWN).
        // When catalog data becomes available, replace this with real type generation using PgToTsTypeMapper.
        return StatusCode(501, ApiResponse<object>.FailureResponse(
            "Type generation requires tenant schema mapping, which is not yet configured for this deployment.",
            "META_TENANT_SCHEMAS_UNKNOWN",
            requestId: HttpContext.TraceIdentifier));
    }
}
