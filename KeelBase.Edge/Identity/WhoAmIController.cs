using Microsoft.AspNetCore.Mvc;
using KeelBase.Edge.Models;
using KeelBase.Edge.Identity;

namespace KeelBase.Edge.Identity;

[ApiController]
[Route("v1/[controller]")]
public class WhoAmIController : ControllerBase
{
    [HttpGet]
    [Route("/v1/whoami")]
    public IActionResult Get()
    {
        var caller = ResolvedCallerExtensions.From(HttpContext);
        if (caller == null)
        {
            return Unauthorized(ApiResponse<object>.FailureResponse("Unauthenticated", "UNAUTHORIZED", requestId: HttpContext.TraceIdentifier));
        }
        return Ok(ApiResponse<ResolvedCaller>.SuccessResponse(caller, "Caller info", "WHOAMI_SUCCESS", HttpContext.TraceIdentifier));
    }
}
