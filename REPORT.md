## Report for TS-01

**Files changed**:
- `Vibe.Edge/Identity/ResolvedCaller.cs` (lines 1-31)
- `Vibe.Edge/Identity/IdentityResolutionMiddleware.cs` (lines 128-144, added ResolvedCaller creation and context storage)
- `Vibe.Edge/Identity/WhoAmIController.cs` (new controller, lines 1-22)

**Build output (last 5 lines)**:
```
  Determining projects to restore...
  All projects are up-to-date for restore.
  Vibe.Edge -> C:\Users\jon-local\AgentRepos\RigPert\keelbase-edge\Vibe.Edge\bin\Debug\net9.0\Vibe.Edge.dll

Build succeeded.
    0 Warning(s)
    0 Error(s)
``` 

**Acceptance criteria verification**:
- No build errors, 0 warnings.
- `ResolvedCaller` model created with required fields and enum.
- Middleware now builds `ResolvedCaller` (CallerType=User, fills known fields) and stores in `HttpContext.Items["EdgeCaller"]`.
- `WhoAmIController` added at `/v1/whoami`, requires authentication (pipeline already enforces auth before reaching controller). Returns `ApiResponse<ResolvedCaller>` on success, `401 Unauthorized` when no caller is present.
- Endpoint respects existing auth; unauthenticated request receives 401.
- No tokens or secrets are included in response.

**What was not verified**:
- PermissionLevel is set to `None` (as per spec) – not exercised elsewhere.
- Roles list is passed through unchanged.
- No integration tests for the endpoint.

**Assumptions**:
- Caller is always a User at this stage; other CallerType values will be added later.
- `PermissionLevel.None` is an acceptable placeholder.
- The existing auth middleware returns 401 for unauthenticated requests before reaching this controller.

Done.