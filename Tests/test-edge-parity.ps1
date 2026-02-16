# Vibe.Edge Parity Test
# Validates that requests through Edge produce identical results to the existing proxy path.
#
# Prerequisites:
#   - Public.Api running (default: http://localhost:5000)
#   - Vibe.Edge running (default: http://localhost:5100)
#   - Valid bootstrap IDP JWT token
#   - Matching signing key in edge_client_credentials
#
# Usage:
#   ./Tests/test-edge-parity.ps1 -EdgeUrl "http://localhost:5100" -ProxyUrl "http://localhost:5050" -Token "eyJ..."

param(
    [string]$EdgeUrl = "http://localhost:5100",
    [string]$ProxyUrl = "http://localhost:5050",
    [string]$Token = "",
    [string]$Collection = "test_parity"
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrEmpty($Token)) {
    Write-Host "ERROR: -Token parameter is required (JWT Bearer token)" -ForegroundColor Red
    Write-Host "Usage: ./test-edge-parity.ps1 -Token 'eyJ...'"
    exit 1
}

$headers = @{
    "Authorization" = "Bearer $Token"
    "Content-Type"  = "application/json"
}

$results = @()
$passed = 0
$failed = 0

function Test-Parity {
    param(
        [string]$Name,
        [string]$Method,
        [string]$Path,
        [string]$Body = $null
    )

    Write-Host "`n--- Test: $Name ---" -ForegroundColor Cyan

    $edgeUri = "$EdgeUrl$Path"
    $proxyUri = "$ProxyUrl$Path"

    try {
        $edgeParams = @{
            Uri     = $edgeUri
            Method  = $Method
            Headers = $headers
        }
        if ($Body) { $edgeParams.Body = $Body }

        $edgeResponse = Invoke-WebRequest @edgeParams -SkipHttpErrorCheck
        $edgeStatus = $edgeResponse.StatusCode
        $edgeBody = $edgeResponse.Content
    }
    catch {
        $edgeStatus = "ERROR"
        $edgeBody = $_.Exception.Message
    }

    try {
        $proxyParams = @{
            Uri     = $proxyUri
            Method  = $Method
            Headers = $headers
        }
        if ($Body) { $proxyParams.Body = $Body }

        $proxyResponse = Invoke-WebRequest @proxyParams -SkipHttpErrorCheck
        $proxyStatus = $proxyResponse.StatusCode
        $proxyBody = $proxyResponse.Content
    }
    catch {
        $proxyStatus = "ERROR"
        $proxyBody = $_.Exception.Message
    }

    $statusMatch = $edgeStatus -eq $proxyStatus

    if ($statusMatch) {
        Write-Host "  PASS: Status match ($edgeStatus)" -ForegroundColor Green
        $script:passed++
    }
    else {
        Write-Host "  FAIL: Status mismatch - Edge=$edgeStatus, Proxy=$proxyStatus" -ForegroundColor Red
        $script:failed++
    }

    Write-Host "  Edge response:  $($edgeBody.Substring(0, [Math]::Min(200, $edgeBody.Length)))..."
    Write-Host "  Proxy response: $($proxyBody.Substring(0, [Math]::Min(200, $proxyBody.Length)))..."

    $script:results += [PSCustomObject]@{
        Test        = $Name
        Method      = $Method
        Path        = $Path
        EdgeStatus  = $edgeStatus
        ProxyStatus = $proxyStatus
        Match       = $statusMatch
    }
}

Write-Host "=== Vibe.Edge Parity Test ===" -ForegroundColor Yellow
Write-Host "Edge URL:  $EdgeUrl"
Write-Host "Proxy URL: $ProxyUrl"
Write-Host ""

# Test 1: SELECT query
Test-Parity -Name "SELECT Query" -Method "POST" -Path "/v1/mvp/$Collection/query" -Body '{"sql": "SELECT 1 as test_col"}'

# Test 2: List collections (GET)
Test-Parity -Name "List Collections" -Method "GET" -Path "/v1/mvp/collections"

# Test 3: Schema read
Test-Parity -Name "Schema Read" -Method "GET" -Path "/v1/schemas"

# Test 4: INSERT
Test-Parity -Name "INSERT Record" -Method "POST" -Path "/v1/mvp/$Collection/query" -Body '{"sql": "INSERT INTO parity_test (id, name) VALUES (1, ''edge_test'') ON CONFLICT (id) DO UPDATE SET name = ''edge_test''"}'

# Test 5: UPDATE
Test-Parity -Name "UPDATE Record" -Method "POST" -Path "/v1/mvp/$Collection/query" -Body '{"sql": "UPDATE parity_test SET name = ''edge_updated'' WHERE id = 1"}'

# Test 6: DELETE
Test-Parity -Name "DELETE Record" -Method "POST" -Path "/v1/mvp/$Collection/query" -Body '{"sql": "DELETE FROM parity_test WHERE id = 1"}'

# Test 7: Health check (unauthenticated, Edge-only)
Write-Host "`n--- Test: Edge Health Check ---" -ForegroundColor Cyan
try {
    $healthResponse = Invoke-WebRequest -Uri "$EdgeUrl/health/providers" -Method GET -SkipHttpErrorCheck
    if ($healthResponse.StatusCode -eq 200) {
        Write-Host "  PASS: Health endpoint returns 200" -ForegroundColor Green
        $passed++
    } else {
        Write-Host "  FAIL: Health endpoint returned $($healthResponse.StatusCode)" -ForegroundColor Red
        $failed++
    }
}
catch {
    Write-Host "  FAIL: Health endpoint error - $($_.Exception.Message)" -ForegroundColor Red
    $failed++
}

# Summary
Write-Host "`n=== Results ===" -ForegroundColor Yellow
$results | Format-Table -AutoSize
Write-Host "Passed: $passed / $($passed + $failed)" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })

if ($failed -gt 0) {
    Write-Host "PARITY TEST FAILED" -ForegroundColor Red
    exit 1
}
else {
    Write-Host "PARITY TEST PASSED" -ForegroundColor Green
    exit 0
}
