# Starts, stops or restarts a local relay for development and gate measurements.
#
#   powershell -ExecutionPolicy Bypass -File scripts/dev-relay.ps1 -Action start
#   powershell -ExecutionPolicy Bypass -File scripts/dev-relay.ps1 -Action restart
#   powershell -ExecutionPolicy Bypass -File scripts/dev-relay.ps1 -Action stop
#
# Needs Postgres on 5433, which is the throwaway container the relay test suite
# also uses:
#
#   docker run -d --name osprey-test-pg -p 5433:5432 \
#       -e POSTGRES_HOST_AUTH_METHOD=trust postgres:16-alpine
#
# `restart` is what the agent's relay_reconnect test invokes to produce the
# network drop the P1 gate criterion is about. It must genuinely bring the relay
# back: a stop-only command proves nothing, because an agent cannot reattach to
# something that is gone for good.

param(
    [ValidateSet('start', 'stop', 'restart')]
    [string]$Action = 'restart',
    [int]$Port = 8099,
    [string]$EnrollmentSecret = 'test-enrollment-secret-0123456789abcdef'
)

$ErrorActionPreference = 'Stop'
$relayDir = Resolve-Path "$PSScriptRoot\..\relay"

function Stop-Relay {
    $listener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    if (-not $listener) { return $false }
    foreach ($id in ($listener.OwningProcess | Select-Object -Unique)) {
        Stop-Process -Id $id -Force -ErrorAction SilentlyContinue
    }
    # The socket lingers briefly after the process dies; rebinding before it is
    # released would fail with EADDRINUSE.
    Start-Sleep -Seconds 2
    return $true
}

function Start-Relay {
    $env:DATABASE_URL = "postgres://osprey_app@localhost:5433/osprey_test"
    $env:OSPREY_ENROLLMENT_SECRET = $EnrollmentSecret
    $env:OSPREY_PORT = "$Port"
    $env:OSPREY_LOG_LEVEL = 'warn'
    Start-Process -FilePath 'node' -ArgumentList 'src/index.ts' `
        -WorkingDirectory $relayDir -WindowStyle Hidden | Out-Null

    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline) {
        try {
            $probe = Invoke-WebRequest "http://127.0.0.1:$Port/healthz" -UseBasicParsing -TimeoutSec 2
            if ($probe.StatusCode -eq 200) { return $true }
        } catch {
            Start-Sleep -Milliseconds 500
        }
    }
    return $false
}

switch ($Action) {
    'stop' {
        # Not an inline `if` expression: that is PowerShell 7 syntax and this
        # has to run under Windows PowerShell 5.1 too.
        if (Stop-Relay) {
            Write-Host "relay stopped"
        } else {
            Write-Host "no relay was listening on $Port"
        }
    }
    'start' {
        if (Start-Relay) { Write-Host "relay listening on $Port" } else { throw "relay did not become healthy" }
    }
    'restart' {
        Stop-Relay | Out-Null
        if (Start-Relay) { Write-Host "relay restarted on $Port" } else { throw "relay did not come back" }
    }
}
