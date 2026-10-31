#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
docker info *> $null
if ($LASTEXITCODE -ne 0) { throw 'Start Docker Desktop and wait until it is running, then retry.' }
docker run --rm --mount "type=bind,source=$($PWD.Path),target=/work" -w /work python:3.12-slim python ops/upgrade_local.py
if ($LASTEXITCODE -ne 0) { throw 'Configuration setup failed.' }
docker compose -f compose.yaml up --build --force-recreate -d --wait --wait-timeout 240
if ($LASTEXITCODE -ne 0) {
    docker compose -f compose.yaml logs --tail 50
    throw 'Startup failed. Inspect output above.'
}
Invoke-RestMethod 'http://127.0.0.1:8000/health/ready'
Write-Host 'Dashboard: http://127.0.0.1:8000'
Write-Host 'First install/upgrade: create your administrator with:'
Write-Host 'docker compose -f compose.yaml exec api python -m ops.admin create-user admin --role admin'
Write-Host 'Existing organization accounts and data are preserved. Shared legacy keys no longer grant access.'
Start-Process 'http://127.0.0.1:8000'
