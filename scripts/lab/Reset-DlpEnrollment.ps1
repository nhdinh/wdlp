[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DeviceId = 'LAB-CLIENT01.lab.local'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$databaseUrl = [Environment]::GetEnvironmentVariable('DLP_DATABASE_URL')
if ([string]::IsNullOrWhiteSpace($databaseUrl)) {
    throw 'DLP_DATABASE_URL is not set'
}

Write-Host "Resetting enrollment authority for device: $DeviceId" -ForegroundColor Cyan

# Use psql to run the DELETE. sqlx-cli does not have an ad-hoc query subcommand.
$psql = Get-Command psql -ErrorAction SilentlyContinue
if (-not $psql) {
    throw 'psql is not available. Install PostgreSQL client tools or run the DELETE manually against DLP_DATABASE_URL.'
}
$uri = [System.Uri]$databaseUrl
$host = $uri.Host
$port = $uri.Port
$database = $uri.AbsolutePath.Trim('/')
$userInfo = $uri.UserInfo.Split(':')
$user = $userInfo[0]
$pass = if ($userInfo.Length -gt 1) { $userInfo[1] } else { $null }
$env:PGPASSWORD = $pass
$output = & psql -h $host -p $port -U $user -d $database -c "DELETE FROM enrollment_authority WHERE device_id = '$DeviceId';" 2>&1
Write-Host $output
if ($LASTEXITCODE -ne 0) { throw "psql failed with exit code $LASTEXITCODE" }

Write-Host "Enrollment authority reset complete for $DeviceId" -ForegroundColor Green
