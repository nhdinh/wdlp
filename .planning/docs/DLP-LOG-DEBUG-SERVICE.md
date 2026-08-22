# DLP Log Debug Service — Development-Only Runbook

`DlpLogDebugService` is an independent development debugger from the
`dlp-log-debug-service` crate. It has no enrollment, policy, health,
management registration, or DLP availability dependency. It is not production
packaging, must not be deployed with `Invoke-Client01Runtime.ps1`, and must be
removed when debugging ends. Its HTTP response is unencrypted raw log text, so
use it only in an isolated trusted lab.

The service binds all interfaces, but that is not authorization: a Windows
Firewall `RemoteAddress` boundary and the service TCP-peer allowlist are both
required. Do not add an `Any` or unrestricted `RemoteAddress` rule.

## Configuration contract

Copy `crates/dlp-log-debug-service/config.example.json` to
`C:\ProgramData\DlpLogDebugService\config.json` and replace every placeholder
with lab-specific values. The example uses documentation-only ranges and paths;
do **not** copy `192.0.2.10` or `C:\path\to\logs` unchanged. An empty
`trusted_client_ips` list deliberately selects `LocalhostOnly` mode. Invalid,
missing, or empty configuration also fails closed to `LocalhostOnly` with no
authorized folders.

`allowed_folders` must be absolute, existing, controlled folders. Only an
immediate file child is authorized: nested children, sibling-prefix paths, and
links escaping the folder are denied. The service canonicalizes before opening,
but there is still a canonicalize/open race; do not let ordinary users write an
allowed folder. Only its trusted log writer and administrators may write it.

## 1. Mandatory read-only lab preflight

Run this **before** displaying a privilege manifest or doing any config, fixture,
SCM, ACL, or firewall mutation. It prints only an alias, a boolean, and one
stable code. The code maps one-to-one to the named machine. A failure prohibits
every later mutation.

Collect an authorized lab administrator credential in memory. The credential is
passed directly to WinRM and is never printed, persisted, or included in
evidence. The preflight uses the `lab.local` FQDNs for deterministic DNS and
Negotiate authentication while continuing to validate the expected short
computer names.

```powershell
$labCredential = Get-Credential -Message 'LAB administrator credential'

function Test-DlpLogDebugLabPreflight {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$ClientComputerName,
        [Parameter(Mandatory)] [string]$TrustedProbeComputerName,
        [Parameter(Mandatory)] [string]$UntrustedProbeComputerName,
        [Parameter(Mandatory)] [System.Management.Automation.PSCredential]$Credential,
        [Parameter()] [ValidateNotNullOrEmpty()] [string]$DnsSuffix = 'lab.local'
    )
    $targets = @(
        @{ Alias = $ClientComputerName; Code = 'PREFLIGHT_LAB_CLIENT01_ADMIN_UNREACHABLE'; Kind = 'Client' },
        @{ Alias = $TrustedProbeComputerName; Code = 'PREFLIGHT_LAB_DC01_PROBE_UNREACHABLE'; Kind = 'Probe' },
        @{ Alias = $UntrustedProbeComputerName; Code = 'PREFLIGHT_LAB_DC02_PROBE_UNREACHABLE'; Kind = 'Probe' }
    )
    $allPassed = $true
    foreach ($target in $targets) {
        $passed = $false
        try {
            $remoteName = if ($target.Alias.Contains('.')) {
                $target.Alias
            } else {
                '{0}.{1}' -f $target.Alias, $DnsSuffix
            }
            $expectedComputerName = $target.Alias.Split('.')[0]
            $records = @(Resolve-DnsName -Name $remoteName -Type A -DnsOnly -ErrorAction Stop)
            $validAddress = $false
            foreach ($record in $records) {
                $parsedAddress = $null
                if ($record.IPAddress -and [System.Net.IPAddress]::TryParse($record.IPAddress, [ref]$parsedAddress)) { $validAddress = $true; break }
            }
            if (-not $validAddress) { throw 'dns_invalid' }
            $wsman = Test-WSMan -ComputerName $remoteName -Authentication Negotiate -Credential $Credential -ErrorAction Stop
            if ($null -eq $wsman) { throw 'wsman_null' }
            if ($target.Kind -eq 'Client') {
                $result = Invoke-Command -ComputerName $remoteName -Authentication Negotiate -Credential $Credential -ErrorAction Stop -ScriptBlock {
                    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
                    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
                }
                $passed = ($result -eq $true)
            } else {
                $result = Invoke-Command -ComputerName $remoteName -Authentication Negotiate -Credential $Credential -ErrorAction Stop -ScriptBlock { $env:COMPUTERNAME }
                $passed = ($result -and $result.ToString().Equals($expectedComputerName, [StringComparison]::OrdinalIgnoreCase))
            }
        } catch { $passed = $false }
        [pscustomobject]@{ Machine = $target.Alias; Passed = [bool]$passed; ReasonCode = $(if ($passed) { 'PASS' } else { $target.Code }) }
        if (-not $passed) { $allPassed = $false }
    }
    if ($allPassed) { exit 0 }
    exit 1
}
Test-DlpLogDebugLabPreflight -ClientComputerName LAB-CLIENT01 -TrustedProbeComputerName LAB-DC01 -UntrustedProbeComputerName LAB-DC02 -Credential $labCredential
```

## 2. Build and protect configuration

After a passing preflight, use an authorized LAB-CLIENT01 administrator session.
This is a manual lifecycle only; do not create an installer, provisioning script,
or management deployment.

```powershell
cargo build --release -p dlp-log-debug-service
$serviceHome = 'C:\ProgramData\DlpLogDebugService'
$binary = (Resolve-Path '.\target\release\dlp-log-debug-service.exe').Path
New-Item -ItemType Directory -Path $serviceHome -Force | Out-Null
Copy-Item '.\crates\dlp-log-debug-service\config.example.json' "$serviceHome\config.json" -Force
notepad "$serviceHome\config.json"
icacls $serviceHome /inheritance:r
icacls $serviceHome /grant:r 'SYSTEM:(OI)(CI)M' 'Administrators:(OI)(CI)M'
icacls $serviceHome /remove:g 'Users' 'Authenticated Users' 'Everyone'
```

The config directory must not be writable by ordinary users. Protect each
configured log folder equivalently, retaining only the trusted log writer and
administrators. Do not store protected data in the synthetic fixture.

```powershell
$syntheticFolder = 'C:\DlpLogDebugFixture'
New-Item -ItemType Directory -Path $syntheticFolder -Force | Out-Null
icacls $syntheticFolder /inheritance:r
icacls $syntheticFolder /grant:r 'SYSTEM:(OI)(CI)M' 'Administrators:(OI)(CI)M'
icacls $syntheticFolder /remove:g 'Users' 'Authenticated Users' 'Everyone'
@("alpha`n", "bravo`n", "charlie`n") | Set-Content -LiteralPath "$syntheticFolder\synthetic.log" -NoNewline
```

## 3. Service and firewall lifecycle

Capture the product-service baseline before elevation. `NotInstalled` is a
baseline sentinel, never evidence that DLP availability was exercised.

```powershell
function Get-DlpWindowsServiceBaseline {
    $service = Get-CimInstance Win32_Service -Filter "Name='DlpWindowsService'" -ErrorAction SilentlyContinue
    if ($null -eq $service) { return 'NotInstalled' }
    return ('Installed|{0}|{1}' -f $service.State, $service.StartMode)
}
$baselineBefore = Get-DlpWindowsServiceBaseline
```

Resolve both probe addresses from the preflight names without documenting or
hard-coding private addresses. The two-address rule is a temporary verification window
used only to prove the application-level rejection. Open it after the
fixture and application allowlist are ready, narrow it to LAB-DC01 immediately
after that test, and remove it during cleanup.

```powershell
$trustedProbeAddress = (Resolve-DnsName -Name 'LAB-DC01' -Type A -DnsOnly -ErrorAction Stop | Where-Object IPAddress | Select-Object -First 1 -ExpandProperty IPAddress)
$untrustedProbeAddress = (Resolve-DnsName -Name 'LAB-DC02' -Type A -DnsOnly -ErrorAction Stop | Where-Object IPAddress | Select-Object -First 1 -ExpandProperty IPAddress)
$ruleName = 'DlpLogDebugService Lab Only'
sc.exe create DlpLogDebugService binPath= ('"' + $binary + '"') start= demand
New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow -Program $binary -Protocol TCP -LocalPort 9191 -RemoteAddress @($trustedProbeAddress, $untrustedProbeAddress)
sc.exe start DlpLogDebugService
Get-Service -Name DlpLogDebugService
Get-NetTCPConnection -LocalPort 9191 -State Listen
```

Never widen `RemoteAddress` to `Any`. When LAB-DC02 has received the expected
application denial, narrow the same rule before any further testing:

```powershell
Set-NetFirewallRule -DisplayName $ruleName -RemoteAddress $trustedProbeAddress
```

## 4. Endpoint checks

From LAB-DC01, issue `GET /logs` only for the synthetic direct-child file. URL-encode the
absolute `path` with `[uri]::EscapeDataString`; use a positive tail. A successful
request is HTTP 200, `text/plain`, and exact source text only—no marker, JSON, or
diagnostic header. Omit `tail` to obtain the configured `max_tail_lines` newest
complete lines; an explicit value above that configured maximum is HTTP 400
`invalid_tail`.

```powershell
$path = 'C:\DlpLogDebugFixture\synthetic.log'
$encodedPath = [uri]::EscapeDataString($path)
$response = Invoke-WebRequest -Uri "http://LAB-CLIENT01:9191/logs?path=$encodedPath&tail=2" -UseBasicParsing
if ($response.StatusCode -ne 200 -or $response.Content -ne "bravo`ncharlie`n") { throw 'trusted_raw_tail_failed' }
```

From LAB-DC02 during the short widened window, the same encoded request must be
HTTP 403 with exactly `untrusted_client`, even for a nonexistent path. This proves
peer authorization happens before filesystem inspection. Then apply the narrowing
block above and confirm LAB-DC02 is blocked before HTTP while LAB-DC01 retains 200.
Nested targets must return `forbidden_path`; large or unterminated targets return
only newest complete lines within `262144` bytes. Other stable codes are
`invalid_path`, `file_not_found`, and `read_failed`; never expose OS details.

## 5. Fail-closed fallback and contract result

Replace the config with malformed JSON and restart only this debugger. It must
remain Running but return `untrusted_client` to remote callers and authorize no
previous folders, including from loopback. Restore valid config before cleanup.

```powershell
Set-Content -LiteralPath 'C:\ProgramData\DlpLogDebugService\config.json' -Value '{ malformed'
sc.exe stop DlpLogDebugService
sc.exe start DlpLogDebugService
Get-Service -Name DlpLogDebugService
```

Use this compact result function after steps 1–7. Supply booleans derived from
the preceding checks; it prints no path or response body and exits nonzero unless
every required predicate is true.

```powershell
function Test-DlpLogDebugServiceContract {
    [CmdletBinding()]
    param(
        [bool]$TrustedRawTail,
        [bool]$ApplicationReject,
        [bool]$FirewallReject,
        [bool]$FallbackClosed,
        [bool]$DlpServiceUnchanged
    )
    $service = Get-Service -Name DlpLogDebugService -ErrorAction SilentlyContinue
    $listener = Get-NetTCPConnection -LocalPort 9191 -State Listen -ErrorAction SilentlyContinue
    $result = [pscustomobject]@{
        ServiceRunning = [bool]($service -and $service.Status -eq 'Running')
        AllInterfaceListener = [bool]($listener -and ($listener.LocalAddress -eq '0.0.0.0' -or $listener.LocalAddress -eq '::'))
        TrustedRawTail = $TrustedRawTail
        ApplicationReject = $ApplicationReject
        FirewallReject = $FirewallReject
        FallbackClosed = $FallbackClosed
        DlpServiceUnchanged = $DlpServiceUnchanged
    }
    $result
    if (@($result.PSObject.Properties.Value | Where-Object { -not $_ }).Count -gt 0) { exit 1 }
    exit 0
}
```

## 6. Graceful cleanup

Stop and delete only the debugger service, remove only its firewall rule, and
delete only debugger-owned fixtures. Confirm the listener, process/config
fixture, and rule are gone. Recapture the normalized product baseline and require
byte-for-byte equality. If both are `NotInstalled`, record
`DlpServiceBaseline=NotInstalled` and conclude only that the debugger did not
create or change a DLP service/artifact.

```powershell
sc.exe stop DlpLogDebugService
sc.exe delete DlpLogDebugService
Remove-NetFirewallRule -DisplayName $ruleName
Remove-Item -LiteralPath 'C:\ProgramData\DlpLogDebugService' -Recurse -Force
Remove-Item -LiteralPath $syntheticFolder -Recurse -Force
Get-NetTCPConnection -LocalPort 9191 -State Listen -ErrorAction SilentlyContinue
$baselineAfter = Get-DlpWindowsServiceBaseline
if ($baselineBefore -cne $baselineAfter) { throw 'dlp_service_changed' }
```

## Troubleshooting

| Stable code | Meaning and safe next action |
| --- | --- |
| `PREFLIGHT_LAB_CLIENT01_ADMIN_UNREACHABLE` | LAB-CLIENT01 FQDN DNS, credentialed WSMan, or administrator check failed; make no changes. |
| `PREFLIGHT_LAB_DC01_PROBE_UNREACHABLE` | LAB-DC01 FQDN DNS, credentialed WSMan, or probe-name check failed; make no changes. |
| `PREFLIGHT_LAB_DC02_PROBE_UNREACHABLE` | LAB-DC02 FQDN DNS, credentialed WSMan, or probe-name check failed; make no changes. |
| `untrusted_client` | Check the service allowlist and then the narrowly scoped firewall rule. |
| `forbidden_path` | Use a direct canonical file child of an authorized protected folder. |
| `invalid_tail` | Use a positive tail not larger than the configured maximum. |
| `read_failed` | Use a valid text synthetic fixture; do not expose OS error text. |
