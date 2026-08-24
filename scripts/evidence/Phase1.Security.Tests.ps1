[CmdletBinding()]param()
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$root=Split-Path -Parent (Split-Path -Parent $PSScriptRoot);$manifest=Join-Path $root 'evidence/phase1/security-closure.yaml';$verifier=Join-Path $root 'scripts/verify-phase1-security.ps1';$security=Join-Path $root '.planning/phases/01-first-encrypted-drive-vertical-slice/01-SECURITY.md'
function Invoke-Verify($path,[switch]$Signed){$out=[IO.Path]::GetTempFileName();$err=[IO.Path]::GetTempFileName();try{$args=@('-NoProfile','-ExecutionPolicy','Bypass','-File',$verifier,'-ClosurePath',$path,'-DiagnosticFormat','Json');if($Signed){$args+=@('-RequireSignedOff','-SecurityPath',$security)};$p=Start-Process powershell -ArgumentList $args -Wait -PassThru -NoNewWindow -RedirectStandardOutput $out -RedirectStandardError $err;[pscustomobject]@{Exit=$p.ExitCode;Out=(Get-Content -Raw $out);Err=(Get-Content -Raw $err)}}finally{Remove-Item $out,$err -Force -ErrorAction SilentlyContinue}}
function Assert($condition,$message){if(!$condition){throw"FAILED: $message"}}
function FileHash($path){$s=[Security.Cryptography.SHA256]::Create();try{([BitConverter]::ToString($s.ComputeHash([IO.File]::ReadAllBytes($path)))).Replace('-','')}finally{$s.Dispose()}}
function Mutate([scriptblock]$change){$p=Join-Path $env:TEMP("closure-$([guid]::NewGuid()).json");$c=Get-Content -Raw $manifest|ConvertFrom-Json;&$change $c;[IO.File]::WriteAllText($p,($c|ConvertTo-Json -Depth 20),[Text.UTF8Encoding]::new($false));$p}
$base=Invoke-Verify $manifest;Assert ($base.Exit-eq0) 'canonical pre-sign-off validation'
$signed=Invoke-Verify $manifest -Signed;Assert ($signed.Exit-eq3) 'signed-off must fail with validation exit 3';Assert ([string]::IsNullOrWhiteSpace($signed.Err)) 'expected empty stderr';$j=$signed.Out|ConvertFrom-Json;$expected=@('T-01-15-03','T-01-16-02','T-01-16-03','T-01-18-SC','T-01-20-01','T-01-20-02','T-01-20-05');$d=@($j.diagnostics);Assert ($j.status-eq'validation_failed'-and$d.Count-eq7) 'exactly seven diagnostics';Assert (@($d|Where-Object { $_.code -ne 'unsigned_current_attestation' }).Count-eq0) 'only unsigned-current diagnostics';Assert (@(Compare-Object ($expected|Sort-Object) (@($d.threat_id)|Sort-Object)).Count-eq0) 'exact seven threat IDs'
$cases=@(
 @{Name='payload reseal';Change={param($c)$c.records[0].mitigation_assertion+=' tampered'}},
 @{Name='attestation payload';Change={param($c)$c.records[0].attestations[0].payload_digest=('0'*64)}},
 @{Name='attestation threat';Change={param($c)$c.records[0].attestations[0].threat_id='T-01-15-02'}},
 @{Name='attestation identity';Change={param($c)$c.records[0].attestations[0].reviewer_identity.name='forged\reviewer'}},
 @{Name='attestation timestamp';Change={param($c)$c.records[0].attestations[0].review_utc='2030-01-01T00:00:00Z'}},
 @{Name='attestation predecessor';Change={param($c)$c.records[0].attestations[0].previous_attestation_digest=('f'*64)}},
 @{Name='attestation deletion';Change={param($c)$c.records[0].attestations=@()}}
)
foreach($case in $cases){$p=Mutate $case.Change;try{$r=Invoke-Verify $p -Signed;Assert ($r.Exit-eq3) "$($case.Name) rejected"}finally{Remove-Item $p -Force}}
$capture=Join-Path $root 'scripts/add-security-closure-review.ps1';$tmp=Join-Path $env:TEMP("closure-$([guid]::NewGuid()).json");Copy-Item $manifest $tmp;try{$before=FileHash $tmp;$oldPreference=$ErrorActionPreference;$ErrorActionPreference='Continue';&powershell -NoProfile -ExecutionPolicy Bypass -File $capture -ClosurePath $tmp -ThreatId T-01-15-03 -DryRun 2>$null;$captureExit=$LASTEXITCODE;$ErrorActionPreference=$oldPreference;Assert ((FileHash $tmp)-eq$before) 'capture failure/dry-run must not mutate manifest';if($env:COMPUTERNAME-eq'hungdinh-lt'){Assert ($captureExit-ne0) 'developer workstation review identity rejected'}}finally{Remove-Item $tmp -Force}
Write-Host "Phase 1 security closure tests passed ($($cases.Count+4) checks)."
