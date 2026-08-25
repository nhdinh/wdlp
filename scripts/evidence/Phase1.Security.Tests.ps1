[CmdletBinding()]param([ValidateSet('All','Publication','Verifier','FinalGate')][string]$Focus='All')
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$root=Split-Path -Parent (Split-Path -Parent $PSScriptRoot);$manifest=Join-Path $root 'evidence/phase1/security-closure.yaml';$verifier=Join-Path $root 'scripts/verify-phase1-security.ps1';$capture=Join-Path $root 'scripts/add-security-closure-review.ps1'
function Assert($condition,$message){if(!$condition){throw "FAILED: $message"}}
function FileHash($path){$s=[Security.Cryptography.SHA256]::Create();try{([BitConverter]::ToString($s.ComputeHash([IO.File]::ReadAllBytes($path)))).Replace('-','')}finally{$s.Dispose()}}
function HashText($value){$s=[Security.Cryptography.SHA256]::Create();try{$json=($value|ConvertTo-Json -Depth 20 -Compress)-replace"`r`n","`n";$bytes=[Text.UTF8Encoding]::new($false).GetBytes($json);([BitConverter]::ToString($s.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$s.Dispose()}}
function Body($a){[ordered]@{threat_id=[string]$a.threat_id;payload_digest=[string]$a.payload_digest;reviewer_identity=$a.reviewer_identity;review_utc=[string]$a.review_utc;procedure_version=[string]$a.procedure_version;environment_fingerprint=$a.environment_fingerprint;previous_attestation_digest=[string]$a.previous_attestation_digest}}
function Invoke-Verify($path,[string[]]$extra=@()){$out=[IO.Path]::GetTempFileName();$err=[IO.Path]::GetTempFileName();try{$args=@('-NoProfile','-ExecutionPolicy','Bypass','-File',$verifier,'-ClosurePath',$path,'-DiagnosticFormat','Json')+$extra;$p=Start-Process powershell -ArgumentList $args -Wait -PassThru -NoNewWindow -RedirectStandardOutput $out -RedirectStandardError $err;[pscustomobject]@{Exit=$p.ExitCode;Out=(Get-Content -Raw $out);Err=(Get-Content -Raw $err)}}finally{Remove-Item $out,$err -Force -ErrorAction SilentlyContinue}}
function Mutate([scriptblock]$change){$p=Join-Path $env:TEMP("closure-$([guid]::NewGuid()).json");$c=Get-Content -Raw $manifest|ConvertFrom-Json;&$change $c;[IO.File]::WriteAllText($p,($c|ConvertTo-Json -Depth 20),[Text.UTF8Encoding]::new($false));$p}
function Start-Publisher($path,$threat,$thumbprint,$policyPath,[string[]]$extra=@()){
 $stdin=Join-Path $env:TEMP("publisher-stdin-$([guid]::NewGuid()).txt");$stdout=Join-Path $env:TEMP("publisher-out-$([guid]::NewGuid()).txt");$stderr=Join-Path $env:TEMP("publisher-err-$([guid]::NewGuid()).txt")
 [IO.File]::WriteAllText($stdin,"YES`r`n",[Text.UTF8Encoding]::new($false));$args=@('-NoProfile','-ExecutionPolicy','Bypass','-File',$capture,'-ClosurePath',$path,'-ThreatId',$threat,'-ReviewerPolicyPath',$policyPath,'-SignerThumbprint',$thumbprint)+$extra
 $process=Start-Process powershell -ArgumentList $args -PassThru -NoNewWindow -RedirectStandardInput $stdin -RedirectStandardOutput $stdout -RedirectStandardError $stderr
 [pscustomobject]@{Process=$process;Input=$stdin;Output=$stdout;Error=$stderr}
}
function Wait-Publisher($publisher,[int]$timeoutSeconds=15){
 if(!$publisher.Process.WaitForExit($timeoutSeconds*1000)){try{$publisher.Process.Kill()}catch{};throw 'FAILED: publisher timed out'}
 [pscustomobject]@{Exit=$publisher.Process.ExitCode;Out=(Get-Content -Raw $publisher.Output -ErrorAction SilentlyContinue);Err=(Get-Content -Raw $publisher.Error -ErrorAction SilentlyContinue)}
}
function Remove-Publisher($publisher){Remove-Item $publisher.Input,$publisher.Output,$publisher.Error -Force -ErrorAction SilentlyContinue}
function New-PublicationTestCertificate {
 $rsa=[Security.Cryptography.RSA]::Create(2048);$request=[Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=Phase1 Publication Test Reviewer',$rsa,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
 $request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new([Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature,$true));$certificate=$request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddMinutes(-5),[DateTimeOffset]::UtcNow.AddHours(1));$persisted=[Security.Cryptography.X509Certificates.X509Certificate2]::new($certificate.Export([Security.Cryptography.X509Certificates.X509ContentType]::Pfx),$null,[Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet)
 $store=[Security.Cryptography.X509Certificates.X509Store]::new('My',[Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser);try{$store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite);$store.Add($persisted)}finally{$store.Dispose();$certificate.Dispose();$rsa.Dispose()};$persisted
}
function Remove-PublicationTestCertificate($certificate){$store=[Security.Cryptography.X509Certificates.X509Store]::new('My',[Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser);try{$store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite);$store.Remove($certificate)}finally{$store.Dispose();$certificate.Dispose()}}

if($Focus-in@('All','Publication')){
 $publicationRoot=Join-Path $env:TEMP("phase1-publication-$([guid]::NewGuid())");New-Item -ItemType Directory -Path $publicationRoot|Out-Null
 $certificate=New-PublicationTestCertificate
 $policyPath=Join-Path $publicationRoot 'reviewer-policy.json';$policy=[ordered]@{procedure_version='phase1-publication-test/v1';reviewers=@([ordered]@{thumbprint=$certificate.Thumbprint;identity='publication-test-reviewer';machine_identity=$env:COMPUTERNAME;role='independent_security_reviewer';domain_network_identity='test.local'})};[IO.File]::WriteAllText($policyPath,($policy|ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))
 try{
  $threat='T-01-15-03'
  $driftPath=Join-Path $publicationRoot 'drift.json';Copy-Item $manifest $driftPath;$barrier=Join-Path $publicationRoot 'drift-barrier';New-Item -ItemType File -Path "$barrier.wait"|Out-Null
  $driftPublisher=Start-Publisher $driftPath $threat $certificate.Thumbprint $policyPath @('-PublicationBarrierPath',$barrier)
  try{for($i=0;$i-lt150-and!(Test-Path $barrier);$i++){Start-Sleep -Milliseconds 50};Assert (Test-Path $barrier) 'drift publisher acquired publication lock';$drift=Get-Content -Raw $driftPath|ConvertFrom-Json;(@($drift.records|Where-Object threat_id -eq $threat))[0].mitigation_assertion+=' concurrent mutation';[IO.File]::WriteAllText($driftPath,($drift|ConvertTo-Json -Depth 20),[Text.UTF8Encoding]::new($false));$mutatedHash=FileHash $driftPath;Remove-Item "$barrier.wait" -Force;$driftResult=Wait-Publisher $driftPublisher;Assert ($driftResult.Exit-ne0) 'protected-field drift is rejected';Assert (($driftResult.Out+$driftResult.Err)-match"publication_conflict:$threat") 'protected-field drift has stable diagnostic';Assert ((FileHash $driftPath)-eq$mutatedHash) 'rejected drift leaves manifest byte-identical'}finally{Remove-Item "$barrier.wait" -Force -ErrorAction SilentlyContinue;Remove-Publisher $driftPublisher}

  $racePath=Join-Path $publicationRoot 'race.json';Copy-Item $manifest $racePath;$raceBarrier=Join-Path $publicationRoot 'race-barrier';New-Item -ItemType File -Path "$raceBarrier.wait"|Out-Null
  $first=Start-Publisher $racePath $threat $certificate.Thumbprint $policyPath @('-PublicationBarrierPath',$raceBarrier)
  try{for($i=0;$i-lt150-and!(Test-Path $raceBarrier);$i++){Start-Sleep -Milliseconds 50};Assert (Test-Path $raceBarrier) 'first publisher acquired publication lock';$second=Start-Publisher $racePath $threat $certificate.Thumbprint $policyPath;Start-Sleep -Milliseconds 500;Remove-Item "$raceBarrier.wait" -Force;$firstResult=Wait-Publisher $first;$secondResult=Wait-Publisher $second;Assert ($firstResult.Exit-eq0) 'one concurrent publisher succeeds';Assert ($secondResult.Exit-ne0) 'stale concurrent publisher is rejected';Assert (($secondResult.Out+$secondResult.Err)-match"publication_conflict:$threat") 'stale publisher has stable diagnostic';$race=Get-Content -Raw $racePath|ConvertFrom-Json;Assert (@((@($race.records|Where-Object threat_id -eq $threat))[0].attestations).Count-gt0) 'one attestation remains published'}finally{Remove-Item "$raceBarrier.wait" -Force -ErrorAction SilentlyContinue;Remove-Publisher $first;if($second){Remove-Publisher $second}}

  $crashPath=Join-Path $publicationRoot 'crash.json';Copy-Item $manifest $crashPath;$beforeCrash=FileHash $crashPath;$crash=Start-Publisher $crashPath $threat $certificate.Thumbprint $policyPath @('-CrashBeforeReplace');try{$crashResult=Wait-Publisher $crash;Assert ($crashResult.Exit-ne0) 'injected pre-replace crash fails';Assert (($crashResult.Out+$crashResult.Err)-match'injected_crash_before_replace') 'injected crash has stable diagnostic';Assert ((FileHash $crashPath)-eq$beforeCrash) 'injected crash preserves original manifest bytes';Assert (@(Get-ChildItem $publicationRoot -Filter '.crash.json.*.tmp').Count-eq0) 'injected crash removes publication temporary files'}finally{Remove-Publisher $crash}
 }finally{Remove-PublicationTestCertificate $certificate;Remove-Item $publicationRoot -Recurse -Force -ErrorAction SilentlyContinue}
}

if($Focus-eq'Publication'){Write-Host 'Phase 1 publication security tests passed.';exit 0}

$base=Invoke-Verify $manifest;Assert ($base.Exit-eq0) 'canonical pre-sign-off validation'
$missing=Invoke-Verify $manifest @('-RequireSignedOff');Assert ($missing.Exit-eq2) 'signed-off mode requires external trust inputs';Assert (($missing.Out|ConvertFrom-Json).error-eq'trusted_root_missing') 'stable missing-root diagnostic'
$fakeRoot=Join-Path $env:TEMP("root-$([guid]::NewGuid()).cer");$fakePolicy=Join-Path $env:TEMP("policy-$([guid]::NewGuid()).json");[IO.File]::WriteAllText($fakeRoot,'manifest copied trust cannot substitute',[Text.UTF8Encoding]::new($false));[IO.File]::WriteAllText($fakePolicy,'{}',[Text.UTF8Encoding]::new($false));try{$bad=Invoke-Verify $manifest @('-RequireSignedOff','-TrustedRootPath',$fakeRoot,'-ReviewerPolicyPath',$fakePolicy);Assert ($bad.Exit-eq2) 'malformed external trust inputs fail closed'}finally{Remove-Item $fakeRoot,$fakePolicy -Force}

# Fully recompute attacker-controlled hashes after forging reviewer provenance. A detached signature cannot be recomputed.
$forged=Mutate {param($c)$r=$c.records[0];$r.attestations[0].reviewer_identity.name='forged\reviewer';$prior='';foreach($a in @($r.attestations)){$a.previous_attestation_digest=$prior;$a.attestation_digest=HashText (Body $a);$prior=$a.attestation_digest}}
try{$fakeRoot=Join-Path $env:TEMP("root-$([guid]::NewGuid()).cer");$fakePolicy=Join-Path $env:TEMP("policy-$([guid]::NewGuid()).json");[IO.File]::WriteAllText($fakeRoot,'x');[IO.File]::WriteAllText($fakePolicy,'{}');$forgedResult=Invoke-Verify $forged @('-RequireSignedOff','-TrustedRootPath',$fakeRoot,'-ReviewerPolicyPath',$fakePolicy);Assert ($forgedResult.Exit-ne0) 'recomputed forgery rejected'}finally{Remove-Item $forged,$fakeRoot,$fakePolicy -Force -ErrorAction SilentlyContinue}

$verifierSource=Get-Content -Raw $verifier;$finalSource=Get-Content -Raw (Join-Path $root 'scripts/verify-phase1.ps1')
Assert ($verifierSource-match'SignedCms' -and $verifierSource-match'CheckSignature') 'detached CMS verification is wired'
Assert ($verifierSource-match'Add-Type\s+-AssemblyName\s+System\.Security' -and $verifierSource-match'pkcs_runtime_unavailable') 'verifier loads PKCS runtime explicitly with a distinct failure diagnostic'
Assert ($finalSource-match'TrustedRootPath' -and $finalSource-match'ReviewerPolicyPath' -and $finalSource-match'RequireSignedOff') 'FinalGate forwards authenticated trust inputs'
Assert ($finalSource-match'manifest_digest' -and $finalSource-match'reviewer_policy_identity') 'FinalGate reports matching identities'

# Capture must display every protected field and cannot bypass affirmative review with a switch.
$captureSource=Get-Content -Raw $capture
foreach($field in @('threat_id','disposition','severity','mitigation_assertion','implementation_refs','evidence_attempt_ids','required_machine_roles','artifact_refs','procedure_version','environment_fingerprint')){Assert ($captureSource-match[regex]::Escape($field)) "capture protects field $field"}
Assert ($captureSource-notmatch'ConfirmEach') 'optional confirmation bypass removed'
Assert ($captureSource-match'Read-Host' -and $captureSource-match"-ne\s*'YES'") 'exact affirmative input required'
Assert ($captureSource-match'SignedCms' -and $captureSource-match'ComputeSignature') 'reviewer-controlled CMS signing wired'
Assert ($captureSource-match'Add-Type\s+-AssemblyName\s+System\.Security' -and $captureSource-match'pkcs_runtime_unavailable') 'capture loads PKCS runtime explicitly and fails closed when unavailable'

$tmp=Join-Path $env:TEMP("closure-$([guid]::NewGuid()).json");Copy-Item $manifest $tmp;try{$before=FileHash $tmp;&powershell -NoProfile -ExecutionPolicy Bypass -File $capture -ClosurePath $tmp -ThreatId T-01-15-03 -DryRun;$exit=$LASTEXITCODE;Assert ($exit-eq0) 'dry run succeeds';Assert ((FileHash $tmp)-eq$before) 'dry run byte-identical';&powershell -NoProfile -ExecutionPolicy Bypass -File $capture -ClosurePath $tmp -ThreatId T-01-15-03 -WhatIf 2>$null;Assert ((FileHash $tmp)-eq$before) 'WhatIf byte-identical'}finally{Remove-Item $tmp -Force}

# Publication source contract: named cross-process mutex, locked re-read, flush-through, atomic replace, and test hooks.
foreach($needle in @('Mutex','PublicationBarrierPath','CrashBeforeReplace','Flush($true)','Replace(')){Assert ($captureSource-match[regex]::Escape($needle)) "publication contract includes $needle"}
Assert ($captureSource-match'Get-PublicationMutexName' -and $captureSource-match'WaitOne') 'all publishers serialize on the canonical manifest path'
Write-Host 'Phase 1 security closure tests passed.'
