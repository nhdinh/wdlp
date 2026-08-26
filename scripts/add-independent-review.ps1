[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ReviewerPolicyPath,
    [Parameter(Mandatory)][string]$ReviewerRootPath,
    [Parameter(Mandatory)][string]$ArchivalPolicyPath,
    [Parameter(Mandatory)][string]$SignerThumbprint,
    [string]$ReviewStorePath,
    [switch]$NonInteractive
)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$repoRoot=Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $repoRoot 'scripts/evidence/Phase1.Evidence.psm1') -Force
if(!$ReviewStorePath){$ReviewStorePath=Join-Path $repoRoot 'evidence/phase1/independent-reviews'}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name;$machine=$env:COMPUTERNAME;$thumbprint=$SignerThumbprint.Replace(' ','').ToUpperInvariant()
$policy=Get-Content -Raw $ReviewerPolicyPath|ConvertFrom-Json;$archive=Get-Content -Raw $ArchivalPolicyPath|ConvertFrom-Json
$authorized=@($policy.reviewers|?{$_.identity-eq$identity-and$_.machine_identity-eq$machine-and$_.thumbprint.Replace(' ','').ToUpperInvariant()-eq$thumbprint})
if($authorized.Count-ne1){throw 'd48_observed_context_not_authorized'}
$store=[Security.Cryptography.X509Certificates.X509Store]::new('My',[Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
try{$store.Open('ReadOnly');$certs=@($store.Certificates|?{$_.Thumbprint.Replace(' ','').ToUpperInvariant()-eq$thumbprint-and$_.HasPrivateKey})}finally{$store.Close()}
if($certs.Count-ne1){throw 'd48_signer_certificate_count_invalid'};$cert=$certs[0]
$usage=@($cert.Extensions|?{$_.Oid.Value-eq'2.5.29.15'});if(!$usage-or-($usage[0].KeyUsages-band[Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature)-eq0){throw 'd48_signer_wrong_key_usage'}
foreach($reviewer in @($archive.reviewers)){
    $archivalSubject = if($reviewer.PSObject.Properties['subject']){[string]$reviewer.subject}else{''}
    if($reviewer.identity-eq$identity-or$archivalSubject-eq$cert.Subject-or$reviewer.thumbprint.Replace(' ','').ToUpperInvariant()-eq$thumbprint){throw 'd48_archival_signer_reuse'}
}
$mutexName='Global\Phase1-D48-'+([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes([IO.Path]::GetFullPath($ReviewStorePath))))).Substring(0,24)
$mutex=[Threading.Mutex]::new($false,$mutexName);if(!$mutex.WaitOne([TimeSpan]::FromSeconds(30))){throw 'd48_publication_lock_timeout'}
try{
 New-Item -ItemType Directory -Force $ReviewStorePath|Out-Null
 Get-ChildItem $ReviewStorePath -Directory -Filter '.staging-*' -ErrorAction SilentlyContinue|Remove-Item -Recurse -Force
 $indexPath=Join-Path $ReviewStorePath 'index.json';$index=if(Test-Path $indexPath){Get-Content -Raw $indexPath|ConvertFrom-Json}else{[pscustomobject]@{schema_version='phase1-independent-review-index/v1';generations=@()}}
 $previous=if(@($index.generations).Count){[string]@($index.generations)[-1].generation_digest}else{''}
 $signer=[ordered]@{identity=$identity;machine=$machine;role=[string]$authorized[0].role;subject=$cert.Subject;thumbprint=$thumbprint;policy_id=[string]$policy.policy_id}
 $commitment=Get-Phase1ReviewCommitment -RepositoryRoot $repoRoot -ReviewerPolicyPath $ReviewerPolicyPath -ReviewerRootPath $ReviewerRootPath -ArchivalPolicyPath $ArchivalPolicyPath -Signer $signer -PreviousGenerationDigest $previous
 $canonical=ConvertTo-Phase1CanonicalBytes $commitment
 if(!$NonInteractive){$answer=Read-Host 'Type YES to sign and publish this immutable D-48 generation';if($answer-cne'YES'){throw 'd48_confirmation_rejected'}}
 $cms=[Security.Cryptography.Pkcs.SignedCms]::new([Security.Cryptography.Pkcs.ContentInfo]::new($canonical),$true);$cmsSigner=[Security.Cryptography.Pkcs.CmsSigner]::new($cert);$cmsSigner.IncludeOption='EndCertOnly';$cms.ComputeSignature($cmsSigner)
 $generation=[ordered]@{schema_version='phase1-independent-review-generation/v1';commitment_base64=[Convert]::ToBase64String($canonical);signature_cms_base64=[Convert]::ToBase64String($cms.Encode())};$bytes=ConvertTo-Phase1CanonicalBytes $generation
 $digest=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant();$id='{0:000000}-{1}'-f(@($index.generations).Count+1),$digest.Substring(0,16)
 $stage=Join-Path $ReviewStorePath ".staging-$([guid]::NewGuid())";New-Item -ItemType Directory $stage|Out-Null;[IO.File]::WriteAllBytes((Join-Path $stage 'generation.json'),$bytes);Move-Item $stage (Join-Path $ReviewStorePath $id)
 $entries=@($index.generations)+@([ordered]@{id=$id;path="$id/generation.json";generation_digest=$digest;previous_generation_digest=$previous});$newIndex=[ordered]@{schema_version='phase1-independent-review-index/v1';generations=$entries}
 $tmp="$indexPath.tmp-$([guid]::NewGuid())";[IO.File]::WriteAllBytes($tmp,(ConvertTo-Phase1CanonicalBytes $newIndex));Move-Item -Force $tmp $indexPath;Write-Host "D-48 generation published: $id"
}finally{$mutex.ReleaseMutex();$mutex.Dispose();$cert.Dispose()}
