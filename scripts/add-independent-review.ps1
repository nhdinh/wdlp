[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ReviewerPolicyPath,
    [Parameter(Mandatory)][string]$ReviewerRootPath,
    [Parameter(Mandatory)][string]$ArchivalPolicyPath,
    [Parameter(Mandatory)][string]$SignerThumbprint,
    [string]$ReviewStorePath,
    [switch]$NonInteractive,
    [switch]$ValidateIndexOnly
)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$repoRoot=Split-Path -Parent $PSScriptRoot
try{Add-Type -AssemblyName System.Security -ErrorAction Stop}catch{throw 'd48_pkcs_assembly_missing'}
Import-Module (Join-Path $repoRoot 'scripts/evidence/Phase1.Evidence.psm1') -Force
function Get-Sha256Bytes([byte[]]$bytes){$sha=[Security.Cryptography.SHA256]::Create();try{$sha.ComputeHash($bytes)}finally{$sha.Dispose()}}
function ConvertTo-Hex([byte[]]$bytes){([BitConverter]::ToString($bytes)-replace '-','')}
function Test-IndependentReviewIndex($index,$indexPath){
 if($index.schema_version-ne'phase1-independent-review-index/v1'){throw 'd48_index_schema_invalid'};$entries=@($index.generations);$seen=@{};$previous='';for($i=0;$i-lt$entries.Count;$i++){$entry=$entries[$i];$ordinal=$i+1;if([string]$entry.generation_digest-notmatch'^[a-f0-9]{64}$'-or[string]$entry.id-ne('{0:000000}-{1}'-f$ordinal,([string]$entry.generation_digest).Substring(0,16))){throw 'd48_index_order_invalid'};if($seen.ContainsKey([string]$entry.id)-or[string]$entry.path-ne"$($entry.id)/generation.json"-or[IO.Path]::IsPathRooted([string]$entry.path)-or[string]$entry.path-match'(^|[\\/])\.\.([\\/]|$)'){throw 'd48_index_path_invalid'};$seen[[string]$entry.id]=$true;if([string]$entry.previous_generation_digest-ne$previous){throw 'd48_index_predecessor_invalid'};$generationPath=Join-Path (Split-Path $indexPath -Parent) ([string]$entry.path);if(!(Test-Path -LiteralPath $generationPath -PathType Leaf)){throw 'd48_index_generation_missing'};$bytes=[IO.File]::ReadAllBytes($generationPath);$actual=(ConvertTo-Hex (Get-Sha256Bytes $bytes)).ToLowerInvariant();if($actual-ne[string]$entry.generation_digest){throw 'd48_index_generation_digest_invalid'};try{$generation=[Text.Encoding]::UTF8.GetString($bytes)|ConvertFrom-Json;$canonical=ConvertTo-Phase1CanonicalBytes $generation;$commitmentBytes=[Convert]::FromBase64String([string]$generation.commitment_base64);$commitment=[Text.Encoding]::UTF8.GetString($commitmentBytes)|ConvertFrom-Json}catch{throw 'd48_index_generation_invalid'};if($generation.schema_version-ne'phase1-independent-review-generation/v1'-or -not [Convert]::ToBase64String($canonical).Equals([Convert]::ToBase64String($bytes))-or -not [Convert]::ToBase64String((ConvertTo-Phase1CanonicalBytes $commitment)).Equals([Convert]::ToBase64String($commitmentBytes))){throw 'd48_index_generation_noncanonical'};if([string]$commitment.previous_generation_digest-ne$previous-or[string]$commitment.commit_id-notmatch'^[a-f0-9]{40}$'){throw 'd48_index_commitment_link_invalid'};$previous=[string]$entry.generation_digest};$store=Split-Path $indexPath -Parent;$directories=@(Get-ChildItem $store -Directory|?{$_.Name-notlike'.staging-*'});if($directories.Count-ne$entries.Count-or@($directories|?{!$seen.ContainsKey($_.Name)}).Count){throw 'd48_index_truncation_or_fork'};$previous
}
if(!$ReviewStorePath){$ReviewStorePath=Join-Path $repoRoot 'evidence/phase1/independent-reviews'}
if($ValidateIndexOnly){$indexPath=Join-Path $ReviewStorePath 'index.json';try{$index=Get-Content -Raw $indexPath|ConvertFrom-Json}catch{throw 'd48_index_parse_invalid'};$head=Test-IndependentReviewIndex $index $indexPath;Write-Host "D-48 index valid: head=$head";exit 0}
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
$mutexName='Global\Phase1-D48-'+(ConvertTo-Hex (Get-Sha256Bytes ([Text.Encoding]::UTF8.GetBytes([IO.Path]::GetFullPath($ReviewStorePath))))).Substring(0,24)
$mutex=[Threading.Mutex]::new($false,$mutexName);if(!$mutex.WaitOne([TimeSpan]::FromSeconds(30))){throw 'd48_publication_lock_timeout'}
try{
 New-Item -ItemType Directory -Force $ReviewStorePath|Out-Null
 Get-ChildItem $ReviewStorePath -Directory -Filter '.staging-*' -ErrorAction SilentlyContinue|Remove-Item -Recurse -Force
 $indexPath=Join-Path $ReviewStorePath 'index.json';try{$index=if(Test-Path $indexPath){Get-Content -Raw $indexPath|ConvertFrom-Json}else{[pscustomobject]@{schema_version='phase1-independent-review-index/v1';generations=@()}}}catch{throw 'd48_index_parse_invalid'}
 $previous=Test-IndependentReviewIndex $index $indexPath
 $signer=[ordered]@{identity=$identity;machine=$machine;role=[string]$authorized[0].role;subject=$cert.Subject;thumbprint=$thumbprint;policy_id=[string]$policy.policy_id}
 $commitment=Get-Phase1ReviewCommitment -RepositoryRoot $repoRoot -ReviewerPolicyPath $ReviewerPolicyPath -ReviewerRootPath $ReviewerRootPath -ArchivalPolicyPath $ArchivalPolicyPath -Signer $signer -PreviousGenerationDigest $previous
 $canonical=ConvertTo-Phase1CanonicalBytes $commitment
 if(!$NonInteractive){$answer=Read-Host 'Type YES to sign and publish this immutable D-48 generation';if($answer-cne'YES'){throw 'd48_confirmation_rejected'}}
 $cms=[Security.Cryptography.Pkcs.SignedCms]::new([Security.Cryptography.Pkcs.ContentInfo]::new($canonical),$true);$cmsSigner=[Security.Cryptography.Pkcs.CmsSigner]::new($cert);$cmsSigner.IncludeOption='EndCertOnly';$cms.ComputeSignature($cmsSigner)
 $generation=[ordered]@{schema_version='phase1-independent-review-generation/v1';commitment_base64=[Convert]::ToBase64String($canonical);signature_cms_base64=[Convert]::ToBase64String($cms.Encode())};$bytes=ConvertTo-Phase1CanonicalBytes $generation
 $digest=(ConvertTo-Hex (Get-Sha256Bytes $bytes)).ToLowerInvariant();$id='{0:000000}-{1}'-f(@($index.generations).Count+1),$digest.Substring(0,16)
 $stage=Join-Path $ReviewStorePath ".staging-$([guid]::NewGuid())";New-Item -ItemType Directory $stage|Out-Null;[IO.File]::WriteAllBytes((Join-Path $stage 'generation.json'),$bytes);Move-Item $stage (Join-Path $ReviewStorePath $id)
 $entries=@($index.generations)+@([ordered]@{id=$id;path="$id/generation.json";generation_digest=$digest;previous_generation_digest=$previous});$newIndex=[ordered]@{schema_version='phase1-independent-review-index/v1';generations=$entries}
 $tmp="$indexPath.tmp-$([guid]::NewGuid())";[IO.File]::WriteAllBytes($tmp,(ConvertTo-Phase1CanonicalBytes $newIndex));Move-Item -Force $tmp $indexPath;Write-Host "D-48 generation published: $id"
}finally{$mutex.ReleaseMutex();$mutex.Dispose();$cert.Dispose()}
