# 1. Get the current computer's Active Directory Domain naming context
$DomainDN = ([ADSI]"LDAP://RootDSE").Get("configurationNamingContext")

# 2. Build the AD path to the Certification Authorities container
$LdapPath = "LDAP://CN=Certification Authorities,CN=Public Key Services,CN=Services,$DomainDN"
$Searcher = [DirectoryServices.DirectorySearcher]::new([ADSI]$LdapPath)

# 3. Pull all authority objects
$Results = $Searcher.FindAll()

# 4. Loop through and export the certificates to your Desktop
foreach ($Result in $Results) {
    $Entry = $Result.GetDirectoryEntry()
    $CAName = $Entry.Properties["name"].Value
    $CertBytes = $Entry.Properties["cACertificate"].Value

    if ($CertBytes) {
        Write-Host "Found Authority Certificate for: $CAName"
        
        # Instantiate the certificate using the raw byte array
        $Cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertBytes)
        $OutputPath = "$env:USERPROFILE\Desktop\$CAName`_RootCA.cer"
        
        # FIXED: Changed the explicit type acceleration to a simple string "Cert"
        [System.IO.File]::WriteAllBytes($OutputPath, $Cert.Export("Cert"))
        
        Write-Host "Successfully exported to: $OutputPath" -ForegroundColor Green
    }
}
