$ErrorActionPreference = "Stop"
$cimOption = New-CimSessionOption -UseSSL
$session = New-CimSession -ComputerName "LAB-CLIENT01.lab.local" -Authentication Kerberos -SessionOption $cimOption
$product = @(Get-CimInstance -CimSession $session -ClassName Win32_ComputerSystemProduct)
$bios = @(Get-CimInstance -CimSession $session -ClassName Win32_BIOS)
$logical = @(Get-CimInstance -CimSession $session -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'")
$partition = @($logical | Get-CimAssociatedInstance -Association Win32_LogicalDiskToPartition)
$disk = @($partition | Get-CimAssociatedInstance -Association Win32_DiskDriveToDiskPartition)
[pscustomobject]@{
    product_count = $product.Count
    product_uuid = $product[0].UUID
    bios_count = $bios.Count
    bios_serial = $bios[0].SerialNumber
    logical_count = $logical.Count
    logical_deviceid = $logical[0].DeviceID
    partition_count = $partition.Count
    disk_count = $disk.Count
    disk_serial = $disk[0].SerialNumber
} | ConvertTo-Json -Depth 3 | Set-Content -Path C:\dlp\server\fingerprint-debug.json -Encoding UTF8
Remove-CimSession -CimSession $session
