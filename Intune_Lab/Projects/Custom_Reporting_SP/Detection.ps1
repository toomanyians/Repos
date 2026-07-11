$Thumbprint = "<THUMBPRINT>"
$Store = Get-ChildItem -Path Cert:\LocalMachine\My
$Cert = $Store | Where-Object { $_.Thumbprint -eq $Thumbprint }
if ($Cert) {
    Write-Host "Detected"
    exit 0
} else {
    Write-Host "Not Detected"
    exit 1
}
