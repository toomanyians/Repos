# ------------------------------------------------------------
#
# Configuration
#
# ------------------------------------------------------------
$Thumbprint = "<THUMBPRINT>"
# ------------------------------------------------------------
# Locate the certificate by thumbprint
# ------------------------------------------------------------
$Cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Thumbprint -eq $Thumbprint}
# ------------------------------------------------------------
# Delete it if found
# ------------------------------------------------------------
if ($Cert) {
    Write-Host "Detected"
    exit 0
} else {
    Write-Host "Not Detected"
    exit 1
}
