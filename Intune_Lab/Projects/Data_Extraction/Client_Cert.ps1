# ------------------------------------------------------------
#
# Configuration
#
# ------------------------------------------------------------
#---------------------------------
# Trusted Root CA
#---------------------------------
# Thumbprint of the required Trusted Root CA
# If the client certificate does not need to be signed, leave this blank
$RootThumbprint = "<ROOT CA THUMBPRINT>"
# Path to the PFX for the trusted root if it needs to be imported
$RootPfxPath = "<FULL ROOT CA PFX PATH>"
# PFX password (replace with your actual password)
$RootPfxPassword = "<ROOT PFX PASSWORD>"
#---------------------------------
# Client certificate
#---------------------------------
$ClientName = "<LEAF CERT NAME>"
$ClientPassword = "<LEAF CERT PASSWORD>"
$DNSName = "<YOUR DOMAIN NAME>"
#
# ------------------------------------------------------------
# Check for Trusted Root CA certificate before proceeding
# ------------------------------------------------------------
# Set semaphores for later use
$SignCert = $false
$ImportRequired = $false
#
if ($RootThumbprint.Length -gt 0) {
    # Set the semaphore to require client certificate signing
    $SignCert = $true
    #
    Write-Host "Checking for required Trusted Root CA certificate..."
    $rootCert = Get-ChildItem -Path "Cert:\LocalMachine\Root" | Where-Object {($_.Thumbprint -eq $RootThumbprint) -and ($_.NotBefore -le (Get-Date)) -and ($_.NotAfter  -ge (Get-Date))}
    if (-not $rootCert) {
        # Set the semaphore so we remove the root certificate after use
        $ImportRequired = $true
        Write-Host "Root CA Missing, attempting to import PFX"
        try {
            # Convert the password to a secure string
            $RootPfxPassword =  ConvertTo-SecureString -String $RootPfxPassword -Force -AsPlainText
            # Import the trusted root
            $rootCert = Import-PfxCertificate -FilePath $RootPfxPath -CertStoreLocation Cert:\LocalMachine\My -Password $RootPfxPassword
            Write-Host "Root certificate import completed."
        } catch {
            #
            $Message = "ERROR: Root CA import failed with " + $error
            # Import failed, exit with error state
            Write-Host $Message
            exit 1
        }
    }
}
# ------------------------------------------------------------
# Set the client certificate parameters
# ------------------------------------------------------------
#
# Extended Key Usage - can be used to determine what this
#  certificate is to be used for
# Code Signing          1.3.6.1.5.5.7.3.3 
# Client Authentication 1.3.6.1.5.5.7.3.2  
# S/MIME (Email)        1.3.6.1.5.5.7.3.4
# OCSP Signing          1.3.6.1.5.5.7.3.9
#
# Assign EKU's
$eku = @("1.3.6.1.5.5.7.3.2")
#
$params = @{
    Subject           = "CN=$ClientName"
    CertStoreLocation = "Cert:\CurrentUser\My"
    KeyAlgorithm      = "RSA"
    KeyLength         = 2048
    KeySpec           = "Signature"
    KeyExportPolicy   = "Exportable"
    KeyUsage          = @("DigitalSignature")
    TextExtension     = @(
        "2.5.29.19={text}ca=false",
        "2.5.29.37={text}$($eku -join ',')"
    )
    DnsName           = $DNSName
    NotBefore         = (Get-Date).AddMinutes(-5)
    NotAfter          = (Get-Date).AddYears(2)
    HashAlgorithm     = "SHA256"
}
#
if ($SignCert) {
    $params.Signer = $rootCert
}
# -------------------------------
# Create client certificate
# -------------------------------
try {
    $cert = New-SelfSignedCertificate @params
    $cert.FriendlyName = $ClientName
    #
    Write-Host ""
    Write-Host "Certificate Thumbprint:" $cert.Thumbprint.ToLower()
    Write-Host "Friendly Name:" $cert.FriendlyName
    Write-Host "Subject:" $cert.Subject
    Write-Host ""
} catch {
    #
    $Message = "ERROR: Certificate creation failed with " + $error
    # Creation failed, exit with error state
    Write-Host $Message
    exit 1
}
# -------------------------------
# EXPORT PUBLIC CERT (.CER)
# -------------------------------
try {
    $cerPath = "$env:USERPROFILE\Documents\$ClientName.cer"
    Export-Certificate -Cert $cert -FilePath $cerPath | Out-Null
    Write-Host ".CER certificate exported."
} catch {
    #
    $Message = "ERROR: Certificate .CER export failed with " + $error
    # Export failed, exit with error state
    Write-Host $Message
    exit 1
}
# -------------------------------
# EXPORT PRIVATE KEY (.PFX)
# -------------------------------
try {
    $mypwd = ConvertTo-SecureString -String $ClientPassword -Force -AsPlainText
    $pfxPath = "$env:USERPROFILE\Documents\$ClientName.pfx"
    Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $mypwd -ChainOption EndEntityCertOnly | Out-Null
    Write-Host ".PFX certificate exported."
} catch {
    #
    $Message = "ERROR: Certificate .PFX export failed with " + $error
    # Export failed, exit with error state
    Write-Host $Message
    exit 1
}
# -------------------------------
# Remove client certificate
# -------------------------------
try {
    Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -DeleteKey
    Write-Host "Client certificate removed."
} catch {
    #
    $Message = "ERROR: Client certificate removal failed with " + $error
    # Removal failed, exit with error state
    Write-Host $Message
    exit 1
}
# -------------------------------
# Remove trusted root certificate
# -------------------------------
if ($ImportRequired) {
    try {
        Remove-Item -Path "Cert:\LocalMachine\My\$($rootCert.Thumbprint)" -DeleteKey
        Write-Host "Trusted Root CA certificate removed."
    } catch {
        #
        $Message = "ERROR: Root CA certificate removal failed with " + $error
        # Removal failed, exit with error state
        Write-Host $Message
        exit 1
    }
}
#
Write-Host "Certificate Generation complete."
