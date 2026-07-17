# -------------------------------
# PARAMETERS FOR SELF-SIGNED CERT
# -------------------------------
$RootFriendlyName = "<ROOT CERT NAME>"
$FriendlyName = "<PFX CERT NAME>"
$MyPassword = "<PFX PASSWORD>"
$DNSName = "<YOUR DOMAIN NAME>"
#
cls
Write-Host "Certificate Generation begin."
# Root CA for signing
#
$params = @{
    Subject           = "CN=$RootFriendlyName"
    CertStoreLocation = "Cert:\CurrentUser\My"
    KeyAlgorithm      = "RSA"
    KeyLength         = 4096
    KeySpec           = "Signature"
    KeyExportPolicy   = "Exportable"
    KeyUsage          = @("CertSign","CRLSign")
    HashAlgorithm     = "SHA256"
    TextExtension = @(
        "2.5.29.19={critical}{text}ca=true&pathlength=0"
    )
    NotBefore         = (Get-Date).AddMinutes(-5)
    NotAfter          = (Get-Date).AddYears(20)
}
# -------------------------------
# CREATE SELF-SIGNED CERTIFICATE
# -------------------------------
$rootCA = New-SelfSignedCertificate @params
$rootCA.FriendlyName = $RootFriendlyName
#
Write-Host ""
Write-Host "Root CA Thumbprint:" $rootCA.Thumbprint.ToLower()
Write-Host "Root CA Friendly Name:" $rootCA.FriendlyName
Write-Host "Root CA Subject:" $rootCA.Subject
# -------------------------------
# EXPORT PUBLIC CERT (.CER)
# -------------------------------
$cerPath = "$env:USERPROFILE\Documents\$RootFriendlyName.cer"
Export-Certificate -Cert $rootCA -FilePath $cerPath | Out-Null
# -------------------------------
# EXPORT PRIVATE KEY (.PFX)
# -------------------------------
$mypwd = ConvertTo-SecureString -String $MyPassword -Force -AsPlainText
$pfxPath = "$env:USERPROFILE\Documents\$RootFriendlyName.pfx"
Export-PfxCertificate -Cert $rootCA -FilePath $pfxPath -Password $mypwd -ChainOption EndEntityCertOnly | Out-Null
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
    Subject           = "CN=$FriendlyName"
    CertStoreLocation = "Cert:\CurrentUser\My"
    # Key settings (IMPORTANT)
    KeyAlgorithm      = "RSA"
    KeyLength         = 2048
    KeySpec           = "Signature"
    KeyExportPolicy   = "Exportable"
    # CRITICAL FOR JWT / ENTRA ID
    KeyUsage          = @("DigitalSignature")
    TextExtension     = @(
        "2.5.29.19={text}ca=false",           # Basic Constraints: leaf cert
        "2.5.29.37={text}$($eku -join ',')"   # Client Authentication
    )
    # Certificate identity
    DnsName           = $DNSName
    # Validity
    NotBefore         = (Get-Date).AddMinutes(-5)
    NotAfter          = (Get-Date).AddYears(2)
    HashAlgorithm     = "SHA256"
    # Signed by our root
    Signer            = $rootCA
}
# -------------------------------
# CREATE SELF-SIGNED CERTIFICATE
# -------------------------------
$cert = New-SelfSignedCertificate @params
$cert.FriendlyName = "Data Collect"
#
Write-Host ""
Write-Host "Certificate Thumbprint:" $cert.Thumbprint.ToLower()
Write-Host "Friendly Name:" $cert.FriendlyName
Write-Host "Subject:" $cert.Subject
# -------------------------------
# EXPORT PUBLIC CERT (.CER)
# -------------------------------
$cerPath = "$env:USERPROFILE\Documents\$FriendlyName.cer"
Export-Certificate -Cert $cert -FilePath $cerPath | Out-Null
# -------------------------------
# EXPORT PRIVATE KEY (.PFX)
# -------------------------------
$mypwd = ConvertTo-SecureString -String $MyPassword -Force -AsPlainText
$pfxPath = "$env:USERPROFILE\Documents\$FriendlyName.pfx"
#Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $mypwd -ChainOption BuildChain | Out-Null
Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $mypwd -ChainOption EndEntityCertOnly | Out-Null
# -------------------------------
# REMOVE CERT FROM WINDOWS STORE
# -------------------------------
Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -DeleteKey
# -------------------------------
# REMOVE ROOT CA FROM WINDOWS STORE
# -------------------------------
Remove-Item -Path "Cert:\CurrentUser\My\$($rootCA.Thumbprint)" -DeleteKey
Write-Host "Certificate Generation complete."