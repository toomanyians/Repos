# -------------------------------
# PARAMETERS FOR SELF-SIGNED CERT
# -------------------------------
$FriendlyName = "YOUR CERTIFICATE NAME"
$MyPassword = "PASSWORD for PFX"
$DNSName = "YOUR DOMAIN"
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
        "2.5.29.37={text}$($eku -join ',')"
    )
    # Certificate identity
    DnsName           = $DNSName
    # Validity
    NotBefore         = (Get-Date).AddMinutes(-5)
    NotAfter          = (Get-Date).AddYears(2)
    HashAlgorithm     = "SHA256"
}
#
cls
Write-Host "Certificate Generation begin."
# -------------------------------
# CREATE SELF-SIGNED CERTIFICATE
# -------------------------------
$cert = New-SelfSignedCertificate @params
$cert.FriendlyName = "Data Collect"
#
Write-Host ""
Write-Host "Certificate Thumbprint:" $cert.Thumbprint
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
Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $mypwd -ChainOption EndEntityCertOnly | Out-Null
# -------------------------------
# RE-IMPORT PFX USING CAPI PROVIDER
# -------------------------------
$pfxBytes = [System.IO.File]::ReadAllBytes($pfxPath)
$pfx = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$pfx.Import($pfxBytes, $MyPassword, 'Exportable,PersistKeySet')
# -------------------------------
# EXTRACT PRIVATE KEY (NOW CAPI-BACKED)
# -------------------------------
$privateKey = $pfx.PrivateKey
if ($privateKey -eq $null) {
    Write-Host "ERROR: No private key found in PFX."
} else {
    # Export PKCS#1 (CAPI blob)
    $pkcs1 = $privateKey.ExportCspBlob($true)
    # ASN.1 PKCS#8 wrapper
    $rsaOID = @(0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01)
    $nullParams = @(0x05, 0x00)
    $algId = @(0x30, $rsaOID.Length + $nullParams.Length) + $rsaOID + $nullParams
    $version = @(0x02, 0x01, 0x00)
    $pkcs1Length = $pkcs1.Length
    $pkcs1LenBytes = if ($pkcs1Length -lt 128) {
        @($pkcs1Length)
    } else {
        @(0x82, ($pkcs1Length -shr 8), ($pkcs1Length -band 0xFF))
    }
    $pkcs1Octet = @(0x04) + $pkcs1LenBytes + $pkcs1
    $pkcs8Body = $version + $algId + $pkcs1Octet
    $pkcs8Length = $pkcs8Body.Length
    $pkcs8Header = @(0x30, 0x82, ($pkcs8Length -shr 8), ($pkcs8Length -band 0xFF))
    $pkcs8 = $pkcs8Header + $pkcs8Body
    $keyPem = "-----BEGIN PRIVATE KEY-----`n" +
              [System.Convert]::ToBase64String($pkcs8, 'InsertLineBreaks') +
              "`n-----END PRIVATE KEY-----"
    $pemKeyPath = "$env:USERPROFILE\Documents\$FriendlyName.pem.key"
    Set-Content -Path $pemKeyPath -Value $keyPem
}
# -------------------------------
# EXPORT CERTIFICATE (PEM)
# -------------------------------
$certPem = "-----BEGIN CERTIFICATE-----`n" +
           [System.Convert]::ToBase64String($cert.RawData, 'InsertLineBreaks') +
           "`n-----END CERTIFICATE-----"
$pemCertPath = "$env:USERPROFILE\Documents\$FriendlyName.pem.crt"
Set-Content -Path $pemCertPath -Value $certPem
# -------------------------------
# REMOVE CERT FROM WINDOWS STORE
# -------------------------------
Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -DeleteKey
Write-Host "Certificate Generation complete."