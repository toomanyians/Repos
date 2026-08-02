# -------------------------------
# PARAMETERS FOR SELF-SIGNED CERT
# -------------------------------
$RootFriendlyName = "<ROOT CA NAME>"
$FriendlyName = "<LEAF CERT NAME>"
$MyPassword = "<PFX PASSWORD>"
$DNSName = "<YOUR DOMAIN>"
#
cls
Write-Host "Certificate Generation begin."
# Root CA for signing
#
$params = @{
    Type                = 'Custom'
    Subject             = "CN=$RootFriendlyName"
    CertStoreLocation   = 'Cert:\CurrentUser\My'
    KeyAlgorithm        = 'RSA'
    KeyLength           = 4096
    HashAlgorithm       = 'SHA256'
    KeyExportPolicy     = 'Exportable'
    KeyUsage            = @('CertSign','CRLSign')
    TextExtension       = @(
        '2.5.29.19={critical}{text}CA=true&pathlength=0'
    )
}
# -------------------------------
# CREATE SELF-SIGNED CERTIFICATE
# -------------------------------
$rootCA = $null
$rootCA = New-SelfSignedCertificate @params
$rootCA.FriendlyName = $RootFriendlyName
if ($rootCA) {

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
    # -------------------------------
    # EXPORT Certificate (.PEM)
    # -------------------------------
    # Path for PEM output
    $pemPath = "$env:USERPROFILE\Documents\$RootFriendlyName.pem"
    # Build PEM content
    $pemContent = @(
        "-----BEGIN CERTIFICATE-----"
        [System.Convert]::ToBase64String($rootCA.RawData, 'InsertLineBreaks')
        "-----END CERTIFICATE-----"
    )
    # Write PEM file
    $pemContent | Out-File -FilePath $pemPath -Encoding ascii
    #
    # Create our Leaf Certificate
    #
    $params = @{
        Type                = "Custom"
        Subject             = "CN=$FriendlyName"
        CertStoreLocation   = "Cert:\CurrentUser\My"

        KeyAlgorithm        = "RSA"
        KeyLength           = 2048
        Provider            = "Microsoft Software Key Storage Provider"
        KeyExportPolicy     = "Exportable"

        KeyUsage            = @(
            "DigitalSignature"
        )

        TextExtension = @(
            "2.5.29.19={critical}{text}CA=false",
            "2.5.29.37={text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2"
        )

        NotBefore           = (Get-Date).AddMinutes(-5)
        NotAfter            = (Get-Date).AddYears(2)

        HashAlgorithm       = "SHA256"
        Signer              = $rootCA
    }
    # -------------------------------
    # CREATE SELF-SIGNED CERTIFICATE
    # -------------------------------
    $cert = $null
    $cert = New-SelfSignedCertificate @params
    if ($cert) {
        $cert.FriendlyName = $FriendlyName
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
    } else {
        Write-Host "ERROR: Certificate Generation failed."
    }
    # -------------------------------
    # REMOVE ROOT CA FROM WINDOWS STORE
    # -------------------------------
    Remove-Item -Path "Cert:\CurrentUser\My\$($rootCA.Thumbprint)" -DeleteKey
    Write-Host "Certificate Generation complete."
} else {
    Write-Host "ERROR: Trusted Root Certificate Generation failed."
}