# ------------------------------------------------------------
#
# Configuration
#
# ------------------------------------------------------------
# Path to the log file
$LogFile = '<LOG FILE>'
# Thumbprint of the required Trusted Root CA
$RequiredThumbprint = "THUMBPRINT"
# Path to the PFX inside the Win32 app package
$PfxPath = "$PSScriptRoot\<CERT FILE>.pfx"
# PFX password (replace with your actual password)
$Password = "<PASSWORD>" | ConvertTo-SecureString -AsPlainText -Force
# ------------------------------------------------------------
# Logging function and initialization
# ------------------------------------------------------------
# If a log file has been specified and it already exists, delete it.
if (-not [string]::IsNullOrWhiteSpace($LogFile) -and (Test-Path -LiteralPath $LogFile)) {
    try {
        Remove-Item -LiteralPath $LogFile -Force -ErrorAction Stop
    } catch {
        Write-Warning "Unable to delete log file '$LogFile'. $($_.Exception.Message)"
    }
}
# ------------------------------------------------------------
# Write-Log - Basic logging function, only works when LogFile is populated.
# Parameter(s):
#  LogFile - The full path of the file you wish to create.
#  Message - The message to wite with a timestamp
# ------------------------------------------------------------
function Write-Log {
    param (
        [Parameter(Mandatory = $false)] [string]$LogFile,
        [Parameter(Mandatory = $true)] [string]$Message
    )

    if ($LogFile.Length -gt 0) {
        $encoding = New-Object System.Text.UTF8Encoding($false)
        $writer = New-Object System.IO.StreamWriter($LogFile, $true, $encoding)

        try {
            $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            $writer.WriteLine("$timestamp`t$Message")
        } finally {
            $writer.Close()
        }
    }
}
# ------------------------------------------------------------
# Check for Trusted Root CA certificate before proceeding
# ------------------------------------------------------------
Write-Log -LogFile $LogFile -Message "Checking for required Trusted Root CA certificate..."
$rootCert = Get-ChildItem -Path "Cert:\LocalMachine\Root" | Where-Object {($_.Thumbprint -eq $RequiredThumbprint) -and ($_.NotBefore -le (Get-Date)) -and ($_.NotAfter  -ge (Get-Date))}
if (-not $rootCert) {
    Write-Log -LogFile $LogFile -Message "Root CA Missing"
    Write-Log -LogFile $LogFile -Message "Expected thumbprint: $RequiredThumbprint"
    exit 1
}
# ------------------------------------------------------------
# Import PFX certificate
# ------------------------------------------------------------
Write-Log -LogFile $LogFile -Message "Importing PFX certificate into LocalMachine\My..."
try {
    Import-PfxCertificate -FilePath $PfxPath -CertStoreLocation Cert:\LocalMachine\My -Password $Password | Out-Null
    Write-Log -LogFile $LogFile -Message "Certificate import completed."
    exit 0
} catch {
    $Message = "Certificate import failed with: $($_.Exception.Message)"
    Write-Log -LogFile $LogFile -Message $Message
    exit 1
}
