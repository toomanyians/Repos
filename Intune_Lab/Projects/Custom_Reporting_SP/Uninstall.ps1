# ------------------------------------------------------------
#
# Configuration
#
# ------------------------------------------------------------
# Certificate Thumbprint
$Thumbprint = "<PFX THUMBPRINT>"
# Path to the log file
$LogFile = "<FULL PATH TO LOG FILE>"
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
    param ([Parameter(Mandatory = $false)] [string]$LogFile,[Parameter(Mandatory = $true)] [string]$Message)
    # If a Log filename has been specified
    if ($LogFile.Length -gt 0) {
        # Make sure we write in UTF-8
        $encoding = New-Object System.Text.UTF8Encoding($false)
        # Open or create the file for appending
        $writer = New-Object System.IO.StreamWriter($LogFile, $true, $encoding)
        # Write the message
        try {
            # Get the timestamp
            $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            # write the timestamp, a tab and the message
            $writer.WriteLine("$timestamp`t$Message")
        } finally {$writer.Close()}
    }
}
# ------------------------------------------------------------
# Locate the certificate by thumbprint
# ------------------------------------------------------------
$Message = "Locating certificate with thumbprint $Thumbprint..." 
Write-Log -LogFile $LogFile -Message $Message
# Get the certificate if it exists
$Cert = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object {$_.Thumbprint -eq $Thumbprint}
# ------------------------------------------------------------
# Delete it if found
# ------------------------------------------------------------
if ($Cert) {
    $Message = "Removing certificate with thumbprint $Thumbprint..." 
    Write-Log -LogFile $LogFile -Message $Message
    try {
        # -------------------------------
        # REMOVE CERT FROM WINDOWS STORE
        # -------------------------------
        $CertPath = "Cert:\LocalMachine\My\$Thumbprint"
        Remove-Item -Path $CertPath -DeleteKey
        # Log the success
        Write-Log -LogFile $LogFile -Message "Certificate successfully removed."
        exit 0
    } catch {
        $Message = "Removal failed with: " + $Error
        Write-Log -LogFile $LogFile -Message $Message
        exit 1
    }
} else {
    # Not found, is already deleted
    Write-Log -LogFile $LogFile -Message "Certificate not found. Nothing to remove."
    exit 0
}
