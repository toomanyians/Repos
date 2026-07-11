
# Path to the log file
$LogFile = '<LOG FILE>'
# Path to the PFX inside the Win32 app package
$PfxPath = "$PSScriptRoot\<CERT FILE>.pfx"
# PFX password (replace with your actual password)
$Password = "<PASSWORD>" | ConvertTo-SecureString -AsPlainText -Force
# If a log file has been specified and it already exists, delete it.
if (-not [string]::IsNullOrWhiteSpace($LogFile) -and (Test-Path -LiteralPath $LogFile)) {
    try {
        Remove-Item -LiteralPath $LogFile -Force -ErrorAction Stop
    } catch {
        Write-Warning "Unable to delete log file '$LogFile'. $($_.Exception.Message)"
    }
}
#
# Write-Log - Basic logging function, only works when LogFile is populated.
# Parameter(s):
#  LogFile - The full path of the file you wish to create.
#  Message - The message to wite with a timestamp
#
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
#
Write-Log -LogFile $LogFile -Message "Importing PFX certificate into LocalMachine\My..."
#
try {
    #
    Import-PfxCertificate -FilePath $PfxPath -CertStoreLocation Cert:\LocalMachine\My -Password $Password
    #
    Write-Log -LogFile $LogFile -Message "Certificate import completed."
} catch {
    $Message = "Certificate import failed with: " + $error
    #
    Write-Log -LogFile $LogFile -Message $Message 
}
