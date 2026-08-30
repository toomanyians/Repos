#
# BEGIN CONFIGURATION
#
# Modules
Add-Type -AssemblyName System.Web
#
# Certificate (Required for mTLS)
$CertName = "AF_Collect"
# URL Data (for JSON submission)
$URL = "<URL>"
# Script logging
$LogFile = "C:\ProgramData\ScriptLogs\Inventory.log"
#
# If a log file has been specified and it already exists, delete it.
if (-not [string]::IsNullOrWhiteSpace($LogFile) -and (Test-Path -LiteralPath $LogFile)) {
    try {
        Remove-Item -LiteralPath $LogFile -Force -ErrorAction Stop
    } catch {
        Write-Warning "Unable to delete log file '$LogFile'. $($_.Exception.Message)"
    }
}
#
# BEGIN FUNCTIONS
#
#
# write-log - Basic logging function, only works when LogFile is populated.
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
# Get-ValidCertificate - 
# Parameter(s):
#  CertName - A pattern to match in the certificate subject
# Returns :
#  A certificate that is valid and where the subject contains the CertName
#
function Get-ValidCertificate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CertName
    )
    # Get today's date
    $now = Get-Date
    # Get the first certificate that is valid that matches the subject pattern
    Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -like "*$CertName*" -and $_.NotBefore -le $now -and $_.NotAfter -ge $now} | Select-Object -First 1
}#
# BEGIN SCRIPT
#
#
# Get the first valid certificate that matches $CertName
$cert = Get-ValidCertificate -CertName $CertName
# If one was found
if ($cert) {
    #
    # Build inventory object as a proper PowerShell hashtable
    $Inventory = [ordered]@{
        ManagedDeviceName = "IanBaxter_Windows_6/19/2026_3:13 AM"
        ManagedDeviceID = "<INTUNE DEVICE ID>"
        DefenderState = "Running"
        DefenderStart = "Automatic"
        DefSpySigAge = 1
        DefNisSigAge = 1
        DefAVSigAge = 1
        DefAMEngine = "1.1.26060.3008"
        BitlockerState = "Running"
        BitlockerStart = "Automatic"
        BitEncrypted = "C:FullyDecrypted"
        BitEncryption = "C:None"
        BitProtected = "C:Unprotected"
        BitProtector = "C:Unknown"
        XProtect_Version = "5346"
		XProtect_Meta = "5346"
		XProtect_Launch = "enabled"
		XProtect_Background = "enabled"
        FileVault_Status = "Macintosh HD - Data;Encrypted"
		FileVault_UserToken = "enabled"
		FileVault_BootToken = "enabled"
        BuildDate = "2026-06-16T17:25:30"
        LastBootTime = "2026-07-08T13:50:03"
        MAC0 = "Intel(R) PRO/1000 MT Desktop Adapter|08:00:27:C4:49:3C"
        MAC1 = "Intel(R) PRO/1000 MT Desktop Adapter|08:00:27:C4:49:3C"
        MAC2 = "Intel(R) PRO/1000 MT Desktop Adapter|08:00:27:C4:49:3C"
        MAC3 = "Intel(R) PRO/1000 MT Desktop Adapter|08:00:27:C4:49:3C"
        MAC4 = "Intel(R) PRO/1000 MT Desktop Adapter|08:00:27:C4:49:3C"
        MAC5 = "Intel(R) PRO/1000 MT Desktop Adapter|08:00:27:C4:49:3C"
    }
    # Convert to JSON Array safely
    $Body = ConvertTo-Json -InputObject @($Inventory) -Depth 5
    #
    # Send the JSON to the Azure Function
    $headers = @{"Content-Type" = "application/json" }
    # Log it
    Write-Log -LogFile $LogFile -Message "Uploading inventory..."
    Write-Log -LogFile $LogFile -Message "URI: $URL"
    Write-Log -LogFile $LogFile -Message "Body Length: $($Body.Length) bytes"
    # Report back status
    $date = Get-Date -Format "dd-MM HH:mm"
    $OutputMessage = "InventoryDate:$date "
    try {
        # We use invoke-webrequest so we can get better response data.
        $response = Invoke-WebRequest -Uri $URL -Method Post -Headers $headers -Body $Body -Certificate $cert -ErrorAction Stop -UseBasicParsing
        # Log the response status and description
        Write-Log -LogFile $LogFile -Message "HTTP Status: $($response.StatusCode)"
        Write-Log -LogFile $LogFile -Message "Status Description: $($response.StatusDescription)"
        # Log any header data sent back in the reponse
        foreach ($header in $response.Headers.Keys) { Write-Log -LogFile $LogFile -Message "Header: $header = $($response.Headers[$header])" }
        # Log the response body content
        if (![string]::IsNullOrWhiteSpace($response.Content)) {
            Write-Log -LogFile $LogFile -Message "Response Body: $($response.Content)"
        } else {
            Write-Log -LogFile $LogFile -Message "Response Body: <empty>"
        }
        # This output can be seen in the console
        $OutputMessage += "DeviceInventory:OK (" + $response.StatusCode + ")"
    } catch {
        # Put a big FAILED message in the log
        Write-Log -LogFile $LogFile -Message "Upload FAILED"
        # If we got a response to report the failure cause
        if ($_.Exception.Response) {
            # Get the error code
            $status = $_.Exception.Response.StatusCode.value__
            # Log the HTPP status code it returned
            Write-Log -LogFile $LogFile -Message "HTTP Status: $status"
            try {
                # Read the response if we can                
                $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $body = $reader.ReadToEnd()
                $reader.Close()
                # Log the full reponse
                Write-Log -LogFile $LogFile -Message "Azure Response: $body"
            } catch {
                # Log that there was no response
                Write-Log -LogFile $LogFile -Message "Unable to read response body."
            }
        }
        # Put the exception data in the log
        Write-Log -LogFile $LogFile -Message $_.Exception.Message
        # This will be returned to the console
        $OutputMessage += "DeviceInventory:Failed ($status)"
        exit 1
    }
} else {
    # Report back status
    $date = Get-Date -Format "dd-MM HH:mm"
    $OutputMessage = "InventoryDate:$date "
    $OutputMessage += "DeviceInventory:Fail No certificate."
    exit 1
}
Write-Output $OutputMessage
exit 0