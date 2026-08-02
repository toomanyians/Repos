#
# BEGIN CONFIGURATION
#
# Modules
Add-Type -AssemblyName System.Web
#
# Certificate (Required for mTLS)
$CertName = "<LEAF CERT NAME>"
# URL Data (for JSON submission)
$URL = "<URL>"
# Script logging
$LogFile = "<LOG FILE FULL PATH>"
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
# BEGIN DIMENSIONS
#
$Service_Start = @{
    0 = "Boot"
    1 = "System"
    2 = "Automatic"
    3 = "Manual"
    4 = "Disabled"
}
#
$Service_State = @{
    1 = "Stopped"
    2 = "StartPending"
    3 = "StopPending"
    4 = "Running"
    5 = "ContinuePending"
    6 = "PausePending"
    7 = "Paused"
}
#
$Enc_Conversion = @{
    0 = "FullyDecrypted"
    1 = "FullyEncrypted"
    2 = "EncryptionInProgress"
    3 = "DecryptionInProgress"
    4 = "EncryptionPaused"
    5 = "DecryptionPaused"
}
#
$Enc_Method = @{
    0 = "None"
    1 = "AES_128_WITH_DIFFUSER"
    2 = "AES_256_WITH_DIFFUSER"
    3 = "AES_128"
    4 = "AES_256"
    5 = "HARDWARE_ENCRYPTION"
    6 = "XTS_AES_128"
    7 = "XTS_AES_256"
}
#
$Enc_Protection = @{
    0 = "Unprotected"
    1 = "Protected"
    2 = "Unknown"
}
#
$Enc_Protector = @{
    0  = "Unknown"
    1  = "TPM"
    2  = "External key"
    3  = "Numerical password"
    4  = "TPM and PIN"
    5  = "TPM and Startup key"
    6  = "TPM and PIN and Startup key"
    7  = "Public key"
    8  = "Passphrase"
    9  = "TPM Certificate"
    10 = "CNG protector"
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
    # BEGIN INVENTORY
    #
    #
    # Get the ManagedDeviceID and Name from Intune enrollment
    try {
        # If the device is enrolled
        if (@(Get-ChildItem HKLM:SOFTWARE\Microsoft\Enrollments\ -Recurse | Where-Object { $_.PSChildName -eq 'MS DM Server' })) {
            # Get the source for the managed device information
            $MSDMServerInfo = Get-ChildItem HKLM:SOFTWARE\Microsoft\Enrollments\ -Recurse | Where-Object { $_.PSChildName -eq 'MS DM Server' }
            $ManagedDeviceInfo = Get-ItemProperty -LiteralPath "Registry::$($MSDMServerInfo)"
        } else {
            Write-Log -LogFile $LogFile -Message "Device has not been enrolled."
        }
        # Get Intune DeviceID and ManagedDeviceName from the registry or nulls if not
        $ManagedDeviceName = $ManagedDeviceInfo.EntDeviceName
        $ManagedDeviceID = $ManagedDeviceInfo.EntDMID
        # Log the success
        Write-Log -LogFile $LogFile -Message "Retrieved Intune data for: $ManagedDeviceName, $ManagedDeviceID"
    } catch {
        # Log the error
        Write-Log -LogFile $LogFile -Message "Error reading enrollment data: $($Error)"
        # Clear the error
        $error.clear()
    }
    #
    # Antivirus - Hardware info in Intune runs every 7 days, we need reporting more often.
    # Key Compliance Indicators:
    #   Service Start
    #   Service State
    #   AntispywareSignatureAge (Days) -
    #   NISSignatureAge (Days) - 
    #   AntivirusSignatureAge
    #   AMEngineVersion
    try {
        # Query the service
        $DefSvc = Get-Service -name WinDefend -ErrorAction Stop
        # Get the data we need to report
		$Defender_State=$Service_State[[int]$DefSvc.Status]
        # Get the data we need to report
		$Defender_Start=$Service_Start[[int]$DefSvc.StartType]
        # Log the success
        Write-Log -LogFile $LogFile -Message "Retrieved Defender service data"
    } catch {
        # Log the error
        Write-Log -LogFile $LogFile -Message "Error reading Defender service data: $($Error)"
        # Clear the error
        $error.clear()
    }
    try {
        # Query WMI Data
        $DefWMI = Get-CimInstance -ClassName MSFT_MpComputerStatus -Namespace root/microsoft/windows/defender -Property *
        # Get the data we need to report
        $Defender_SpySigAge = $DefWMI.AntispywareSignatureAge
        $Defender_NisSigAge = $DefWMI.NISSignatureAge
        $Defender_AVSigAge = $DefWMI.AntivirusSignatureAge
        $Defender_AMEngine = $DefWMI.AMEngineVersion
        # Log the success
        Write-Log -LogFile $LogFile -Message "Retrieved Defender WMI data"
    } catch {
        # Log the error
        Write-Log -LogFile $LogFile -Message "Error reading Defender WMI data: $($Error)"
        # Clear the error
        $error.clear()
    }
    #
    # Bitlocker - Hardware info in Intune runs every 7 days, we need reporting more often.
    # Key Compliance Indicators:
    #   Service Start
    #   Service Status
    #   Device Encryption
    #   Device Protection Status
    #   Device Protector
    #   Encryption Algorithm
    try {
        # Query the service
        $BitSvc = Get-Service -name BDESvc
        # Get the data we need to report
		$Bitlocker_State=$Service_State[[int]$BitSvc.Status]
        # Get the data we need to report
		$Bitlocker_Start=$Service_Start[[int]$BitSvc.StartType]
        # Log the success
        Write-Log -LogFile $LogFile -Message "Retrieved BitLocker service data"
    } catch {
        # Log the error
        Write-Log -LogFile $LogFile -Message "Error reading Bitlocker service data: $($Error)"
        # Clear the error
        $error.clear()
    }
    try {
        # Query WMI Data
        $BitWMI = Get-CimInstance -Namespace "Root\CIMV2\Security\MicrosoftVolumeEncryption" -Class Win32_EncryptableVolume -Property * | Sort-Object DriveLetter
        # Get the data we need to report
        # Encryption status for every drive
        $BitEncrypted = $null
        foreach ($thisDrive in $BitWMI) {
            $DriveLetter = $thisDrive.DriveLetter
			$Status=$Enc_Conversion[[int]$thisDrive.GetConversionStatus]
            if ($BitEncrypted) {$BitEncrypted += ";$DriveLetter$Status"} else {$BitEncrypted = "$DriveLetter$Status"}        
        }
        # Encryption Algorithm for each drive
        $BitEncryption = $null
        foreach ($thisDrive in $BitWMI) {
            $DriveLetter = $thisDrive.DriveLetter
			$Status=$Enc_Method[[int]$thisDrive.GetEncryptionMethod]
            if ($BitEncryption) {$BitEncryption += ";$DriveLetter$Status"} else {$BitEncryption = "$DriveLetter$Status"}        
        }
        # Protection status for each drive
        $BitProtected = $null
        foreach ($thisDrive in $BitWMI) {
            $DriveLetter = $thisDrive.DriveLetter
            $Status=$Enc_Protection[[int]$thisDrive.GetProtectionStatus]
            if ($BitProtected) {$BitProtected += ";$DriveLetter$Status"} else {$BitProtected = "$DriveLetter$Status"}        
        }
        # Protector for each drive
        $BitProtector = $null
        foreach ($thisDrive in $BitWMI) {
            $DriveLetter = $thisDrive.DriveLetter
			$Status=$Enc_Protector[[int]$thisDrive.GetKeyProtectorType]
            if ($BitProtector) {$BitProtector += ";$DriveLetter$Status"} else {$BitProtector = "$DriveLetter$Status"}  
        }
        # Log the success
        Write-Log -LogFile $LogFile -Message "Retrieved Bitlocker WMI data"
    } catch {
        # Log the error
        Write-Log -LogFile $LogFile -Message "Error reading Bitlocker WMI data: $($Error)"
        # Clear the error
        $error.clear()
    }
    #
    # BuildDate
    #
    $BuildDate = (Get-CimInstance Win32_OperatingSystem).InstallDate.ToString("yyyy-MM-ddTHH:mm:ss")
    #
    # LastBootTime
    #
    $LastBootTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString("yyyy-MM-ddTHH:mm:ss")
    #
    # Physical device Mac Addresses
    # Key Compliance Indicators:
    # We just need the Description and Mac Address seperated by a pipe character for the
    # first 6 listed adapters
    try {
    # Perform the WMI query and filter for physical adapters with Mac Addresses
        $NetAdapters = Get-CimInstance Win32_NetworkAdapter -Property * |
        Where-Object {
            $_.PhysicalAdapter -eq $true -and
            $_.PNPDeviceID -ne $null -and
            ($_.AdapterTypeID -eq 0 -or $_.AdapterTypeID -eq 9) -and
            $_.MACAddress -ne $null
        }
        # Use a hash to hold the data
        $hashCtr = 0
        $NetHash = @{}
        # Iterate through all the adapters
        foreach ($adapter in $NetAdapters) {
            if ($hashCtr -le 5) {
                $datarow = $adapter.Name +"|" + $adapter.MACAddress
                $NetHash[$hashCtr] = $datarow
            }
            # Increment the hash counter
            $hashCtr++
        }
        # Fill in the blanks
        while ($hashCtr -le 5) {
            $NetHash[$hashCtr] = ""
            $hashCtr++
        }
        # Log the success
        Write-Log -LogFile $LogFile -Message "Retrieved NetworkAdapter WMI data"
    } catch {
        # Log the error
        Write-Log -LogFile $LogFile -Message "Error reading NetworkAdapter WMI data: $($Error)"
        # Clear the error
        $error.clear()
    }
    #
    # Build inventory object as a proper PowerShell hashtable
    $Inventory = [ordered]@{
        ManagedDeviceName = $ManagedDeviceName
        ManagedDeviceID = $ManagedDeviceID
        DefenderState = $Defender_State
        DefenderStart = $Defender_Start
        DefSpySigAge = $Defender_SpySigAge
        DefNisSigAge = $Defender_NisSigAge
        DefAVSigAge = $Defender_AVSigAge
        DefAMEngine = $Defender_AMEngine
        BitlockerState = $Bitlocker_State
        BitlockerStart = $Bitlocker_Start
        BitEncrypted = $BitEncrypted
        BitEncryption = $BitEncryption
        BitProtected = $BitProtected
        BitProtector = $BitProtector
        XProtect_Version = ""
		XProtect_Meta = ""
		XProtect_Launch = ""
		XProtect_Background = ""
        FileVault_Status = ""
		FileVault_UserToken = ""
		FileVault_BootToken = ""
        BuildDate = $BuildDate
        LastBootTime = $LastBootTime
    }
    #
    # Add MAC entries safely
    foreach ($key in ($NetHash.Keys | Sort-Object)) {
        $Inventory["MAC$key"] = $NetHash[$key]
    }
    # Convert to JSON Array safely
    $Body = ConvertTo-Json -InputObject @($Inventory) -Depth 5
    try {
        $null = $Body | ConvertFrom-Json
    } catch {
        # We may need the entire JSON for debugging
        $Message = "Invalid JSON : " + $Body
        Write-Log -LogFile $LogFile -Message "Invalid JSON : $Body"
        Write-Output "JSON is invalid!"
        exit 1
    }
    #
    #
    # END INVENTORY
    #
    #
    #
    # UnComment for DEBUGGING
    $Body
    exit 0
    #
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