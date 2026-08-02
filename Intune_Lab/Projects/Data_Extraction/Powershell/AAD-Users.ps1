Add-Type -AssemblyName System.Web
Add-Type -AssemblyName System.Collections
#
# CONFIGURATION
#
#
# Service Principal Data (Required for Token)
$ApplicationID = "<App Registration Client ID"
$TenantID = "<Tenant ID>"
$CertName = "<Certificate Name"
#
# Script logging
$LogFile = "<Full Log File Path>"
$scope=""
#
# If a log file has been specified and it already exists, delete it.
if (-not [string]::IsNullOrWhiteSpace($LogFile) -and (Test-Path -LiteralPath $LogFile)) {
    try {
        Remove-Item -LiteralPath $LogFile -Force -ErrorAction Stop
    } catch {
        Write-Warning "Unable to delete log file '$LogFile'. $($_.Exception.Message)"
    }
}
# Token management
$global:AccessToken = $null
$global:TokenExpires = $null
#
# Retry Logic
$MaxRetries = 10
$DelaySec = 10
#
# Grapoh API
$api_version = "beta"
#
# FUNCTIONS
#
#----------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------
# DATA CONVERSION, TYPING
# ---------------------------------------------------------
#
# Get-Typed -value <string>
#
# Parameters:
#   - value: The string value to convert to its appropriate type.
# Returns:
#   The converted value with the appropriate type (int32, int64, or double).
# Description:
# This function attempts to convert a string value to its appropriate numeric type (int32, int64, or double) for easier processing later on. This processing
# is critical because hash keys are strongly typed. An Int64 will NOT match an Int32 key, and will cause lookups to fail if 
# the types do not match.
#----------------------------------------------------------------------------------------------------------
# ToBase64Url - Takes a custom PSObject, converts it to JSON, ensures UTF-8 encoding,
# then coverts that to a Base64 encoded string and then URLEncodes it.
# Parameter(s):
#  object - The PSObject to convert
# Return(s):
#  The coverted object in JSON format
#
function ToBase64Url {
    param ([Parameter(Mandatory = $true)] $object)
    # Convert the PSObject to JSON
    $json = ConvertTo-Json $object -Compress
    # Turn that into an array of bytes representing the UFT-encoding of the JSON
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    # Convert that into Base64 encoding
    $base64 = [Convert]::ToBase64String($bytes)
    # URL encode the result
    $base64Url = $base64 -replace '\+', '-' -replace '/', '_' -replace '='
    # Send that back tot he caller
    return $base64Url
}
#
# Get-AuthTokenWithCert - Takes the necessary information to obtain an OAUTH2 token from Azure based
# on an App Registration and a client certificate and either returns the token or an error message.
# Parameter(s):
#  TenantId - A unique identifier assinged to every AzureAD tenant.
#  ClientId - Also known as an Apolication ID, uniquely identifies the App Registration in the Tenant.
#  CertThumbprint - A unique identifier for the certificate we are going to use.
# Return(s):
#  An access token or error message.
#
function Get-AuthTokenWithCert {
    param ([Parameter(Mandatory = $true)] [string]$TenantId, [Parameter(Mandatory = $true)] [string]$ClientId,
        [Parameter(Mandatory = $true)] [string]$CertThumbprint )
    try {
        # Read the certificate from the Local Machine keystore.
        $cert = Get-ChildItem -Path Cert:\LocalMachine\My\$CertThumbprint
        # Throw an error if it doesn't exist
        if (-not $cert) {throw "Certificate with thumbprint '$CertThumbprint' not found."}
        # Get the RSA Private Key.
        $privateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
        # Thow an error if it's not present and reaadable
        if (-not $privateKey) { throw "Unable to Get Certificate Private Key."}
        # Time based data for the payload
        $now = [DateTime]::UtcNow
        $exp = $now.AddMinutes(10)
        $epoch = [datetime]'1970-01-01T00:00:00Z'
        # Create a new GUID for the payload
        $jti = [guid]::NewGuid().ToString()
        # Create the payload
        $jwtPayload = @{
            aud = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
            iss = $ClientId
            sub = $ClientId
            jti = $jti
            nbf = [int]($now - $epoch).TotalSeconds
            exp = [int]($exp - $epoch).TotalSeconds
        }
        # Convert to Base64, URL encoded
        $payload = ToBase64Url -object $jwtPayload
        # Populate the header
        $jwtHeader = @{alg = "RS256"; typ = "JWT"; x5t = [System.Convert]::ToBase64String($cert.GetCertHash())}
        # Convert to Base64, URL encoded
        $header = ToBase64Url -object $jwtHeader
        # Concatenate the Header and Payload with a dot
        $jwtToSign = "$header.$payload" 
        # Hash the JWT to create a byte encoded signature
        $bytesToSign = [System.Text.Encoding]::UTF8.GetBytes($jwtToSign)
        # Encode the signature in SHA256
        $signatureBytes = $privatekey.SignData(
            $bytesToSign,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        )
        # Convert the signature to Base64 Url encoded format
        $signature = [Convert]::ToBase64String($signatureBytes) -replace '\+', '-' -replace '/', '_' -replace '=' 
        # Concatednate the JWT request and the Signature
        $clientAssertion = "$jwtToSign.$signature" 
        # Create the body for the request including the Client Assertion
        $body = @{ 
            client_id = $ClientId
            scope = "https://graph.microsoft.com/.default"
            client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            client_assertion = $clientAssertion
            grant_type = "client_credentials"
        }
        # Request the token
        $response = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -ContentType "application/x-www-form-urlencoded" -Body $body
        # Save the Access token to our global variable
        $global:AccessToken = $response.access_token
        # Save the token expiry to our global variable
        $global:TokenExpires = (Get-Date).AddSeconds($response.expires_in)
        # Return a success message
        return "Token Updated."
    } catch { return "Failed to get token: $Error"}
}
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
}
#
# ---------------------------------------------------------
#
# END FUNCTIONS
#
# ---------------------------------------------------------
# Get the first valid certificate that matches $CertName
$cert = Get-ValidCertificate -CertName $CertName
# If one was found
if ($cert) {
    # Get the thumbprint
    $thumbprint = (Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object {$_.Subject -Match $CertName}).Thumbprint
    # Get the auth token
    $Token_Result = Get-AuthTokenWithCert -TenantId $TenantID -ClientId $ApplicationID -CertThumbprint $thumbprint
    if ($Token_Result.Contains("Updated")) {
        # Don't save the whole token to the log, just enough to know we got it
        $Message = "Token : " + $global:AccessToken.Substring(0, [Math]::Min(40, $global:AccessToken.Length))
        Write-Log -LogFile $LogFile -Message $Message
        #
        # Suppress noise from Invoke-WebRequest
        $OldProgress = $ProgressPreference
        $ProgressPreference    = 'SilentlyContinue'
        # Initialize a list for our output, faster than array +=
        $Output = [System.Collections.Generic.List[object]]::new()
        # Retryable HTTP status codes
        $RetryableStatuses = @{
            429 = "Too Many Requests"
            500 = "Internal Server Error"
            502 = "Bad Gateway"
            503 = "Service Unavailable"
            504 = "Gateway Timeout"
        }
        #
        # Set the URL
        $URL = "https://graph.microsoft.com/$api_version/users?$select=id,accountEnabled,createdDateTime,displayName,mail,securityIdentifier,userPrincipalName,userType"
        #
        #
        # Query as long as we have a valid URL
        while ($URL) {
            # Retry loop, make sure we do not exceed the specified number of retries for transient errors
            for ($Try = 1; $Try -le $MaxRetries; $Try++) {
                # Catch and handle any errors that occur during the request or JSON parsing
                try {
                    # Check the token and update if necessary
                    $CheckTime = (Get-Date).AddSeconds(10)
                    if ($CheckTime -gt $global:TokenExpires) {
                        # Get a new token
                        $Token_Result = Get-AuthTokenWithCert -TenantId $TenantID -ClientId $ApplicationID -CertThumbprint $thumbprint
                        # if we had a failure
                        if ($Token_Result -contains "Failed") {
                            # Restore old progree preference
                            $OldProgress = $ProgressPreference
                            # Log the failure
                            $Message = "Token refresh failed."
                            Write-Log -LogFile $LogFile -Message $Message
                            # Exit with an error
                            exit 1
                        }
                    }
                    # Create the header
                    $headers = @{
                        "Authorization" = "Bearer $global:AccessToken"
                        "Content-Type"  = "application/json"
                    }
                    # Invoke request
                    $Response = Invoke-WebRequest -Uri $URL -Headers $headers -Method Get -TimeoutSec 30 -UseBasicParsing -ErrorAction Stop
                    # Convert JSON only if content exists
                    if (![string]::IsNullOrWhiteSpace($Response.Content)) {
                        try {
                            $users = ($Response.Content | ConvertFrom-Json).value
                        } catch {
                            # Restore progress preferences
                            $OldProgress = $ProgressPreference
                            # JSON parsing failure
                            $Message = "JSON parse error: $($_.Exception.Message)"
                            Write-Log -LogFile $LogFile -Message $Message
                            # Exit with an error
                            exit 1
                        }
                    }
                    #
                    # Build output
                    foreach ($U in $users) {
                        # Add each user object to our output list
                        $Output.Add([PSCustomObject]@{
                            id = $U.id
                            accountEnabled = $U.accountEnabled
                            createdDateTime = $U.createdDateTime
                            displayName = $U.displayName
                            mail = $U.mail
                            securityIdentifier = $U.securityIdentifier
                            userPrincipalName = $U.userPrincipalName
                            userType = $U.userType
                        })
                    }
                    # See if we have another page of data
                    $URL=$Response.'@odata.nextLink'
                    # break out of the retry loop
                    break
                } catch {
                    # Safely extract status code
                    $Status = $null
                    # If we have a response, try to get the status code. If we don't have a response, this will throw and we will
                    # just return 0 for the status code.
                    if ($_.Exception.Response) {try {$Status = $_.Exception.Response.StatusCode.Value__} catch {}}
                    # Retryable HTTP status codes
                    if ($RetryableStatuses.ContainsKey($Status)) {
                        # Respect Retry-After header if present
                        $RetryAfter = $null
                        if ($Response.Headers["Retry-After"]) {[int]::TryParse($Response.Headers["Retry-After"], [ref]$RetryAfter) | Out-Null}
                        # Use Retry-After first, otherwise exponential backoff
                        if (-not $RetryAfter) {$RetryAfter = [Math]::Min(300,[Math]::Pow(2, $Try) + (Get-Random -Minimum 1 -Maximum 5))}
                        #
                        # UNCOMMENT FOR DEBUGGING
                        # Log a warning about the retryable error and the delay before retrying, which can help with debugging and monitoring our
                        # API usage.
                        #$Message = "HTTP $Status [$($RetryableStatuses[$Status])]. " + "Retrying in $RetryAfter sec " + "($($MaxRetries - $Try) retries left)"
                        #Write-Log -LogFile $LogFile -Message $Message
                        #
                        # Wait the specified delay before retrying
                        Start-Sleep -Seconds $RetryAfter
                        # Clear the error
                        $error.clear()
                        # Continue to the next iteration of the retry loop
                        continue
                    }
                    # Non-retryable error
                    # Restore progress preferences
                    $OldProgress = $ProgressPreference
                    # JSON parsing failure
                    $Message = "Error: " + $_.Exception.Message
                    Write-Log -LogFile $LogFile -Message $Message
                    # Exit with an error
                    exit 1
                }
            }
            # Retries exhausted?
            if ($Try -gt $MaxRetries) {
                # Restore old progree preference
                $OldProgress = $ProgressPreference
                # Log the failure
                $Message = "Failed after $MaxRetries retries"
                Write-Log -LogFile $LogFile -Message $Message
                # Exit with an error
                exit 1
            }
        }
    }


$Output

$username = "postgres user name"
$pwd = "postgres user password"

# DSN-less ODBC connection string for PostgreSQL
$connectionString = "Driver={PostgreSQL Unicode(x64)};Server=192.168.1.72;Port=5432;Database=Intune;Uid=$username;Pwd=$pwd;SSLMode=prefer;"

# Create ODBC connection
$connection = New-Object System.Data.Odbc.OdbcConnection
$connection.ConnectionString = $connectionString

# Open connection
$connection.Open()

Write-Host "Connected via ODBC!"





} else {
    # Log the failure
    $Message = "Error: Certificate not found."
    Write-Log -LogFile $LogFile -Message $Message
}