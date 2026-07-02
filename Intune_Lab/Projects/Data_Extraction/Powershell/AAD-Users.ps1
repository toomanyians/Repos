Add-Type -AssemblyName System.Web
Add-Type -AssemblyName System.Collections
#
# CONFIGURATION
#
#
# Service Principal Data (Required for Token)
$ApplicationID = "<Application/Client ID>"
$TenantID = "<Tenant ID>"
$CertName = "Data Collect"
#
#
# Script logging
$LogFile = "<Log File Path>"
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
#
# FUNCTIONS
#
#----------------------------------------------------------------------------------------------------------
# ---------------------------------------------------------
# DATA FUNCTIONS
# ---------------------------------------------------------
#
# Get-JsonFromUrl -Url <string> -Session <WebRequestSession> -MaxRetries <int> -DelaySec <int>
#
# Parameters:
#   - Url: The URL to query for JSON data
#   - Session: An optional WebRequestSession object to reuse for cookies and connection pooling. If null, a new session will be created.
#   - MaxRetries: The maximum number of retries for transient errors (e.g. HTTP 429, 503)
#   - DelaySec: The delay in seconds between retries
# Returns:
#   A PSCustomObject with the following properties:
#   - StatusCode: The HTTP status code of the response, or 0 if the request failed without a response
#   - Json: The parsed JSON object from the response content, or null if parsing failed or no content was returned
#   - Error: An error message if the request failed or JSON parsing failed, or null on success
# Description:
# This function performs an HTTP GET request to the specified URL, with built-in retry logic for transient errors. It attempts to
# parse the response content as JSON and returns a structured result object. The function also suppresses progress output 
# from Invoke-WebRequest to avoid cluttering the console during batch operations.
#----------------------------------------------------------------------------------------------------------
function Get-JsonFromUrl {
    param(
        # URL to query
        [Parameter(Mandatory)]
        [string]$Url,
        # Web session
        [Parameter(Mandatory)]
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        # Retry count
        [Parameter(Mandatory)]
        [int]$MaxRetries,
        # Delay between retries
        [Parameter(Mandatory)]
        [int]$DelaySec
    )
    # Save caller's progress preference
    $OldProgressPreference = $ProgressPreference
    # Disable Invoke-WebRequest progress spam
    $ProgressPreference = 'SilentlyContinue'
    # Retryable HTTP status codes
    $RetryableStatuses = @{
        420 = "Error Limited"          # ESI specific
        429 = "Too Many Requests"
        500 = "Internal Server Error"
        502 = "Bad Gateway"
        503 = "Service Unavailable"
        504 = "Gateway Timeout"
    }
    # Make sure we handle any errors that occur
    try {
        # Create session only if missing
        if (-not $Session) {$Session = [Microsoft.PowerShell.Commands.WebRequestSession]::new()}
        # Retry loop, make sure we do not exceed the specified number of retries for transient errors
        for ($Try = 1; $Try -le $MaxRetries; $Try++) {
            # Catch and handle any errors that occur during the request or JSON parsing
            try {
                # Invoke request
                $Response = Invoke-WebRequest -Uri $Url -WebSession $Session -TimeoutSec 30 -UseBasicParsing -ErrorAction Stop
                # Set the default JSON object
                $Json = $null
                # Convert JSON only if content exists
                if (![string]::IsNullOrWhiteSpace($Response.Content)) {
                   try {
                        $Json = $Response.Content | ConvertFrom-Json
                    } catch {
                        # JSON parsing failure
                        return [PSCustomObject]@{
                            StatusCode = $Response.StatusCode
                            Json       = $null
                            Error      = "JSON parse error: $($_.Exception.Message)"
                        }
                    }
                }
                # Success
                return [PSCustomObject]@{
                    StatusCode = $Response.StatusCode
                    Json       = $Json
                    Error      = $null
                }
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
                    # ESI-specific headers
                    $EsiRemain = $Response.Headers["X-Esi-Error-Limit-Remain"]
                    $EsiReset  = $Response.Headers["X-Esi-Error-Limit-Reset"]
                    # Use Retry-After first, otherwise exponential backoff
                    if (-not $RetryAfter) {$RetryAfter = [Math]::Min(300,[Math]::Pow(2, $Try) + (Get-Random -Minimum 1 -Maximum 5))}
                    # Extra protection when nearing ESI error limit
                    if ($EsiRemain -and [int]$EsiRemain -lt 5) {$ExtraDelay = if ($EsiReset) {[int]$EsiReset} else {60}
                        # If the ESI headers indicate we are close to the error limit, we will use the reset time as the delay if it
                        # is provided, or a default of 60 seconds if not. We will also log a warning about the low remaining limit and
                        # the reset time. This is important to avoid hitting the error limit and getting blocked by ESI, which can happen
                        # if we keep retrying without enough delay when we are close to the limit.
                        $RetryAfter = [Math]::Max($RetryAfter, $ExtraDelay)
                        # Log a warning about the low remaining limit and the reset time, which can help with debugging and monitoring our
                        # API usage.
                        Write-Warning ("ESI error limit low: Remaining=$EsiRemain " + "Reset=$EsiReset sec")
                    }
                    # Log a warning about the retryable error and the delay before retrying, which can help with debugging and monitoring our
                    # API usage.
                    Write-Warning ("HTTP $Status [$($RetryableStatuses[$Status])]. " + "Retrying in $RetryAfter sec " + "($($MaxRetries - $Try) retries left)")
                    # Wait the specified delay before retrying
                    Start-Sleep -Seconds $RetryAfter
                    # Continue to the next iteration of the retry loop
                    continue
                }
                # Non-retryable error
                return [PSCustomObject]@{
                    StatusCode = $Status
                    Json       = $null
                    Error      = $_.Exception.Message
                }
            }
        }
        # Retries exhausted
        return [PSCustomObject]@{
            StatusCode = 0
            Json       = $null
            Error      = "Failed after $MaxRetries retries"
        }
    } finally {
        # Always restore caller's progress preference
        $ProgressPreference = $OldProgressPreference
    }
}
# ---------------------------------------------------------
# BATCH PROCESSOR
# ---------------------------------------------------------
#
# Invoke-URLBatchProcessor -Queue <Queue> -JobBlock <ScriptBlock> -Activity <string> -MaxJobs <int> -BatchSize <int>
#
# Parameters:
#   - Queue: A System.Collections.Queue containing the items to process. The items will be passed as an array to the 
#   JobBlock in batches.
#   - JobBlock: A ScriptBlock that will be executed in a separate thread for each batch of items. The ScriptBlock should
#   accept three parameters: the batch of items, the API version string, and the data source string. It should return an array
#   of results.
#   - Activity: A string describing the activity being performed, used for the progress bar display.
#   - MaxJobs: The maximum number of concurrent jobs to run. This controls the level of parallelism.
#   - BatchSize: The number of items to include in each batch passed to the JobBlock. This allows you to balance the workload
#   and reduce overhead from too many small jobs.
# Returns:
#   An array of results collected from all the completed jobs. Each job should return an array of results, and this function
#   will aggregate them into a single array before returning to the caller.
# Description:
# This function manages the execution of a batch processing workflow using PowerShell jobs. It takes a queue of items to process,
# executes a specified ScriptBlock in parallel on batches of these items, and collects the results. It also includes robust error
# handling and retry logic for jobs that fail, as well as a progress bar to provide feedback on the overall progress of the operation.
#----------------------------------------------------------------------------------------------------------
function Invoke-URLBatchProcessor {
    param(
        # The queue of items to process
        [Parameter(Mandatory)]
        [System.Collections.Queue]$Queue,
        # The scriptblock we need to execute
        [Parameter(Mandatory)]
        [scriptblock]$JobBlock,
        # The Activity value for the progress bar
        [Parameter(Mandatory)]
        [String]$Activity,
        # The Maximum number of jobs we allow in the job table
        [Parameter(Mandatory)]
        [int]$MaxJobs,
        # How many API calls we can add to each batch
        [Parameter(Mandatory)]
        [int]$BatchSize
    )
    # Use generic list instead for efficiency when adding results from each job
    $Results = [System.Collections.Generic.List[object]]::new()
    # Any jobs in these states will be restarted
    $BadStates = @("Failed","Stopped","Blocked")
    # Retry tracking
    $RetryTable = @{}
    $MaxRetries = 5
    # Progress values
    $Done = 0
    $Running = 0
    $Pct = 0
    $JobCount = 0
    # Total items to process
    $Total = $Queue.Count
    # Clean up old jobs
    Get-Job | Remove-Job -Force -ErrorAction SilentlyContinue
    # Initialize progress bar with 0% completion
    Write-Progress -Activity $Activity -Status "Completed: $Done / $Total  Jobs: $JobCount" -PercentComplete $Pct
    # Refresh cached jobs table
    $Jobs = Get-Job
    # While there are jobs in the queue or job table, keep processing
    while (($Queue.Count -gt 0) -or ((Get-Job).Count -gt 0)) {
        # Cache jobs table
        $Jobs = Get-Job
        # Launch new jobs if we have capacity
        while (($Queue.Count -gt 0) -and ($Jobs.Count -lt $MaxJobs)) {
            # Create a new batch
            $Batch = @()
            # Fill batch
            for ($i = 1; $i -le $BatchSize -and $Queue.Count -gt 0; $i++) {$Batch += $Queue.Dequeue()}
            # Start thread job
            Start-ThreadJob  -ScriptBlock $JobBlock  -ArgumentList $Batch,$global:API,$global:Source | Out-Null
            # Refresh cached jobs table
            $Jobs = Get-Job
        }
        # Get active job count
        $JobCount = $Jobs.Count
        # Calculate percentage complete
        $Pct = [Math]::Min(100, [int](($Done / $Total) * 100))
        # Update progress bar
        Write-Progress -Activity $Activity -Status "Completed: $Done / $Total  Jobs: $JobCount" -PercentComplete $Pct
        # Wait efficiently for any job to complete
        if ($Jobs.Count -gt 0) {Wait-Job -Job $Jobs -Any -Timeout 1 | Out-Null}
        # Process completed jobs
        foreach ($job in Get-Job -State Completed) {
            # Collect results
            $out = Receive-Job $job
            # Remove completed job
            Remove-Job $job
            # Process returned results
            foreach ($R in $out) {
                # Add result to output list
                $Results.Add($R)
                # Increment completed count
                $Done++
            }
        }
        # Restart bad-state jobs
        foreach ($state in $BadStates) {
            foreach ($job in Get-Job -State $state) {
                # Recover failed batch
                $Batch = $job.Command[0].Arguments[0]
                # Build retry tracking key
                $RetryKey = ($Batch -join ',')
                # Initialize retry counter
                if (!$RetryTable.ContainsKey($RetryKey)) {$RetryTable[$RetryKey] = 0}
                # Increment retry count
                $RetryTable[$RetryKey]++
                # Retry only within limits
                if ($RetryTable[$RetryKey] -le $MaxRetries) {
                    # Uncomment for debugging
                    Write-Warning "Restarting batch job for IDs $($Batch -join ', ') (state: $state retry: $($RetryTable[$RetryKey]))"
                    # Remove failed job
                    Remove-Job $job
                    # Small stabilization delay
                    Start-Sleep -Milliseconds 200
                    # Restart SAME job block
                    Start-ThreadJob -ScriptBlock $JobBlock -ArgumentList $Batch,$global:API,$global:Source | Out-Null
                } else {
                    # Permanent failure after retries, log and skip
                    Write-Error "Batch permanently failed after $MaxRetries retries: $($Batch -join ', ')"
                    # Remove failed job
                    Remove-Job $job
                }
            }
        }
    }
    # Close and hide progress bar
    Write-Progress -Activity $Activity -Completed
    # Return results to caller
    return $Results
}
# ---------------------------------------------------------
# CSV IMPORT/EXPORT
# ---------------------------------------------------------
#
# Get_FromCSV -filepath <string> -keyname <string>
#
# Parameters:
#   - filepath: The full path to the CSV file we want to read
#   - keyname: The name of the column to use as the key (Index) for the hashtable. If null, the row number will be used as the key.
# Returns:
#   A PSCustomObject with the following properties:
#   - A hashtable of the data from the CSV file, indexed by the specified key column. Each value in the hashtable is itself a
#   - hashtable containing the data for that row, with keys corresponding to the column headers.
# Description:
# This function reads a CSV file and returns a hashtable of the data, indexed by the specified key column. It also attempts to 
# convert numeric values to their appropriate types (int32, int64, double) for easier processing later on. This processing
# is critical because hash keys are stronly typed. An Int64 will NOT match an Int32 key, and will cause lookups to fail if 
# the types do not match.
#----------------------------------------------------------------------------------------------------------
function Get_FromCSV {
    param(
        # The full path to the file we are importing
        [Parameter(Mandatory=$true)][string]$filepath,
        # Either the column name to use as an index, or $null to use the row number
        [string]$keyname = $null
    )
    # Read the file into an array
    $rows = Import-Csv -LiteralPath $filepath
    # If nothing was read, return a blank hash and skip further processing
    if(-not $rows){return @{}}
    # Get the headers from the first row
    $headers = $rows[0].PSObject.Properties.Name
    # If we don't find the index header, throw and error
    if (($keyname) -and ($headers -notcontains $keyname)) {throw "Key '$keyname' not found."}
    # Create a hash to hold the results
    $csv_data = @{}
    # Start processing at the second row (zero based). If no index was specified, we will use this counter
    $rowctr = 1
    # Proceess each line in the file
    foreach($row in $rows){
        # Create a hash, preserving the order of the data inserted
        $typedRow = [ordered]@{}
        # Iterate through the headers
        foreach($h in $headers){
            # Get the value from the specified column
            $v = Get-Typed -value $row.$h
            # Add the value to the typed row hash, using the header as the key. This will convert numeric
            # values to their appropriate.    
            $typedRow[$h] = $v
        }
        # Determine the key value for this row based on the specified keyname. If no keyname was specified,
        # use the row counter as the key.
        if($keyname){$keyval = $typedRow[$keyname]} else {$keyval = $rowctr}
        # Add the converted data to the indexed hash
        $csv_data[$keyval] = $typedRow
        # Increment the row counter
        $rowctr++
    }
    # Send the data back to the caller
    return $csv_data
}
# Save-ToCsv -FilePath <string> -Data <hashtable>
#
# Parameters:
#   - FilePath: The full path to the CSV file to write. If the file already exists, it will be overwritten.
#   - Data: A hashtable containing the data to write to the CSV file. The keys of the hashtable will be ignored, 
#    and the values will be written as rows in the CSV file. Each value in the hashtable should itself be a hashtable
#    representing a row of data, with keys corresponding to column headers and values corresponding to the cell values for that row.
# Returns:
#   None. This function writes the data to a CSV file at the specified path.
# Description:
# This function takes a hashtable of data and writes it to a CSV file. The keys of the outer hashtable are ignored, and the values
# are expected to be hashtables representing rows of data. The function writes a header row based on the keys of the first row's hashtable,
# and then writes each row of data, quoting string values and leaving numeric values unquoted for better compatibility with Excel and other
# CSV readers.
#----------------------------------------------------------------------------------------------------------
function Save-ToCsv {
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,
        [Parameter(Mandatory)]
        [hashtable]$Data
    )
    # Create a StreamWriter for UTF-8 output
    $writer = [System.IO.StreamWriter]::new($FilePath, $false, [System.Text.UTF8Encoding]::new($false))
    try {
        $lineCtr = 0
        # Iterate through the hashtable entries
        foreach ($thiskey in $Data.keys) {
            # Get the sub-hash that actually contains the data
            $row = $Data[$thisKey]
            # First line → write header
            if ($lineCtr -eq 0) {
                $header = ($row.Keys | ForEach-Object { '"{0}"' -f $_ }) -join ","
                $writer.WriteLine($header)
            }
            # Write values (quote strings, leave numbers unquoted)
            $line = ($row.Values | ForEach-Object {
                if ($_ -is [string]) {
                    '"{0}"' -f $_
                } else {
                    $_.ToString()
                }
            }) -join ","
            # Write the data
            $writer.WriteLine($line)
            $lineCtr++
        }
    }
    finally {
        $writer.Close()
    }
}
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
function Get-Typed() {
    param(
        # The value to convert to its appropriate type
        [Parameter(Mandatory=$true)]
        $value
    )
    $RtnVal = $null
    # If there are only 0-9 characters in the value, it's an integer
    if($value -match '^[+-]?\d+$') {
        try {
            # If converting it to an int32 causes an overflow, convert it to an int64
            $RtnVal = [int32]$value
        } catch {$RtnVal = [int64]$value}
    # If there are only 0-9 characters in the value with a decimal, convert it to a double
    } elseif ($value -match '^[+-]?\d+\.\d+$'){
        $RtnVal = [double]$value
    # Anything else does not need a conversion
    } else {$RtnVal = $value}
    return $RtnVal
}
# ---------------------------------------------------------
#
# END FUNCTIONS
#
# ---------------------------------------------------------
