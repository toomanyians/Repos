#------------------------------------
# Configuration
#------------------------------------
$functionUrl = "http://localhost:7071/api/DataCollect"
#------------------------------------
# Create the body
$body = @{ name = "Ian" } | ConvertTo-Json
# Submit to our Azure function
$response = Invoke-WebRequest `
    -Uri $functionUrl `
    -Method Post `
    -Body $body `
    -ContentType "application/json"
# Output what the Azure function sent back
$response.Content