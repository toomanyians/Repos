#------------------------------------
# Configuration
#------------------------------------
$CertName = 'AF_Collect'
$functionUrl = "https://intune-reporting-h9erhpghbnfybqf0.canadacentral-01.azurewebsites.net/api/DataCollect"
#------------------------------------
# Get our certificate
$cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.FriendlyName -eq $CertName }
# Create the body
$body = @{ name = "Ian" } | ConvertTo-Json
# Submit to our Azure function
$response = Invoke-WebRequest `
    -Uri $functionUrl `
    -Method Post `
    -Body $body `
    -ContentType "application/json" `
    -UseBasicParsing `
    -Certificate $cert
# Output what the Azure function sent back
$response.Content