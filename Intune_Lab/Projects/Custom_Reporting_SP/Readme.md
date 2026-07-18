# Introduction

Four years ago, I got introduced to Intune. I was not impressed, it couldn't even report the start mode and status of a Windows service. 
It was clear it needed to be extended and having experience with Configuration Manager Compliance Baselines, I quickly embraced Custom Compliance Scripts with Remediation.  

The API for submitting JSON data to Log Analytics is changing and now requires authentication to a Service Principal.  Instead of using a Client Secret, I wanted to use a Client Certificate, but very few examples for this are available.  

Here is how I would do it.  

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=flat&logo=linkedin)](https://www.linkedin.com/in/ian-b-01828112)

---

# Files

## Documentation

**Secure Custom Inventory.pdf** — Step by step instructions for obtaining a test certificate, Service Principal, Data Collection Endpoint, Log Analytics Table and Data Collection Rule configuration, and more...

## Certificate Tools

**Get-Cert.ps1** — Powershell script to generate and export a self-signed trusted root certificate and the client certificate with Public and Private keys for lab use.

## Windows

**Windows_Custom_Inventory.ps1** — Windows Custom Compliance script using a Client Certificate to authenticate as a Service Principal.

**Windows_Custom_Inventory.log** — Sample log output of Windows_Custom_Inventory.ps1

**Install.ps1** — Powershell script to install the private key as a Win32 app in Intune with logging.

**Uninstall.ps1** — Powershell script to uninstall the private key as a Win32 app with logging.

**Detection.ps1** — Powershell script to detect if the private key is installed.

## MacOS

**MacOS_Custom_Inventory.sh** — MacOS Custom Compliance script using a Client Certificate to authenticate as a Service Principal.

**MacOS_Custom_Inventory.log** — Sample log output of Windows_Custom_Inventory.ps1

**Build_PKG.sh** - Bash script to automate package (.pkg) creation for bulk depployment of the private key.

**postinstall** - Bash script embedded in the package to install and remove the private key file after installation.

**Uninstall.sh** - Bash script for removing the public-private key pair.

**Detect.sh** - Bash script to properly report the installation status of the private key.

**JWT_Assertion.py** - Python code to use inline with Bash to obtain a JWT assertion and pass it back to Bash. Uses a substring match and the certificate validity period to determine which certificate to use.

## Intune

**Output.json** — Used to configure the Log Analytics table and DCR. Sample data submission in JSON format.
