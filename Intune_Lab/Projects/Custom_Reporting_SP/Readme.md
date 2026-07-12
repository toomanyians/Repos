# Introduction

Four years ago, I got introduced to Intune. I was not impressed, it couldn't even report the start mode and status of a Windows service. 
It was clear it needed to be extended and having experience with Configuration Manager Compiance Baselines, I quickly embraced Custom Compliance Scripts with Remediation.  

The API for submitting JSON data to Log Analytics is changing and now requires authentication to a Service Principal.  Instead of using a Client Secret, I wanted to use a Client Certificate, but very few examples for this are available.  

Here is how I would do it.  

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=flat&logo=linkedin)](https://www.linkedin.com/in/ian-b-01828112)

---

# Files

## Documentation

**Secure Custom Inventory.pdf** — Step by step instructions for obtaining a test certificate, Service Principal, Data Collection Endpoint, Log Analytics Table and Data Collection Rule configuration, and more...

## Certificate Tools

**Get-Cert.ps1** — Powershell script to generate and export a self-signed certificate Public and Private keys.

## Windows

**Windows_Custom_Inventory.ps1** — Windows Custom Compliance script using a Client Certificate to authenticate as a Service Principal.

**Install.ps1** — Powershell script to install the private key as a Win32 app in Intune with logging.

**Uninstall.ps1** — Powershell script to uninstall the private key as a Win32 app with logging.

**Detection.ps1** — Powershell script to detect if the private key is installed.

**Inventory.log** — Sample log output of Windows_Custom_Inventory.ps1

## MacOS

**MacOS_Custom_Inventory.sh** — MacOS Custom Compliance script using a Client Certificate to authenticate as a Service Principal.  
Pending updates:

- Update certificate location code to allow multiple subject matches

- Add logging for remote log retrieval and analysis.

**Build_PKG.sh** - Bash script to automate package (.pkg) creation for bulk depployment of the private key.

**postinstall** - Bash script embedded in the package to install and remove the private key file after installation.

**Detect.sh** - Bash script to properly report the installation status of the private key.

**JWT_Assertion.py** - Python code to use inline with Bash to obtain a JWT assertion and pass it back to Bash.

## Intune

**Output.json** — Used to configure the Log Analytics table and DCR. Sample data submission in JSON format.
