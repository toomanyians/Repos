# Introduction

Reporting for just one tenant in Azure is relatively simple. Seperation of environments and SDLC (Dev, UAT, Prod) mean that most corporations have three tenants. Adding the size of the environment and reporting requirements adds more complexity.

Often it makes sense to collect all the data from all three tenants, and this requires some central storage for transformation of data for processing efficiency and historical data maintenance.

For large infrastructures with prohibitive retention policies, Sharepoint is not an option, but it can be for smaller, less regulated environments.

I will be using a PostGres server as a Data Warehouse to serve up dashboards in Power BI and Excel reports in SharePoint.

Stay tuned..  

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=flat&logo=linkedin)](https://www.linkedin.com/in/ian-b-01828112)

---

# Folders

I am going to provide two sets of identical code because I have found that Python is actually much more efficient than Powershell for REST based data extraction. Powershell is still useful since it doesn't require installation on Windows and rarely has vulnerabilities.

Here we will focus on extracting, transforming and loading data (ETL) from the following sources:

- **Graph API** - Standard REST Calls, documented here: [Microsoft Graph REST API beta endpoint reference - Microsoft Graph beta | Microsoft Learn](https://learn.microsoft.com/en-us/graph/api/overview?view=graph-rest-beta)

- **Graph API Reports** - Documented here: [Intune Graph API - Reports and Properties - Microsoft Intune | Microsoft Learn](https://learn.microsoft.com/en-us/intune/device-management/reports/ref-graph-available-reports)

- **Log Analytics** - Documented here: [Log Analytics REST APIs | Microsoft Learn](https://learn.microsoft.com/en-us/rest/api/loganalytics/)

## /Documents

Documentation more general in nature that is common between both programming languages. Threading, parallelization, error and throttling handling and approaches to optimize performance.

## /Powershell

Documentation and code examples for EntraID and Intune using Graph API, Graph API reports and Log Analytics specific to Powershell.

## /Python

Documentation and code examples for EntraID and Intune using Graph API, Graph API reports and Log Analytics. specific to Python.

## /PostGres

What you need to know to install and maintain a PostGres server to ingest the data, perform SQL based ETL processes and provide the data in a meaningful form.
