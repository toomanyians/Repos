# Introduction

Intune is an interesting beast. It has strength and weaknesses. It's pretty good at managing devices, but clearly needs better reporting and dashboarding. It's Microsoft's idea of how things should be, a view which is not always grounded in the corporate realities driven by auditors and regulators.

These are projects I have decided to take on in my own time to experiment and see if somehow I can "tame the beast" and make sense of this fragmented and incoherent platform to produce some sort of enterprise wide view into device compliance data.

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=flat&logo=linkedin)](https://www.linkedin.com/in/ian-b-01828112)

---

# Projects

## Custom Reporting SP (Service Principal)

There are certain data points that Intune cannot, and probably never will be able to report. Its capabilities can be extended through the use of custom compliance scripts to return data back to some central point (Log Analytics, SQL, make a choice...).

This extended data need could be driven by delays in Intune reporting (hardware inventory every week), data extraction limitations (throttling) or one of many other factors including trust.

This project uses a custom compliance script to submit JSON data to the Log Analytics Data Ingestion API V2.0. It requires the submitter to authenticate to a Service Principal (App Registration) and instead of using a client secret, I take the more secure route - a client certificate.

## **Custom Reporting AF (Azure Function)**

Recently, I have seen a move away from using Log Analytics and authenticated data submission to using Azure Functions.

I think Azure Functions have some promise, especially in a serverless microservices environment, but I question its use for this purpose.

This will be my exploration into an alternative to my preferred, and I suspect, a more secure approach to data aquisition.

## **Data_Extraction**

Intune presents data in a few ways, but when you have three environments and thousands of devices the report on, you still need a way to extract and transform the data to build meaningful metrics.

In large environments, iterating through lists of devices can be detrimental due to data limits, throttling, infrastructure issues and such.

This is where I will be documenting the data and how to collect it reliably into some sort of ETL platform (PostGres, SharePoint, etc) from:

- **Graph API** - REST API calls, either device summaries (List) or iterating through device records (Get)

- **Graph API Reports** - A much more efficient method for gathering bulk data from Graph API

- **Log Analytics API** - Processing customized datasets in bulk with transorms at the source for data normalization and de-duplication.
