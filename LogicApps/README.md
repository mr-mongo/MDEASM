#### Logic App for importing Azure Public IPs into an EASM Workspace

This template will:
  1. Create a Logic App that will query the Azure REST API for Azure Public IPs and add them to an EASM Workspace
     1. The IPs will be assigned a Label of your choice (defaults to `AzureIP`). If this Label does not exist, the Logic App will create it for you.
     2. The IPs will be assigned a State of your choice (defaults to `Dependency`)
  2. Create the following Role Assignments:
     1. Subscription Reader for the Logic App's managed identity to allow it to query the REST API for Public IPs
     2. EASM Resource Group Contributor for the Logic App's managed identity to allow it to read and write to the EASM Workspace

The Logic App will run immediately on deployment, and then every 1 week on Monday, 00:00 UTC. The recurrence is configurable within the Logic App's trigger.
 This first run **will fail** due to the role assignments not having enough time to propagate. You can re-run the Logic App manually or wait for the next scheduled recurrence. 

The `Deploy to Azure` button below will only use the ARM template and parameters JSON file. These were generated from a Bicep template, which is included here for reference.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fmr-mongo%2FMDEASM%2Fmain%2FLogicApps%2FGetAzurePublicIPs.json)