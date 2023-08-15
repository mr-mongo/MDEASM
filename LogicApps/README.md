# MDEASM
 MD External Attack Surface Management Logic App for importing Azure Public IPs into a Workspace

### REQUIRED: a Service Principal (a.k.a. AzureAD App Registration) which you know the Client ID and Client Secret

This template will:
  1. Create a Key Vault and add the Client Secret
  2. Create a Logic App that will query the Azure REST API for Azure Public IPs and add them to an EASM Workspace
  3. Create the following Role Assignments:
     1. Subscription Reader for the Logic App's managed identity to allow it to query the API for Public IPs
     2. Key Vault Secrets User for the Logic App's managed identity to allow it to get the Client Secret (**Note that you will need to assign yourself a RBAC permission, such as `Key Vault Administrator`, to be able to see and manage the secret**)
     3. EASM Resource Group Contributor for the Logic App's managed identity to allow it to create Labels
     4. EASM Resource Group Contributor for the Service Principal to allow it to add the Azure Public IPs to the EASM Workspace

The `Deploy to Azure` button below will only use the ARM template. The corresponding Bicep template is included here simply for reference.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fmr-mongo%2FMDEASM%2Fmain%2FLogicApps%2FGetAzurePublicIPs.json)