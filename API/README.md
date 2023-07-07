# MDEASM API
MD External Attack Surface Management API helpers and examples.

All these are based on the mdeasm.py helper. It is easiest to import it into the use case scripts and jupyter notebook if it is in the same directory.


## Environment file

1. copy the `.env.template` file to `.env` in the project root directory
2. modify with your specific tenant, subscription, service principal, etc

## Required Python package imports

requests, PyJWT, python-dateutil, python-dotenv
```
python3 -m pip install requests PyJWT python-dateutil python-dotenv --upgrade
```
### Initialize your mdeasm.Workspaces object:
```
import mdeasm
```
```
#can pass arguments to override or supplement .env defaults
easm = mdeasm.Workspaces()
```
### Interact with MDEASM Workspaces
```
#can pass arguments to override or supplement .env defaults
easm.get_workspaces()
```
```
#can pass arguments to override or supplement .env defaults
easm.create_workspace()
```
### Retrieve MDEASM Workspace Assets and Risk Findings
```
easm.get_workspace_assets(  
    query_filter='state = "confirmed" AND kind = "domain"',  
    asset_list_name='owned_domains',  
    get_all=True)
```
```
easm.get_workspace_assets(  
    query_filter='state = "confirmed" AND kind = "host" AND ipAddress empty AND cname !empty',  
    asset_list_name='hosts_with_cnames',  
    get_all=True)
```
```
easm.get_workspace_asset_by_id(  
    asset_id='domain$$mydomain.com')
```
```
easm.get_workspace_risk_observations(  
    severity=<low,med,high>)
```
### Interrogate Asset details
```
easm.asset_lists()
```
>hosts_with_cnames  
owned_domains

```
easm.hosts_with_cnames.assets[0].to_dict()
```
```
easm.owned_domains.assets[0].pretty()
```
```
easm.facet_filters()  
```
>kind  
host  
domain  
headers  
...etc...
```
easm.filters.host
```
```
easm.filters.headers
```
```
easm.query_facet_filter(  
    search=<search_term>,  
    out_format=<print,csv,json>,  
    out_path=<only_used_with_csv_or_json>)
```