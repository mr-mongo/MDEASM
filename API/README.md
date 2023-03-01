# MDEASM API
 MD External Attack Surface Management API helpers and examples.

 All these are based on the mdeasm.py helper. It is easiest to import it into the use case scripts and jupyter notebook if it is in the same directory.

### Initialize your measm.Workspaces object:
 >easm = mdeasm.Workspaces(workspace_name=<workspace_name>, tenant_id=<tenant_id>, subscription_id=<subscription_id>, client_id=<client_id>, client_secret=<client_secret>)

### Interact with MDEASM Workspaces
 >easm.get_workspaces()

 >easm.create_workspace(
 >  resource_group_name=<resource_group>, 
 >  location=<oneOf---easm._locations>,
 >  workspace_name=<new_workspace_name>)

### Retrieve MDEASM Workspace Assets and Risk Findings
 >easm.get_workspace_assets(
 >  query_filter='state = "confirmed" AND kind = "domain"',
 >  asset_list_name='owned_domains',
 >  get_all=True)

 >easm.get_workspace_assets(
 >  query_filter='state = "confirmed" AND kind = "host" AND ipAddress empty AND cname !empty',
 >  asset_list_name='hosts_with_cnames',
 >  get_all=True)

 >easm.get_workspace_asset_by_id(
 >  asset_id=<domain$$mydomain.com>)

 >easm.get_workspace_risk_observations(
 >  severity=<low,med,high>)

### Interrogate Asset details
 >easm.asset_lists()
 
 >>  hosts_with_cnames
 
 >>  owned_domains

 >easm.facet_filters()
 
 >>  kind
 
 >>  host
 
 >>  domain
 
 >>  headers
 
 >  ...etc...

 >easm.<AssetList_name>.assets[0].to_dict()

 >easm.<AssetList_name>.assets[0].pretty()

 >easm.facet_filters()

 >easm.filters.webComponents

 >easm.filters.cveId

 >easm.query_facet_filter(
 >  search=<search_term>,
 >  out_format=<print,csv,json>,
 >  out_path=<only_used_with_csv_or_json>)
