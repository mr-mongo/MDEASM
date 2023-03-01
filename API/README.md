# MDEASM API
 MD External Attack Surface Management API helpers and examples.

 All these are based on the mdeasm.py helper. It is easiest to import it into the use case scripts and jupyter notebook if it is in the same directory.

### Initialize your measm.Workspaces object:
 >easm = mdeasm.Workspaces(workspace_name=<workspace_name>, tenant_id=<tenant_id>, subscription_id=<subscription_id>, client_id=<client_id>, client_secret=<client_secret>)

### Interact with MDEASM Workspaces
 >easm.get_workspaces()

### Retrieve MDEASM Workspace Assets and Risk Findings
 >easm.get_workspace_assets(
 >  query_filter=<easm_query>,
 >  asset_list_name=<output_asset_list_attribute>,
 >  max_page_size=<0-100>,
 >  get_all=<boolean>)

 >easm.get_workspace_asset_by_id(
 >  asset_id=<domain$$mydomain.com>)

 >easm.get_workspace_risk_observations(
 >  severity=<low,med,high>)

### Interrogate Asset details
 >easm.assetList.assets

 >easm.assetList.assets[0].to_dict()

 >easm.assetList.assets[0].pretty()

 >easm.filters.webComponents

 >easm.filters.cveId

 >easm.query_facet_filter(
 >  search=<search_term>,
 >  out_format=<print,csv,json>,
 >  out_path=<only_used_with_csv_or_json>)
