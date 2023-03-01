# MDEASM
 MD External Attack Surface Management API helpers and examples.

 All these are based on the mdeasm.py helper. It is easiest to import it into the use case scripts and jupyter notebook if it is in the same directory.

 Initialize your measm.Workspaces object:
 >easm = mdeasm.Workspaces(workspace_name=<workspace_name>, tenant_id=<tenant_id>, subscription_id=<subscription_id>, client_id=<client_id>, client_secret=<client_secret>)

 Interact with MDEASM Workspaces
 >easm.create_workspace(resource_group_name=<resource_group>, location=<oneOf easm._locations>, workspace_name='')

 >easm.get_workspaces()

 >easm.get_workspace_assets(query_filter=<easm_query>, asset_list_name=<output_asset_list_attribute>, page=<starting_page_number>, max_page_size=<0-100>, max_page_count=<number_of_pages_to_retrieve>, get_all=<boolean>, auto_create_facet_filters=<boolean>, get_recent=<boolean>, last_seen_days_back=<keep_asset_details_seen_within_N_days>, date_range_start=<keep_asset_details_seen_starting_at_YYYY-MM-DD>, date_range_end=<keep_asset_details_seen_ending_at_YYYY-MM-DD>, workspace_name=<workspace_name>)

 >