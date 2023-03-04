 **version 1.0**, JAN 2023

 **version 1.1**, JAN 2023
~~added create_facet_filter support for when attribute_value is itself a list of dicts~~
added deduping for `create_facet_filter()` output
changed `self._state_map` from `dict` to `requests.structures.CaseInsensitiveDict()`
added `get_workspace_asset_summaries()`
added default option to auto-create facet filters  
also made facet filters a class object, so asset filters are now object attributes
added csv and json file output options for `query_facet_filter()`

 **version 1.2**, FEB 2023
added `get_workspace_risk_observations()` for retrieving asset details for high,medium,low observations (reports/assets:summarize --> reports/assets:snapshot --> /assets)
adjusted evaluation of date_range_start (any asset details where 'lastSeen' is AFTER the supplied date will be included)
adjusted evaluation of date_range_end (any asset details where 'lastSeen' is BEFORE the supplied date will be included)
added 'names' list support to `create_discovery_group()` disco_custom arg
moved `create_discovery_group()` dependency from `__run_discovery_group__()` to `__workspace_query_helper__()`
removed `__run_discovery_group__()`
fixed bug when `__get_discovery_group_runs__()` would be called without disco_name arg
added `asset_lists()` and `facet_filters()` to enable easier finding of AssetList and FacetFilter objects within a mdeasm.Workspaces object

**version 1.3**, FEB 2023
added `create_or_update_label()`
added `get_labels()`
adjusted `update_asset_states()` --> `update_assets()`
added `update_assets()` support for adding/removing asset labels
added `update_assets()` function summary/usage details
adjusted `__facet_filter_helper__()` eval of assetSecurityPolicies to only include `isAffected=True`
adjusted `poll_asset_state_change()` print behavior
automatically run `get_workspaces()` on Workspaces initialization
`Workspaces._workspaces` dict now includes URI+PATH for both Data Plane (`_workspaces[<workspace_name>][0]`) & Control Plane (`_workspaces[<workspace_name>][1]`)
adjusted `__workspace_query_helper__()` to retrieve Data Plane or Control Plane URI+PATH automatically