#!/usr/bin/python3
import sys

#easiest to import mdeasm.py if it is in the same directory as this retreive_risk_observations.py script
#requires mdeasm.py VERSION 1.4
import mdeasm

if mdeasm._VERSION < 1.4:
    sys.exit(f"requires mdeasm.py VERSION 1.4; current version: {mdeasm._VERSION}")

easm = mdeasm.Workspaces()

# a query for domain, host, page, and ip assets with CNs
approved_ips_query = 'state = "confirmed" AND kind in ("domain", "host", "ipAddress", "page") AND subjectCommonName !empty'

# this will run the query above and create facet filters for all asset details
easm.get_workspace_assets(query_filter=approved_ips_query, asset_list_name='assets_with_cert_cn', max_page_size=100, get_all=True)

# if we don't want to create facet filters for everything,
# we instead pass auto_create_facet_filters=False to get_workspace_assets() above
# and create just the 'subjectCommonNames' facet filter by passing in the asset_list_name we just defined above
# and the name of an attribute to extract from all the assets in that asset list
# in both cases (auto and manual) the facet filter will be accessible
# in <mdeasm.Workspaces object>.filters.<attribute_name> --> easm.filters.subjectCommonNames
#easm.create_facet_filter(asset_list_name='assets_with_cert_cn', attribute_name='subjectCommonNames')

print(f"found {len(easm.assets_with_cert_cn.assets)} assets with subjectCommonName values")

# a brief search for a few common TLDs (helps filter out CA certs)
# this is a regex search, so can pass any python regex tokens/quantifiers/classes/etc
# this will write results to CSV files in the scripts current directory
# can also choose out_format='json', out_format='print', and/or out_path for different write options/locations
easm.query_facet_filter(search='\.com|\.net|\.ca|\.co', facet_filter='subjectCommonNames', out_format='csv')
print('')
