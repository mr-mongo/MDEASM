#!/usr/bin/python3
import sys

#easiest to import mdeasm.py if it is in the same directory as this retreive_risk_observations.py script
#requires mdeasm.py VERSION 1.4
import mdeasm

if mdeasm._VERSION < 1.4:
    sys.exit(f"requires mdeasm.py VERSION 1.4; current version: {mdeasm._VERSION}")

easm = mdeasm.Workspaces()

#query for hosts with at least one CNAME record but no live IP Address
hosts_with_cnames = 'state = "confirmed" AND kind = "host" AND ipAddress empty AND cname !empty'
#query for domains owned by the org
owned_domains = 'state = "confirmed" AND kind = "domain"'

#retreive assets for each of the query filters
#if we want to automatically extract all unique attribute values and associated assets, we would not change auto_create_facet_filters from its default value True (`auto_create_facet_filters=True`)
easm.get_workspace_assets(query_filter=hosts_with_cnames, asset_list_name='hosts_with_cnames', max_page_size=100, get_all=True, auto_create_facet_filters=False)

#since we only care about the CNAME attribute and values, we can disable auto_create_facet_filters for all attributes in the above function, and instead explicitly create the CNAME facet filter
easm.create_facet_filter(asset_list_name='hosts_with_cnames', attribute_name='cnames')

#we don't need to auto-create any facet filters for this either, as all we care about are the domain name values
easm.get_workspace_assets(query_filter=owned_domains, asset_list_name='owned_domains', max_page_size=100, get_all=True, auto_create_facet_filters=False)

#create the list of domain names
domain_list = []
for asset in easm.owned_domains.assets:
    domain_list.append(asset.name)

#compare the CNAME record values in the facet filter with the list of domain names
#and only keep (print) those where the CNAME record does not end with a domain owned by the Org
for cname,assetlist in easm.filters.cnames.items():
    if not cname[0].endswith(tuple(domain_list)):
        print('CNAME record points to asset:', cname[0])
        print('CNAME records:', ', '.join(assetlist['assets']).replace('host$$',''))
        #include an empty line after each result set just for a bit easier viewing of output
        print()
        #alternative printing if its preferred to keep the Asset Type indicator (host$$) with the asset name
        #print('Assets with CNAME record:', ','.join(assetlist['assets']))
