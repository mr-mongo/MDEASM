import mdeasm
from dateutil import parser

# name of the EASM resource
workspace_name = ''

tenant_id = ''
subscription_id = ''

# service principal needs to have Contributor permissions on EASM resource
client_id = ''
client_secret = ''

easm = mdeasm.Workspaces(workspace_name=workspace_name, tenant_id=tenant_id, subscription_id=subscription_id, client_id=client_id, client_secret=client_secret)

# the cvss severity queries that populate the dashboard
cvss_10 = 'state = confirmed | kind = page | rootUrl = true | (cvssScore = 10 or cvss3BaseScore = 10)'
cvss_9 = 'state = confirmed | kind = page | rootUrl = true | (cvssScore = 9 or cvss3BaseScore = 9)'
cvss_8 = 'state = confirmed | kind = page | rootUrl = true | (cvssScore = 8 or cvss3BaseScore = 8)'
cvss_7 = 'state = confirmed | kind = page | rootUrl = true | (cvssScore = 7 or cvss3BaseScore = 7)'
cvss_6 = 'state = confirmed | kind = page | rootUrl = true | (cvssScore = 6 or cvss3BaseScore = 6)'
cvss_5 = 'state = confirmed | kind = page | rootUrl = true | (cvssScore = 5 or cvss3BaseScore = 5)'
cvss_4 = 'state = confirmed | kind = page | rootUrl = true | (cvssScore = 4 or cvss3BaseScore = 4)'
cvss_3 = 'state = confirmed | kind = page | rootUrl = true | (cvssScore = 3 or cvss3BaseScore = 3)'
cvss_2 = 'state = confirmed | kind = page | rootUrl = true | (cvssScore = 2 or cvss3BaseScore = 2)'
cvss_1 = 'state = confirmed | kind = page | rootUrl = true | (cvssScore = 1 or cvss3BaseScore = 1)'

# this will get all the assets with CVSS Score of 10
# that will include all the other recent CVEs on the asset, regardless of score
# this function will also auto-create facet filters for all asset details
# which will be available through <mdeasm.Workspaces object>.filters.<filter_name>
easm.get_workspace_assets(query_filter=cvss_10, asset_list_name='cvss_10', max_page_size=100, get_all=True)

print(f"checking {len(easm.cvss_10.assets)} assets with CVE CVSS Scores")


# if we chose not to auto-create facet filters above (if we passed 'auto_create_facet_filters=False')
# we can explicitly create individual filters with create_facet_filter()
# we can extract all the CVEs and Scores from the assets we retrieved above
# similar to above, this will still include those CVEs with scores less than 10
# CVEs are part of the webComponent detail, and so can only be parsed out using attribute_name='webComponents' 
#easm.create_facet_filter(asset_list_name='cvss_10', attribute_name='webComponents')


# we can query that just-created facet filter for any search term (case insensitive)
# this will find all CVEs that contain '2022' and print all the details found in the facet filter
easm.query_facet_filter(search='CVE-2022-22720', facet_filter='cveId')


# if we need to conduct a more thorough or granular search through the facet filter
# we can use any dict method and iterate through all the keys/values to evaluate/find what we need
for key,val in easm.filters.cveId.items():
    web_component = key[0]
    cve_id = key[1]
    cve_score = key[2]
    asset_count = val['count']
    asset_list = val['assets']
    if cve_score > 9:
        print(f"\nWeb Component: {web_component}, CVE: {cve_id}, CVSS Score: {cve_score}, Asset Count: {asset_count}")
        print(asset_list)
