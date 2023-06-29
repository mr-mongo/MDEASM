#!/usr/bin/python3
import sys

#easiest to import mdeasm.py if it is in the same directory as this retreive_risk_observations.py script
#requires mdeasm.py VERSION 1.4
import mdeasm

if mdeasm._VERSION < 1.5:
    sys.exit(f"requires mdeasm.py VERSION 1.5; current version: {mdeasm._VERSION}")

easm = mdeasm.Workspaces()

#OWASP Top 10 Identifiers
#putting these all into a dictionary to allow iteration and to maintain OWASP Category --> CWE Identifier mapping
owasp_top_10 = {
    'broken_access_control':["CWE-22", "CWE-23", "CWE-35", "CWE-59", "CWE-200", "CWE-201", "CWE-219", "CWE-264", "CWE-275", "CWE-276", "CWE-284", "CWE-285", "CWE-352", "CWE-359", "CWE-377", "CWE-402", "CWE-425", "CWE-441", "CWE-497", "CWE-538", "CWE-540", "CWE-548", "CWE-552", "CWE-566", "CWE-601", "CWE-639", "CWE-651", "CWE-668", "CWE-706", "CWE-862", "CWE-863", "CWE-913", "CWE-922", "CWE-1275"],
    'cryptographic_failure':["CWE-261", "CWE-296", "CWE-310", "CWE-319", "CWE-321", "CWE-322", "CWE-323", "CWE-324", "CWE-325", "CWE-326", "CWE-327", "CWE-328", "CWE-329", "CWE-330", "CWE-331", "CWE-335", "CWE-336", "CWE-337", "CWE-338", "CWE-339", "CWE-340", "CWE-347", "CWE-523", "CWE-720", "CWE-757", "CWE-759", "CWE-760", "CWE-780", "CWE-706", "CWE-818", "CWE-916"],
    'injection':["CWE-20", "CWE-74", "CWE-75", "CWE-77", "CWE-78", "CWE-79", "CWE-80", "CWE-83", "CWE-87", "CWE-88", "CWE-89", "CWE-90", "CWE-91", "CWE-93", "CWE-94", "CWE-95", "CWE-96", "CWE-97", "CWE-98", "CWE-99", "CWE-100", "CWE-113", "CWE-116", "CWE-138", "CWE-184", "CWE-470", "CWE-471", "CWE-564", "CWE-610", "CWE-643", "CWE-644", "CWE-652", "CWE-917"],
    'insecure_design':["CWE-73", "CWE-183", "CWE-209", "CWE-213", "CWE-235", "CWE-256", "CWE-257", "CWE-266", "CWE-269", "CWE-280", "CWE-311", "CWE-312", "CWE-313", "CWE-316", "CWE-419", "CWE-430", "CWE-434", "CWE-444", "CWE-451", "CWE-472", "CWE-501", "CWE-522", "CWE-525", "CWE-539", "CWE-579", "CWE-598", "CWE-602", "CWE-642", "CWE-646", "CWE-650", "CWE-653", "CWE-656", "CWE-657", "CWE-799", "CWE-807", "CWE-840", "CWE-841", "CWE-927", "CWE-1021", "CWE-1173"],
    'security_misconfiguration':["CWE-2", "CWE-11", "CWE-13", "CWE-15", "CWE-16", "CWE-260", "CWE-315", "CWE-266", "CWE-520", "CWE-526", "CWE-537", "CWE-541", "CWE-547", "CWE-611", "CWE-614", "CWE-756", "CWE-776", "CWE-942", "CWE-1004", "CWE-1032", "CWE-1174"],
    'vulnerable_and_outdated_components':["Drupal", "WordPress", "Joomla"],
    'identification_and_authentication_failures':["CWE-255", "CWE-259", "CWE-287", "CWE-288", "CWE-290", "CWE-294", "CWE-295", "CWE-297", "CWE-300", "CWE-302", "CWE-304", "CWE-306", "CWE-307", "CWE-346", "CWE-384", "CWE-521", "CWE-613", "CWE-620", "CWE-640", "CWE-798", "CWE-940", "CWE-1216"],
    'software_and_data_integrity_failures':["CWE-345", "CWE-353", "CWE-426", "CWE-494", "CWE-502", "CWE-565", "CWE-784", "CWE-829", "CWE-830", "CWE-913"],
    'security_logging_and_monitoring_misconfiguration':["CWE-117", "CWE-223", "CWE-532", "CWE-778"],
    'server_side_request_forgery':["CWE-918"]
}

#iterate through owasp_top_10 and pull all results for each
for k,v in owasp_top_10.items():
    print(f"\nrunning query for {k}\n")
    owasp_query='","'.join(v)
    owasp_query = f'("{owasp_query}")'
    if k == 'vulnerable_and_outdated_components':
        owasp_query = f'webComponentNameVersion #in {owasp_query} AND cvssScore >= "5" AND state = confirmed'
    else:
        owasp_query = f'cweID in {owasp_query} AND state = confirmed'
    easm.get_workspace_assets(query_filter=owasp_query, asset_list_name=k, max_page_size=100, get_all=True)

for k,v in owasp_top_10.items():
    print(f"\nfacet filter search for {k}\n")
    if k == 'vulnerable_and_outdated_components':
        for component in v:
            
            #print results to terminal
            #easm.query_facet_filter(search=component, facet_filter='webComponents')
            
            #save results to file
            easm.query_facet_filter(search=component, facet_filter='webComponents',out_format='csv',out_path=f"C:\\Users\\Public\\{k}")
    else:
        for cwe in v:
            
            #print results to terminal
            #easm.query_facet_filter(search=cwe, facet_filter='cveId')
            
            #save results to file
            easm.query_facet_filter(search=cwe, facet_filter='cveId',out_format='csv',out_path=f"C:\\Users\\Public\\{k}")

