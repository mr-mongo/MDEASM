import mdeasm
from dateutil import parser

easm = mdeasm.Workspaces(workspace_name=mdeasm.workspace_name, tenant_id=mdeasm.tenant_id, subscription_id=mdeasm.subscription_id, client_id=mdeasm.client_id, client_secret=mdeasm.client_secret)

# the certificate expiration queries that populate the dashboard
certs_expired_query = 'state = confirmed | kind = sslCert | sslCertExpiration = Expired'
certs_expire_30days_query = 'state = confirmed | kind = sslCert | sslCertExpiration = Expires30'
certs_expire_60days_query = 'state = confirmed | kind = sslCert | sslCertExpiration = Expires60'
certs_expire_90days_query = 'state = confirmed | kind = sslCert | sslCertExpiration = Expires90'
certs_expire_after90days_query = 'state = confirmed | kind = sslCert | sslCertExpiration = ExpiresAfter90'

easm.get_workspace_assets(query_filter=certs_expired_query, asset_list_name='expired_certs', max_page_size=100, get_all=True)

# the catch for this use case is that it will not produce valid results until
# a second discovery has been run on the workspace (usually 7 or 8 days after creation)
# this is due to the 'lastSeen' date on an asset initially showing a date on/about its creation in the workspace
# subsequent discovery runs will update this 'lastSeen' date to when our scanners actually last saw and interacted with it on the public internet

print(f"checking {len(easm.expired_certs.assets)} expired certificates")

true_pos_counter = 0
for cert in easm.expired_certs.assets:
    if parser.parse(cert.lastSeen) > parser.parse(cert.invalidAfter):
        #print(f"\ncertificate {cert.name} invalid after: {cert.invalidAfter}")
        #print(f"certificate {cert.name} last seen: {cert.lastSeen}")
        #print(f"{cert.name} lastSeen is more recent than invalidAfter")
        #print('performing additional validation check on the asset with this cert')
        
        asset_id = cert.auditTrail[-1]['kind'] + '$$' + cert.auditTrail[-1]['name']
        easm.get_workspace_asset_by_id(asset_id=asset_id)
        try:
            for asset_cert in getattr(easm, asset_id).sslCerts:
                if asset_cert['sha1'] == cert.name:
                    #print(f"{cert.name} found on asset {asset_id}")
                    if asset_cert['recent']:
                        print(f"\nTrue Positive! {cert.name} IS recent on {asset_id}")
                        true_pos_counter += 1
                    else:
                        #print(f"False Positive! {cert.name} is NOT recent on {asset_id}")
                        pass
        except AttributeError:
            #print(f"{asset_id} has no recent certs, so False Positive!")
            pass

print(f"total true positives found: {true_pos_counter}")

