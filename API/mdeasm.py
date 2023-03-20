#!/usr/bin/python3

_VERSION = 1.4
# Created by Josh Randall
# jorandall@microsoft.com
# 
# CHANGELOG
# https://github.com/fer39e4f/MDEASM/blob/main/API/changelog.md
#
# TODO 
#   create/update azure resource tags
#   delete azure resource
#   delete disco group (endpoint bugged)
#   asset snapshots
#   create/update saved filters
#   get saved filters
#   delete saved filters
#   cancel tasks


import requests, time, urllib.parse, jwt, datetime, base64, uuid, re, binascii, logging, json, pathlib, os
from dateutil import parser
from dotenv import load_dotenv

load_dotenv()

log_level = 'WARNING'   ## DEBUG,INFO,WARNING,ERROR,CRITICAL ##

logging.basicConfig(format='%(asctime)s - %(levelname)s - %(funcName)s - %(message)s', datefmt='%d-%b-%y %H:%M:%S', level = getattr(logging, log_level))

class Workspaces:
    _state_map = requests.structures.CaseInsensitiveDict({
        'Approved':'confirmed', 'Candidate':'candidate', 'Dependency':'associatedThirdparty', 'MonitorOnly':'associatedPartner', 'RequiresInvestigation':'candidateInvestigate', 'Dismissed':'dismissed'})
    _easm_regions = [
        'southcentralus','westus3','eastus','eastasia','swedencentral','australiaeast','japaneast']
    _metric_categories = [
        'priority_high_severity','priority_medium_severity','priority_low_severity']
    _metrics = [
        'cvss_score_critical','cvss_score_high','cvss_score_medium','cvss_score_low','unique_registrars','websites','unique_registrants','client_update_prohibited','client_transfer_prohibited','client_delete_prohibited','epp_none','owned_asns','third_party_asns','ssl_sha256','ssl_cert_sha1','ssl_cert_md5','ssl_cert_expired','ssl_cert_org_units','ssl_cert_orgs','site_status_active','site_status_inactive','site_status_requires_authorization','site_status_broken','site_status_browser_error','site_status_broken_cert_issue','site_status_active_cert_issue','site_status_requires_authorization_cert_issue','site_status_browser_error_cert_issue','pii_https','pii_http','pii_ssl_posture_md5','pii_ssl_posture_sha1','pii_ssl_posture_sha256','pii_ssl_posture_other','pii_ssl_posture_nocert','login_https','login_http','login_ssl_posture_md5','login_ssl_posture_sha1','login_ssl_posture_sha256','login_ssl_posture_other','login_ssl_posture_nocert','first_party_cookie_violation_https','first_party_cookie_violation_http','third_party_cookie_violation_https','third_party_cookie_violation_http']
    _label_colors = [
        'red','green','blue','purple','brown','gray','yellow','bronze','lime','teal','pink','silver']
    #'cookies':('cookieDomain','cookieName')
    #'sslCerts':('issuerAlternativeNames','issuerCommonNames','issuerCountry','issuerLocality','issuerOrganizationalUnits','issuerOrganizations','issuerState','keyAlgorithm','keySize','organizationalUnits','organizations','selfSigned','serialNumber','sha1','sigAlgName','sigAlgOid','subjectAlternativeNames','subjectCommonNames','subjectCountry','subjectLocality','subjectOrganizationalUnits','subjectOrganizations','subjectState','validationType','version')
    #'webComponents':('name','type','version','cve,name','cve,cvssScore','cve,cvss3Summary,baseScore')
    _facet_filters = {
        'assetSecurityPolicies':('policyName','description'),'attributes':('attributeType','attributeValue'),'banners':('banner','port'),'cookies':('cookieName'),'finalIpBlocks':('ipBlock'),'headers':('headerName','headerValue'),'ipBlocks':('ipBlock'),'location':('value,countrycode','value,countryname','value,latitude','value,longitude'),'reputations':('threatType','listName'),'resourceUrls':('url'),'responseHeaders':('headerName','headerValue'),'services':('port','scheme','portStates,value'),'soaRecords':('nameServer','email','serialNumber'),'sslServerConfig':('cipherSuites','tlsVersions'),'webComponents':('name','type','version'),'cveId':('webComponent','name','cvssScore')}

    def __init__(self, tenant_id=os.getenv("TENANT_ID"), subscription_id=os.getenv("SUBSCRIPTION_ID"), client_id=os.getenv("CLIENT_ID"), client_secret=os.getenv("CLIENT_SECRET"), workspace_name=os.getenv("WORKSPACE_NAME"), *args, **kwargs) -> None:
        if not (tenant_id and subscription_id and client_id and client_secret):
            logging.error('missing a required argument. check your .env file for missing CLIENT_ID, CLIENT_SECRET, TENANT_ID, and/or SUBSCRIPTION_ID values')
            raise Exception(f"CLIENT_ID: {client_id}, CLIENT_SECRET: {client_secret[:5] + ('*' * 30)}, TENANT_ID: {tenant_id}, SUBSCRIPTION_ID: {subscription_id}")
        self._tenant_id = tenant_id
        self._subscription_id = subscription_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._default_workspace_name = workspace_name
        self._cp_token = self.__bearer_token__()
        self._dp_token = self.__bearer_token__(data_plane=True)
        self._workspaces = requests.structures.CaseInsensitiveDict()
        self._region = os.getenv("EASM_REGION")
        self._resource_group = os.getenv("RESOURCE_GROUP_NAME")
        self.get_workspaces(workspace_name=workspace_name)

    def __bearer_token__(self, data_plane=False):
        url = f"https://login.microsoftonline.com/{self._tenant_id}/oauth2/v2.0/token"
        headers = {'Content-Type':'application/x-www-form-urlencoded'}
        if data_plane:
            data = {'grant_type': 'client_credentials', 'client_id': self._client_id, 'client_secret': self._client_secret, 'scope': 'https://easm.defender.microsoft.com/.default'}
            logging.info('data plane token retrieved')
        else:
            data = {'grant_type': 'client_credentials', 'client_id': self._client_id, 'client_secret': self._client_secret, 'scope': 'https://management.azure.com/.default'}
            logging.info('control plane token retrieved')
        r = requests.post(url, headers=headers, data=data)
        if r.status_code != 200:
            logging.error(r.status_code)
            raise Exception(r.text)
        else:
            return(r.json()['access_token'])

    def __token_expiry__(self, token):
        try:
            expiry = jwt.decode(token, options={"verify_signature": False})['exp']
            now = int(time.time())
            if now - 30 >= expiry:
                logging.debug(f"{now} - 30 >= {expiry}")
                return(True)
            else:
                return(False)
        except KeyError:
            return(True)
        except jwt.DecodeError:
            return(True)

    def __validate_asset_id__(self, asset_id):
        match = re.match(r'(as\$\$\S+|contact\$\$\S+|domain\$\$\S+|host\$\$\S+|ipAddress\$\$\S+|ipBlock\$\$\S+|page\$\$\S+|sslCert\$\$\S+)', asset_id)
        if match:
            logging.debug(f"{asset_id} matches a valid asset.id format")
            verified_asset_id = base64.b64encode(asset_id.encode()).decode()
        else:
            logging.debug(f"{asset_id} does not match any asset.id format")
            try:
                if uuid.UUID(asset_id):
                    logging.debug(f"{asset_id} matches a valid UUID format")
                    verified_asset_id = asset_id
            except ValueError:
                try:
                    if base64.b64encode(base64.b64decode(asset_id.encode())).decode() == asset_id:
                        logging.debug(f"{asset_id} is valid base64")
                        verified_asset_id = asset_id
                except binascii.Error:
                    logging.error('invalid base64')
                    raise Exception(asset_id)
            except Exception:
                logging.error('invalid uuid')
                raise Exception(asset_id)
        return(asset_id, verified_asset_id)

    def __set_default_workspace_name__(self, workspace_name):
        self._default_workspace_name = workspace_name
        logging.info(f"default workspace name set: {workspace_name}")

    def __verify_workspace__(self, workspace_name):
        if workspace_name not in self._workspaces:
            self.get_workspaces(workspace_name=workspace_name)
            if workspace_name not in self._workspaces:
                logging.debug(f"{workspace_name} not found")
                return(False)
            else:
                logging.debug(f"{workspace_name} found")
                self.__set_default_workspace_name__(workspace_name)
                return(True)
        else:
            logging.debug(f"{workspace_name} found")
            self.__set_default_workspace_name__(workspace_name)
            return(True)

    def __get_discovery_group_runs__(self, disco_name='', workspace_name=''):
        if not workspace_name:
            workspace_name = self._default_workspace_name
        if self.__verify_workspace__(workspace_name):
            disco_results = {}
            if disco_name:
                disco_results[disco_name] = []
                r = self.__workspace_query_helper__('__get_discovery_group_runs__', method='get', endpoint=f"discoGroups/{disco_name}/runs", workspace_name=workspace_name)
                for run in r.json()['content']:
                    disco_results[disco_name].append({'state':run['state'], 'submittedDate':run['submittedDate'], 'completedDate':run['completedDate'], 'totalAssetsFoundCount':run['totalAssetsFoundCount']})
            else:
                disco_names = list(set([run['name'] for run in self.get_discovery_groups(workspace_name)['content']]))
                for disco in disco_names:
                    disco_results[disco] = []
                    r = self.__workspace_query_helper__('__get_discovery_group_runs__', method='get', endpoint=f"discoGroups/{disco}/runs", workspace_name=workspace_name)
                    for run in r.json()['content']:
                        disco_results[disco].append({'state':run['state'], 'submittedDate':run['submittedDate'], 'completedDate':run['completedDate'], 'totalAssetsFoundCount':run['totalAssetsFoundCount']})
            return(disco_results)
        else:
            logging.error(f"{workspace_name} not found")
            raise Exception(workspace_name)

    def __asset_content_helper__(self, response_object, asset_list_name='', asset_id='', get_recent=True, last_seen_days_back=30, date_range_start='', date_range_end=''):
        if asset_list_name:
            for asset in response_object.json()['content']:
                getattr(self, asset_list_name).__add_asset__(Asset().__parse_workspace_assets__(asset, get_recent=get_recent, last_seen_days_back=last_seen_days_back, date_range_start=date_range_start, date_range_end=date_range_end))
        elif asset_id:
            getattr(self, asset_id).__parse_workspace_assets__(response_object.json(), get_recent=get_recent, last_seen_days_back=last_seen_days_back, date_range_start=date_range_start, date_range_end=date_range_end)
        else:
            logging.error('no asset_list_name or asset_id')
            raise Exception('no asset_list_name or asset_id')
        return(self)

    def __facet_filter_helper__(self, asset_list_name='', asset_id='', attribute_name=''):
        # some attributes will be nearly 100% unique or 100% identical across every asset
        # so excluding them
        _exclude_attributes = [
            'auditTrail','count','createdDate','discoGroupName','displayName','externalId','firstSeen','hosts','id','ipAddress','lastSeen','name','reason','updatedDate','uuid']
        logging.debug(f"auto creating facet filter from asset list {asset_list_name}")
        if not hasattr(self, 'filters'):
            setattr(self, 'filters', FacetFilter())

        # CVEs are a special case hence creating attribute dict here
        # so as not to require re-eval on every for-loop iteration
        if not hasattr(self.filters, 'cveId'):
            setattr(self.filters, 'cveId', {})
        
        # create a nested function to avoid duplicating the entire code block below twice
        def __nested_filter_creator__(asset, attribute_name=''):
            logging.debug(asset.id)

            for key,val in vars(asset).items():
                if key in _exclude_attributes:
                    continue
                if not hasattr(self.filters, key):
                    setattr(self.filters, key, {})
                    
                #sslCert assets and attributes are structured the same, so can use the same parsing for each
                ssl_cert = False
                if asset.kind == 'sslCert':
                    ssl_cert = True
                if key == 'sslCerts':
                    ssl_cert = True
                
                if isinstance(getattr(asset, key), (str, int, bool, float)):
                    if attribute_name and not attribute_name == key:
                        continue
                    try:
                        getattr(self.filters, key)[(val,)]['count'] += 1
                        getattr(self.filters, key)[(val,)]['assets'].append(asset.id)

                    except KeyError:
                        getattr(self.filters, key)[(val,)] = {'count':1, 'assets':[asset.id]}
                    
                    if attribute_name == key:
                        break
                
                elif isinstance(getattr(asset, key), list) and ssl_cert:
                    for list_item in getattr(asset, key):
                        if isinstance(list_item, str):
                            if attribute_name and not attribute_name == key:
                                continue
                            
                            if not hasattr(self.filters, key):
                                setattr(self.filters, key, {})
                            try:
                                getattr(self.filters, key)[tuple([list_item])]['count'] += 1
                                getattr(self.filters, key)[tuple([list_item])]['assets'].append(asset.id)

                            except KeyError:
                                getattr(self.filters, key)[tuple([list_item])] = {'count':1, 'assets':[asset.id]}
                            
                            if attribute_name == key:
                                break
                        
                        elif isinstance(list_item, dict):
                            for cert_key,cert_val in list_item.items():
                                if isinstance(cert_val, list):
                                    if attribute_name and not attribute_name == cert_key:
                                        continue
                                    
                                    if not hasattr(self.filters, cert_key):
                                        setattr(self.filters, cert_key, {})
                                    
                                    for sub_cert_val in cert_val:
                                        try:
                                            getattr(self.filters, cert_key)[tuple([sub_cert_val])]['count'] += 1
                                            getattr(self.filters, cert_key)[tuple([sub_cert_val])]['assets'].append(asset.id)

                                        except KeyError:
                                            getattr(self.filters, cert_key)[tuple([sub_cert_val])] = {'count':1, 'assets':[asset.id]}
                                        
                                    if attribute_name == key:
                                        break
                
                elif isinstance(getattr(asset, key), list) and not ssl_cert and key not in self._facet_filters:
                    for list_item in getattr(asset, key):
                        if isinstance(list_item, str):
                            if attribute_name and not attribute_name == key:
                                continue
                            
                            try:
                                getattr(self.filters, key)[tuple([list_item])]['count'] += 1
                                getattr(self.filters, key)[tuple([list_item])]['assets'].append(asset.id)
                            
                            except KeyError:
                                getattr(self.filters, key)[tuple([list_item])] = {'count':1, 'assets':[asset.id]}
                        
                            if attribute_name == key:
                                break
                        
                        elif isinstance(list_item, dict):
                            if attribute_name and not attribute_name == key:
                                continue
                            
                            try:
                                getattr(self.filters, key)[(list_item.get('value'),)]['count'] += 1
                                getattr(self.filters, key)[(list_item.get('value'),)]['assets'].append(asset.id)
                            
                            except KeyError:
                                getattr(self.filters, key)[(list_item.get('value'),)] = {'count':1, 'assets':[asset.id]}
                        
                            if attribute_name == key:
                                break
                
                elif isinstance(getattr(asset, key), list) and not ssl_cert and key in self._facet_filters:
                    if attribute_name and not attribute_name == key:
                        continue
                    for list_item in getattr(asset, key):
                        logging.debug(list_item)
                        eval_commands = []
                        if key == 'sslServerConfig':
                            if list_item['tlsVersions']:
                                for idx,tlsval in enumerate(list_item['tlsVersions']):
                                    eval_commands = []
                                    for facet in self._facet_filters[key]:
                                        eval_commands.append(f"list_item.get('{facet}')[{idx}]")
                                    eval_commands = ','.join(eval_commands)
                                    logging.debug(f"eval command string: {eval_commands}")
                                    try:
                                        getattr(self.filters, key)[(eval(eval_commands))]['count'] += 1
                                        getattr(self.filters, key)[(eval(eval_commands))]['assets'].append(asset.id)
                                    
                                    except KeyError:
                                        getattr(self.filters, key)[(eval(eval_commands))] = {'count':1, 'assets':[asset.id]}
                            else:
                                logging.debug(f"empty sslServerConfig[tlsVersions] list in asset {asset.id}")
                                pass
                        
                        elif key == 'webComponents':
                            for facet in self._facet_filters[key]:
                                eval_commands.append(f"list_item.get('{facet}')")
                            eval_commands = ','.join(eval_commands)
                            logging.debug(f"eval command string: {eval_commands}")
                            try:
                                getattr(self.filters, key)[(eval(eval_commands))]['count'] += 1
                                getattr(self.filters, key)[(eval(eval_commands))]['assets'].append(asset.id)
                                
                            except KeyError:
                                getattr(self.filters, key)[(eval(eval_commands))] = {'count':1, 'assets':[asset.id]}
                            
                            if list_item['cve']:
                                eval_commands = []
                                for cveval in list_item['cve']:
                                    eval_commands = ["list_item.get('name')"]
                                    for cvefacet in self._facet_filters['cveId'][1:]:
                                        eval_commands.append(f"cveval.get('{cvefacet}')")
                                    eval_commands = ','.join(eval_commands)
                                    logging.debug(f"eval command string: {eval_commands}")
                                    try:
                                        getattr(self.filters, 'cveId')[(eval(eval_commands))]['count'] += 1
                                        getattr(self.filters, 'cveId')[(eval(eval_commands))]['assets'].append(asset.id)
                                    
                                    except KeyError:
                                        getattr(self.filters, 'cveId')[(eval(eval_commands))] = {'count':1, 'assets':[asset.id]}

                        elif key == 'services':
                            if list_item['portStates']:
                                for idx,portval in enumerate(list_item['portStates']):
                                    eval_commands = []
                                    for facet in self._facet_filters[key]:
                                        if ',' not in facet:
                                            eval_commands.append(f"list_item.get('{facet}')")
                                        else:
                                            tmp_str = ['list_item']
                                            for i in range(len(facet.split(','))):
                                                tmp_str.append(".get('" + facet.split(',')[i] + "',{})")
                                            tmp_str.insert(2, f"[{idx}]")
                                            tmp_str = ''.join(tmp_str)
                                            tmp_str = ''.join(tmp_str.rsplit(',{}', 1))
                                            eval_commands.append(tmp_str)
                                    eval_commands = ','.join(eval_commands)
                                    logging.debug(f"eval command string: {eval_commands}")
                                    try:
                                        getattr(self.filters, key)[(eval(eval_commands))]['count'] += 1
                                        getattr(self.filters, key)[(eval(eval_commands))]['assets'].append(asset.id)
                                    
                                    except KeyError:
                                        getattr(self.filters, key)[(eval(eval_commands))] = {'count':1, 'assets':[asset.id]}
                            
                            else:
                                for facet in self._facet_filters[key]:
                                    if ',' not in facet:
                                        eval_commands.append(f"list_item.get('{facet}')")
                                    else:
                                        eval_commands.append("list_item.get('dummy_value')")
                                eval_commands = ','.join(eval_commands)
                                logging.debug(f"eval command string: {eval_commands}")
                                try:
                                    getattr(self.filters, key)[(eval(eval_commands))]['count'] += 1
                                    getattr(self.filters, key)[(eval(eval_commands))]['assets'].append(asset.id)
                                
                                except KeyError:
                                    getattr(self.filters, key)[(eval(eval_commands))] = {'count':1, 'assets':[asset.id]}
                        
                        elif key == 'location':
                            if list_item['value']:
                                eval_commands = []
                                for facet in self._facet_filters[key]:
                                    eval_commands.append(f"list_item.get('{facet.split(',')[0]}').get('{facet.split(',')[1]}')")
                                eval_commands = ','.join(eval_commands)
                                logging.debug(f"eval command string: {eval_commands}")
                                try:
                                    getattr(self.filters, key)[(eval(eval_commands))]['count'] += 1
                                    getattr(self.filters, key)[(eval(eval_commands))]['assets'].append(asset.id)
                                
                                except KeyError:
                                    getattr(self.filters, key)[(eval(eval_commands))] = {'count':1, 'assets':[asset.id]}
                            else:
                                logging.debug(f"empty location[value] dict in asset {asset.id}")
                                pass
                        
                        elif key == 'assetSecurityPolicies':
                            if list_item['isAffected']:
                                eval_commands = []
                                for facet in self._facet_filters[key]:
                                    eval_commands.append(f"list_item.get('{facet}')")
                                eval_commands = ','.join(eval_commands)
                                logging.debug(f"eval command string: {eval_commands}")
                                try:
                                    getattr(self.filters, key)[(eval(eval_commands))]['count'] += 1
                                    getattr(self.filters, key)[(eval(eval_commands))]['assets'].append(asset.id)
                                
                                except KeyError:
                                    getattr(self.filters, key)[(eval(eval_commands))] = {'count':1, 'assets':[asset.id]}
                        
                        else:
                            for list_item in getattr(asset, key):
                                logging.debug(list_item)
                                eval_commands = []
                                if len(self._facet_filters[key]) == 1:
                                    eval_commands = f"list_item.get('{self._facet_filters[key][0]}')"
                                    logging.debug(f"eval command string: {eval_commands}")
                                    try:
                                        getattr(self.filters, key)[tuple([eval(eval_commands)])]['count'] += 1
                                        getattr(self.filters, key)[tuple([eval(eval_commands)])]['assets'].append(asset.id)
                                    
                                    except KeyError:
                                        getattr(self.filters, key)[tuple([eval(eval_commands)])] = {'count':1, 'assets':[asset.id]}
                                else:
                                    for facet in self._facet_filters[key]:
                                        eval_commands.append(f"list_item.get('{facet}')")
                                    eval_commands = ','.join(eval_commands)
                                    logging.debug(f"eval command string: {eval_commands}")
                                    try:
                                        getattr(self.filters, key)[(eval(eval_commands),)]['count'] += 1
                                        getattr(self.filters, key)[(eval(eval_commands),)]['assets'].append(asset.id)
                                    
                                    except KeyError:
                                        getattr(self.filters, key)[(eval(eval_commands))] = {'count':1, 'assets':[asset.id]}
                    if attribute_name == key:
                        break
        
        if asset_list_name:
            for asset in getattr(self, asset_list_name).assets:
                __nested_filter_creator__(asset, attribute_name=attribute_name)
        elif asset_id:
            asset = getattr(self, asset_id)
            __nested_filter_creator__(asset, attribute_name=attribute_name)
        
        # place this outside the nested function so that we only have to run it once
        # need to dedup lists of assets as there is a chance for certain details to appear multiple times when processing a single asset
        # also removing empty filters
        keys_to_del = []
        for key,val in vars(self.filters).items():
            if len(val) == 0:
                keys_to_del.append(key)
            else:
                for sub_key,sub_val in val.items():
                    deduped = list(set(sub_val['assets']))
                    dedup_count = len(deduped)
                    if not sub_val['count'] == dedup_count:
                        logging.info(f"removing duplicate assets from {key}: {sub_key}")
                        getattr(self.filters, key)[sub_key] = {'count':dedup_count, 'assets':deduped}
        for key in keys_to_del:
            delattr(self.filters, key)

    def __workspace_query_helper__(self, calling_func, method, endpoint, url='', params={}, payload={}, data_plane=True, retry=True, max_retry=5, workspace_name=''):
        if data_plane:
            if self.__token_expiry__(self._dp_token):
                self._dp_token = self.__bearer_token__(data_plane=True)
            token = self._dp_token
        else:
            if self.__token_expiry__(self._cp_token):
                self._dp_token = self.__bearer_token__()
            token = self._cp_token
        if url:
            helper_url = f"{url}/{urllib.parse.quote(endpoint)}"
        elif workspace_name and data_plane:
            helper_url = f"https://{self._workspaces[workspace_name][0]}/{urllib.parse.quote(endpoint)}"
        elif workspace_name and not data_plane:
            helper_url = f"https://{self._workspaces[workspace_name][1]}/{urllib.parse.quote(endpoint)}"
        elif not workspace_name and data_plane:
            helper_url = f"https://{self._workspaces[self._default_workspace_name][0]}/{urllib.parse.quote(endpoint)}"
        elif not workspace_name and not data_plane:
            helper_url = f"https://{self._workspaces[self._default_workspace_name][1]}/{urllib.parse.quote(endpoint)}"
            
        helper_headers = {'Authorization': f"Bearer {token}"}
        helper_params = {'api-version': '2022-04-01-preview'}
        if params:
            helper_params.update(params)
        
        retry_counter = 1
        while retry:
            if retry_counter > max_retry:
                logging.critical(f"called by: {calling_func} -- endpoint: {endpoint} -- page: {helper_params.get('skip')} -- max attempts: {max_retry}")
                raise Exception(f"called by: {calling_func} -- endpoint: {endpoint} -- page: {helper_params.get('skip')} -- max attempts: {max_retry}")
            try:
                if payload:
                    helper_payload = payload
                    r = requests.request(method=method, url=helper_url, headers=helper_headers, params=helper_params, json=helper_payload)
                else:
                    r = requests.request(method=method, url=helper_url, headers=helper_headers, params=helper_params)
                
                if r.ok:
                    retry=False
                else:
                    logging.warning(f"{r.status_code} -- called by: {calling_func} -- endpoint: {endpoint} -- page: {helper_params.get('skip')} -- attempt: {retry_counter} of {max_retry} -- error: {r.text}")
                    retry_counter += 1
                    if data_plane:
                        if self.__token_expiry__(self._dp_token):
                            self._dp_token = self.__bearer_token__(data_plane=True)
                        token = self._dp_token
                        helper_headers = {'Authorization': f"Bearer {token}"}
                    else:
                        if self.__token_expiry__(self._cp_token):
                            self._dp_token = self.__bearer_token__()
                        token = self._cp_token
                        helper_headers = {'Authorization': f"Bearer {token}"}

            except Exception as e:
                logging.warning(f"called by: {calling_func} -- endpoint: {endpoint} -- page: {helper_params.get('skip')} -- attempt: {retry_counter} of {max_retry} -- error: {str(e)}")
                retry_counter += 1
                if data_plane:
                    if self.__token_expiry__(self._dp_token):
                        self._dp_token = self.__bearer_token__(data_plane=True)
                    token = self._dp_token
                    helper_headers = {'Authorization': f"Bearer {token}"}
                else:
                    if self.__token_expiry__(self._cp_token):
                        self._dp_token = self.__bearer_token__()
                    token = self._cp_token
                    helper_headers = {'Authorization': f"Bearer {token}"}
        return(r)

    def get_workspaces(self, workspace_name=''):
        url = f"https://management.azure.com/subscriptions/{self._subscription_id}/providers/Microsoft.Easm/"
        r = self.__workspace_query_helper__('get_workspaces', method='get', endpoint='workspaces', url=url, data_plane=False, workspace_name=workspace_name)
        if workspace_name:
            for workspace in r.json()['value']:
                if workspace['name'].lower() == workspace_name.lower():
                    self._workspaces[workspace['name']] = (f"{workspace['properties']['dataPlaneEndpoint']}{workspace['id'].replace('/providers/Microsoft.Easm','')}",f"management.azure.com{workspace['id']}")
                    self.__set_default_workspace_name__(workspace['name'])
            if not self._workspaces.get(workspace_name):
                logging.info(f"{workspace_name} not found in subscription {self._subscription_id}")
        else:
            for workspace in r.json()['value']:
                self._workspaces[workspace['name']] = (f"{workspace['properties']['dataPlaneEndpoint']}{workspace['id'].replace('/providers/Microsoft.Easm','')}",f"management.azure.com{workspace['id']}")
            logging.info(f"Found workspaces:\n {self._workspaces}")
        if not self._default_workspace_name:
            if len(self._workspaces.keys()) == 1:
                self.__set_default_workspace_name__(next(iter(self._workspaces)))
            else:
                print("no WORKSPACE_NAME set in the ENVIRONMENT .env file\nmake sure to manually set one of the following as the default or provide it as a workspace_name='<XXX>' argument to a subsequent function\n")
                for k in self._workspaces.keys():
                    print(f"\t{k}")

    def create_workspace(self, resource_group_name=None, region=None, workspace_name=None):
        if not resource_group_name:
            resource_group_name = self._resource_group
            if not resource_group_name:
                logging.error("a RESOURCE_GROUP_NAME must be set in ENVIRONMENT .env file, or passed during Workspaces() initialization, or in this function via resource_group_name=='<easm_rg_name>'")
                raise Exception('no resource_group_name')
        if not region:
            region = self._region
            if region and region not in self._easm_regions:
                logging.error(f"region {region} must be one of {', '.join(self._easm_regions)}")
                raise Exception(region)
            else:
                logging.error("an EASM_REGION must be set in ENVIRONMENT .env file, or passed during Workspaces() initialization, or in this function via region=='<easm_region_name>'")
                raise Exception('no region')
        if not workspace_name:
            workspace_name = self._default_workspace_name
            if not workspace_name:
                logging.error("a WORKSPACE_NAME must be set in ENVIRONMENT .env file, or passed during Workspaces() initialization, or in this function via workspace_name='<easm_workspace_name>'")
                raise Exception('no workspace_name')
        if self.__verify_workspace__(workspace_name):
            return({workspace_name: self._workspaces[workspace_name]})
        else:
            url = f"https://management.azure.com/subscriptions/{self._subscription_id}/resourceGroups/{resource_group_name}/providers/Microsoft.Easm"
            payload = {'location': region}
            r = self.__workspace_query_helper__('create_workspace', method='put', endpoint=f"workspaces/{workspace_name}", url=url, payload=payload, data_plane=False, workspace_name=workspace_name)
            self._workspaces[workspace_name] = (f"{r.json()['properties']['dataPlaneEndpoint']}{r.json()['id'].replace('/providers/Microsoft.Easm','')}",f"management.azure.com{r.json()['id']}")
            self.__set_default_workspace_name__(r.json()['name'])
            return({workspace_name: self._workspaces[workspace_name]})
    
    def get_discovery_templates(self, org_name, workspace_name=''):
        if not workspace_name:
            workspace_name = self._default_workspace_name
        if self.__verify_workspace__(workspace_name):
            params = {'filter': org_name}
            r = self.__workspace_query_helper__('get_discovery_templates', method='get', endpoint='discoTemplates', params=params, workspace_name=workspace_name)
            for org in r.json()['content']:
                logging.info(org)
                if org['name'][-1] != '.':
                    print(f"{org['name']}---{org['id']}")
                else:
                    print(f"{org['name'][:-1]}---{org['id']}")
        else:
            logging.error(f"{workspace_name} not found")
            raise Exception(workspace_name)

    def get_discovery_template_by_id(self, template_id, workspace_name=''):
        if not workspace_name:
            workspace_name = self._default_workspace_name
        if self.__verify_workspace__(workspace_name):
            r = self.__workspace_query_helper__('get_discovery_template_by_id', method='get', endpoint=f"discoTemplates/{template_id}", workspace_name=workspace_name)
            print(json.dumps(r.json(), indent=2))
            return(r.json())
        else:
            logging.error(f"{workspace_name} not found")
            raise Exception(workspace_name)

    def create_discovery_group(self, disco_template='', disco_custom={}, workspace_name=''):
        """Requires **one of** disco_template or disco_custom to be passed to function.
        
        disco_template should be a string generated by get_discovery_templates() in the form of:
            'My Org Name---123456'
        
        disco_custom should be a dict with the Org name and **at least one** seed in the form of:
            {
                'name':'My Org Name',
                'seeds':{
                    'domain':['mydomain1.com', 'mydomain2.com'],
                    'ipBlock':['10.10.0.0/16', '192.168.123.234/32'],
                    'host':['www.mydomain.com', 'mail.mydomain.com'],
                    'contact':['admin@mydomain.com', 'user@mydomain.com'],
                    'as':['ASN1234', '987654'],
                    'attribute':['WhoisOrganization:MY ORG NAME 1', 'WhoisOrganization:MY ORG NAME 2']
                },
                names: ['Org Name', 'Other Org Name, Inc']
            }
        """
        if not disco_template and not disco_custom:
            logging.error('One of "disco_template" or "disco_custom" is required')
            raise Exception('One of "disco_template" or "disco_custom" is required')
        elif disco_template and disco_custom:
            logging.error('Only one of "disco_template" or "disco_custom" is allowed')
            raise Exception('Only one of "disco_template" or "disco_custom" is allowed')
        elif disco_template or disco_custom:
            if not workspace_name:
                workspace_name = self._default_workspace_name
            if self.__verify_workspace__(workspace_name):
                if disco_custom:
                    try:
                        disco_name = f"{disco_custom['name']} seeds"
                        seeds = []
                        for key,val in disco_custom['seeds'].items():
                            for seed in val:
                                custom_seed = {'kind':key, 'name':seed}
                                seeds.append(custom_seed)
                        if disco_custom['names']:
                            names = disco_custom['names']
                        else:
                            names = []
                        payload = {'tier':'advanced', 'frequencyMilliseconds':604800000, 'seeds':seeds, 'names':names, 'excludes':[]}
                    except KeyError:
                        logging.error('invalid format and/or values for disco_custom')
                        raise KeyError(str(disco_custom))
                else:
                    disco_name, disco_id = disco_template.split('---')
                    payload = {'templateId':disco_id}
                self.__workspace_query_helper__('create_discovery_group', method='put', endpoint=f"discoGroups/{disco_name}", payload=payload, workspace_name=workspace_name)
                r_run_disco = self.__workspace_query_helper__('create_discovery_group', method='post', endpoint=f"discoGroups/{disco_name}:run", payload={'what':'ever'}, workspace_name=workspace_name)
                if r_run_disco.status_code == 204:
                    disco_runs = self.__get_discovery_group_runs__(disco_name=disco_name, workspace_name=workspace_name)
                    return(disco_runs)
            else:
                logging.error(f"{workspace_name} not found")
                raise Exception(workspace_name)
        else:
            logging.critical('unknown error')
            raise Exception('unknown error')

    def get_discovery_groups(self, workspace_name=''):
        if not workspace_name:
            workspace_name = self._default_workspace_name
        if self.__verify_workspace__(workspace_name):
            r = self.__workspace_query_helper__('get_discovery_groups', method='get', endpoint='discoGroups', workspace_name=workspace_name)
            return(r.json())
        else:
            logging.error(f"{workspace_name} not found")
            raise Exception(workspace_name)

    def get_workspace_assets(self, query_filter, asset_list_name='', page=0, max_page_size=25, max_page_count=0, get_all=False, auto_create_facet_filters=True, get_recent=True, last_seen_days_back=30, date_range_start='', date_range_end='', workspace_name='', **kwargs):
        """query_filter must be a valid MDEASM query, e.g.:
        
            state = "confirmed" AND kind = "domain"
            state = confirmed | kind = domain
            
            state ! "confirmed" AND kind = "page" AND webComponentName in ("nginx", "Microsoft-IIS", "Apache")
            state ! confirmed | kind = page | webComponentName in ("nginx", "Microsoft-IIS", "Apache")
            
            updatedAt between ("2022-12-01T07:00:00.000Z", "2022-12-16T07:00:00.000Z")
        
        if no asset_list_name value is provided, all assets returned by the query_filter will be placed into a default 'assetList' attribute
        
        the page argument determines from which page of results to start; defaults to 0 
        
        max_page_size determines how many results per page to return. valid values range from 1-100. anything outside that range will revert to the nearest acceptable value; defaults to 25
        
        max_page_count determines how many total pages of results to return. combined with the max_page_size argument, this will let you pull back a specific number of assets; defaults to 0 (AKA no max_page_count); e.g.:
        
            max_page_size=100, max_page_count=10 --> 1000 assets will be returned, 100 per page
            
            max_page_size=50, max_page_count=5 --> 250 assets will be returned, 50 per page
            
            max_page_size=50, max_page_count=0 --> ALL assets will be returned, 50 per page
        
        get_all determines whether to retrieve ALL assets for a query; defaults to False
        
        if both get_all and max_page_count are both passed to this function, max_page_count will take precedence; e.g.:
        
            max_page_size=50, max_page_count=5, get_all=True --> 250 assets will be returned, 50 per page
            
            max_page_size=50, get_all=True --> ALL assets will be returned, 50 per page
        
        The last set of arguments affect whether to keep specific asset details and do not apply to the asset object itself
        
        get_recent determines whether to keep asset details which have a 'recent' value and where that value = true; defaults to True
        
        last_seen_days_back determines whether to keep asset details which have a 'lastSeen' value and where that value is within the past <last_seen_days_back>; defaults to last 30 days
        
        if date_range_start ('YYYY-MM-DD') is submitted without date_range_end, any asset details where 'lastSeen' is AFTER the supplied date will be included
        
        if date_range_end ('YYYY-MM-DD') is submitted without date_range_start, any asset details where 'lastSeen' is BEFORE the supplied date will be included
        
        if both date_range_start and date_range_end are submitted, any asset details that are seen, they will be evaluated together -- whether date_range_start is LATER THAN 'firstSeen' and date_range_end is EARLIER THAN 'lastSeen' -- and prevent any standalone date_range_start or date_range_end evaluation
        """
        if not workspace_name:
            workspace_name = self._default_workspace_name
        if self.__verify_workspace__(workspace_name):
            if asset_list_name:
                setattr(self, asset_list_name, AssetList())
            else:
                asset_list_name = 'assetList'
                setattr(self, asset_list_name, AssetList())
            if max_page_size > 100:
                logging.warning('max_page_size cannot be greater than 100, setting max_page_size=100')
                max_page_size = 100
            elif max_page_size < 1:
                logging.warning('max_page_size cannot be less than 1, setting max_page_size=1')
                max_page_size = 1
            if max_page_count:
                get_all=True
            
            params = {'filter': query_filter, 'skip': page, 'maxpagesize': max_page_size}
            run_query=True
            page_counter=0
            time_counter_start=datetime.datetime.now().replace(microsecond=0)
            while run_query:
                r = self.__workspace_query_helper__('get_workspace_assets', method='get', endpoint='assets', params=params, workspace_name=workspace_name)
                
                total_assets = (r.json()['totalPages'] * max_page_size)
                if page_counter == 0:
                    print(f"{time_counter_start.strftime('%d-%b-%y %H:%M:%S')} -- {total_assets} assets identified by query")

                self.__asset_content_helper__(r, asset_list_name=asset_list_name, get_recent=get_recent, last_seen_days_back=last_seen_days_back, date_range_start=date_range_start, date_range_end=date_range_end)
                
                page_counter+=1
                
                if not get_all:
                    run_query=False
                elif max_page_count and page_counter >= max_page_count:
                    run_query=False
                elif r.json()['last']:
                    run_query = False
                else:
                    page = r.json()['number'] + 1
                    params['skip'] = page
                    
                    #a counter for tracking and printing assets retrieved + estimated time left until completion
                    #can modify by passing kwarg track_every_N_pages=NN (defaults to every 100 pages)
                    #can disable tracking and printing completely by passing kwarg no_track_time=True
                    if not (page_counter % kwargs.get('track_every_N_pages', 100) or kwargs.get('no_track_time')):
                        time_counter_diff = (datetime.datetime.now().replace(microsecond=0) - time_counter_start)
                        assets_so_far = (page_counter * max_page_size)
                        
                        print(f"\nretrieved {assets_so_far} assets in {time_counter_diff}\nestimated time for remaining {total_assets - assets_so_far} assets: {str((time_counter_diff * (total_assets/assets_so_far)) - time_counter_diff).split('.')[0]}")
            
            print(f"\n{datetime.datetime.now().strftime('%d-%b-%y %H:%M:%S')} -- query complete, {len(getattr(self, asset_list_name).assets)} assets retrieved\ncan check available asset lists via <mdeasm.Workspaces object>.asset_lists()")
            
            if auto_create_facet_filters:
                print(f"\nautomatically creating facet filters for all assets in asset list: {asset_list_name}")
                self.__facet_filter_helper__(asset_list_name=asset_list_name)
                print(f"\n{datetime.datetime.now().strftime('%d-%b-%y %H:%M:%S')} -- facet filters created\ncan check available filters via <mdeasm.Workspaces object>.facet_filters()")

        else:
            logging.error(f"{workspace_name} not found")
            raise Exception(workspace_name)

    def get_workspace_asset_by_id(self, asset_id, auto_create_facet_filters=True, get_recent=True, last_seen_days_back=30, date_range_start='', date_range_end='', workspace_name=''):
        """asset_id can be a string of format:
        
            as$$14032
            
            contact$$someone@mydomain.com
            
            domain$$mydomain.com
            
            host$$www.mydomain.com
            
            ipAddress$$10.11.12.13
            
            ipBlock$$10.10.0.0/16
            
            page$$https://www.mydomain.com/
            
            sslCert$$0123456789abcdeffedcba984765432100123456
            
        or a base64 encoded string of any of the above types:
        
            YXMkJDE0MDMy
            Y29udGFjdCQkc29tZW9uZUBteWRvbWFpbi5jb20=
            
            ZG9tYWluJCRteWRvbWFpbi5jb20=
            
            aG9zdCQkd3d3Lm15ZG9tYWluLmNvbQ==
            
            aXBBZGRyZXNzJCQxMC4xMS4xMi4xMw==
            
            aXBCbG9jayQkMTAuMTAuMC4wLzE2
            
            cGFnZSQkaHR0cHM6Ly93d3cubXlkb21haW4uY29tLw==
            
            c3NsQ2VydCQkMDEyMzQ1Njc4OWFiY2RlZmZlZGNiYTk4NDc2NTQzMjEwMDEyMzQ1Ng==
            
        or a valid uuid:
        
            23223be5-ab4c-f64b-384c-cdc9720bee28
        
        The last set of arguments affect whether to keep specific asset details and do not apply to the asset object itself
        
        get_recent determines whether to keep asset details which have a 'recent' value and where that value = true; defaults to True
        
        last_seen_days_back determines whether to keep asset details which have a 'lastSeen' value and where that value is within the past <last_seen_days_back>; defaults to last 30 days
        
        if date_range_start ('YYYY-MM-DD') is submitted without date_range_end, any asset details where 'lastSeen' is AFTER the supplied date will be included
        
        if date_range_end ('YYYY-MM-DD') is submitted without date_range_start, any asset details where 'lastSeen' is BEFORE the supplied date will be included
        
        if both date_range_start and date_range_end are submitted, any asset details that are seen, they will be evaluated together -- whether date_range_start is LATER THAN 'firstSeen' and date_range_end is EARLIER THAN 'lastSeen' -- and prevent any standalone date_range_start or date_range_end evaluation
        """
        if not workspace_name:
            workspace_name = self._default_workspace_name
        if self.__verify_workspace__(workspace_name):
            orig_asset_id, verified_asset_id = self.__validate_asset_id__(asset_id)
            setattr(self, asset_id, Asset())
            
            r = self.__workspace_query_helper__('get_workspace_asset_by_id', method='get', endpoint=f"assets/{verified_asset_id}", workspace_name=workspace_name)
            
            self.__asset_content_helper__(r, asset_id=orig_asset_id, get_recent=get_recent, last_seen_days_back=last_seen_days_back, date_range_start=date_range_start, date_range_end=date_range_end)
            
            if auto_create_facet_filters:
                logging.info(f"auto-creating facet filters for all asset in asset list: {asset_id}")
                self.__facet_filter_helper__(asset_id=asset_id)
            #print(f"query complete, asset available via getattr(<mdeasm.Workspaces object>, '{orig_asset_id}')")
            #return(getattr(self, orig_asset_id))
        else:
            logging.error(f"{workspace_name} not found")
            raise Exception(workspace_name)

    def get_workspace_risk_observations(self, severity='', last_seen_days_back=30, date_range_start='', date_range_end='', workspace_name=''):
        """if supplied, optional argument severity must be one of (case-insensitive) 'high','medium', or 'low'. if not supplied, retreives risk observations for all severities
        
        last_seen_days_back will by default only keep asset details seen within the past N days. this can be adjusted to longer or shorter time ranges to suit.
        
        if date_range_start ('YYYY-MM-DD') is submitted without date_range_end, any asset details where 'lastSeen' is AFTER the supplied date will be included
        
        if date_range_end ('YYYY-MM-DD') is submitted without date_range_start, any asset details where 'lastSeen' is BEFORE the supplied date will be included
        
        if both date_range_start and date_range_end are submitted, any asset details that are seen, they will be evaluated together -- whether date_range_start is LATER THAN 'firstSeen' and date_range_end is EARLIER THAN 'lastSeen' -- and prevent any standalone date_range_start or date_range_end evaluation
        """
        if not workspace_name:
            workspace_name = self._default_workspace_name
        if self.__verify_workspace__(workspace_name):
            if severity.lower() == 'high':
                metric_categories = ['priority_high_severity']
            elif severity.lower() == 'medium':
                metric_categories = ['priority_medium_severity']
            elif severity.lower() == 'low':
                metric_categories = ['priority_low_severity']
            else:
                logging.warning(f"supplied value of severity='{severity}' not one of 'high','medium','low'; defaulting to all severities")
                severity='high & medium & low'
                metric_categories = ['priority_high_severity','priority_medium_severity','priority_low_severity']
            
            summarize_payload = {'metricCategories': metric_categories, 'metrics': None, 'filters': None, 'groupBy': None}
            r_summarize = self.__workspace_query_helper__('get_workspace_risk_observations', method='post', endpoint='reports/assets:summarize', payload=summarize_payload, workspace_name=workspace_name)
            
            metrics = {}
            for summary in r_summarize.json()['assetSummaries']:
                sev_type = summary['displayName']
                if summary['count']:
                    for observation in summary['children']:
                        if observation['count']:
                            finding = f"{sev_type}_{observation['displayName']}"
                            finding = re.sub(r'[^\w]', '_', finding)
                            metrics[finding] = observation['metric']
            
            if not metrics:
                print(f"No Risk Observations found for severity='{severity}'")
            else:
                snapshot_assets = {}
                for key,val in metrics.items():
                    snapshot_payload = {'metric':val,'labelName':None,'page':0,'size':100}
                    asset_uuids = []
                    get_next = True
                    while get_next:
                        r_snapshot = self.__workspace_query_helper__('get_workspace_risk_observations', method='post', endpoint='reports/assets:snapshot', payload=snapshot_payload, workspace_name=workspace_name)
                        for asset in r_snapshot.json()['assets']['content']:
                            asset_uuids.append(asset['uuid'])
                        if r_snapshot.json()['assets']['last']:
                            get_next = False
                        else:
                            snapshot_payload['page'] += 1
                    snapshot_assets[key] = asset_uuids
            
            for key,val in snapshot_assets.items():
                for i in range(0, len(val), 50):
                    uuid_list = []
                    for uuid in val[i:i+50]:
                        uuid_list.append(uuid)
                    uuid_str = '","'.join(uuid_list)
                    query = f"uuid in (\"{uuid_str}\")"
                    self.get_workspace_assets(query_filter=query, asset_list_name=key, max_page_size=50, auto_create_facet_filters=False, last_seen_days_back=last_seen_days_back, date_range_start=date_range_start, date_range_end=date_range_end)
                self.create_facet_filter(asset_list_name=key)
                print(f"{key} risk observations retrieved for {len(val)} assets and available at <mdeasm.Workspaces object>.{key}.assets\n")
            print(f"facet filters created and available at <mdeasm.Workspaces object>.filters.<facet_filter>")
        else:
            logging.error(f"{workspace_name} not found")
            raise Exception(workspace_name)

    def create_facet_filter(self, asset_list_name='', asset_id='', attribute_name=''):
        """Expects an asset_list_name created by get_workspace_assets() or an asset_id created by get_workspace_asset_by_id().
        
        If no attribute_name value is passed to the function, this will create facet filters for every attribute found in every asset(s). Optionally pass in a single attribute_name (e.g.: 'cnames', 'headers', 'location') to create a facet filter for just that attribute.
        
        The exceptions to this are webComponents and cve - passing attribute_name='webComponents' will ALSO create the cve filter. This is the ONLY way to create the cve filter
        
        Results are accessible in the <mdeasm.Workspaces object>.filters.<attribute_name> attribute. Either use the built-in query_facet_filter() function, or perform a more advanced/granular search by accessing the facet filter details through any dict method (e.g.: .items(), .keys(), .values() )
        """
        if (not asset_list_name and not asset_id):
            logging.error('one of either asset_list_name or asset_id must be passed to this function')
            raise Exception('no asset_list_name and no asset_id')
        if not isinstance(getattr(self, asset_list_name), AssetList):
            logging.error(f"{asset_list_name} is of type {type(asset_list_name)}; must be AssetList object")
            raise Exception(type(asset_list_name))
        if not len(getattr(self, asset_list_name).assets) > 0:
            logging.error(f"{asset_list_name} has no items")
            raise Exception(asset_list_name)

        if asset_list_name:
            self.__facet_filter_helper__(asset_list_name=asset_list_name, attribute_name=attribute_name)
        elif asset_id:
            self.__facet_filter_helper__(asset_id=asset_id, attribute_name=attribute_name)

        #print(f"facet filter created, available at <mdeasm.Workspaces object>.filters.<attribute_name>")
        if attribute_name:
            print(f"facet filter created successfully and available at <mdeasm.Workspaces object>.filters.{attribute_name}")

    def query_facet_filter(self, search, facet_filter='', search_type='contains', case_insensitive=True, sort_order='descending', out_format='print', out_path=''):
        """Expects a search string and optionally the name of an alread-created facet filter. Valid values for facet_filter can be identified via:

                for key in vars(<mdeasm.Workspaces object>.filters).keys():
                
                    print(key)
        
        If no facet_filter is provided, this will apply the search across ALL facet filters.
        
        Search should be a single string value to look for within any of the facet filter key index positions (key[0], key[1], key[2], etc.); e.g. the webComponents facet filter key positions:
        
                name, type, version
                
                key[0], key[1], key[2]
    
        Optional parameter 'search_type' must be one of 'contains', 'starts', or 'ends' and dictates where in the facet filter entries to look for the search string. Defaults to 'contains'.
        
        Optional parameter 'sort_order' must be one of 'descending' or 'ascending' and dictates how to display found search strings. This only sorts based on the count of the found search string, not on the found search string value itself. Defaults to 'descending'.
        
        Optional parameter 'out_format' can be used to either save the results to file or print to terminal. Accepted arguments are 'csv' and 'json' (if ommitted or set to any other value, will print to terminal). Default behavior is 'print'.
        
        If out_format is set to 'csv' or 'json', optional parameter out_path can be used to save results to a particular location on disk. If no out_path value is submitted this will default to the script's current directory.
        """
        search = str(search)
        if search_type.lower() not in ('contains', 'starts', 'ends'):
            logging.error(f"{search_type} must be one of 'contains', 'starts', or 'ends' (case-insensitive)")
            raise Exception(search_type)
        if sort_order.lower() not in ('descending', 'ascending'):
            logging.error(f"{sort_order} must be one of 'descending' or 'ascending' (case-insensitive)")
            raise Exception(sort_order)
        if facet_filter and not hasattr(self.filters, facet_filter):
            logging.error(f"facet_filter {facet_filter} submitted but no <mdeasm.Workspaces object>.filter.{facet_filter} attribute exists; this means it was either never created or it was empty and thus deleted")
            raise Exception(f"{facet_filter} not exists")
        
        def __nested_output_formatter__(out_format='', out_path=''):
            if not out_path:
                out_path = pathlib.Path(__file__).parent.resolve()
            else:
                if out_path.endswith('\\') or out_path.endswith('/'):
                    out_path = out_path[:-1]
                out_path = pathlib.Path(out_path)
            file_name = f"{facet_filter}_{'_'.join([str(f) for f in facet_key if not f == None])}"
            file_name = re.sub(r'[^\w_. -]', '_',file_name)
            if out_format == 'csv':
                file_name += '.csv'
                out_path = out_path / file_name
                out_path.parent.mkdir(parents=True, exist_ok=True)
                with open(out_path, 'w') as f:
                    f.write(','.join(facet_val['assets']))
                    print(f"saving {search} query results to {out_path}")
            elif out_format == 'json':
                file_name += '.json'
                out_path = out_path / file_name
                out_path.parent.mkdir(parents=True, exist_ok=True)
                with open(out_path, 'w') as f:
                    f.write(json.dumps(facet_val))
                    print(f"saving {search} query results to {out_path}")
            else:
                out_dict.update({facet_key:facet_val})
                newlinenewtab = f"\n\t"
                ffkeys = f"\n{self._facet_filters.get(facet_filter)}"
                if ffkeys == None:
                    ffkeys == ''
                print(f"\nSearch in '{facet_filter}' for '{search_type} {search}' found:{ffkeys}\n{facet_key}\nCount: {facet_val['count']}\nAsset IDs:\n\t{newlinenewtab.join(facet_val['assets'])}")
                #print(self._facet_filters.get(facet_filter))
                #print(f"{facet_key}", '\nCount:', facet_val['count'], '\nAsset IDs:\n       ', '\n\t'.join(facet_val['assets']))

        
        sort_order_bool = bool
        if sort_order.lower() == 'descending':
            sort_order_bool = True
        else:
            sort_order_bool = False
        if search_type.lower() == 'starts':
            if case_insensitive:
                filter_search = re.compile(f"^{search.lower()}")
            else:
                filter_search = re.compile(f"^{search}")
        elif search_type.lower() == 'ends':
            if case_insensitive:
                filter_search = re.compile(f"{search.lower()}$")
            else:
                filter_search = re.compile(f"{search}$")
        else:
            if case_insensitive:
                filter_search = re.compile(search.lower())
            else:
                filter_search = re.compile(search)
        
        out_dict = {}
        if facet_filter:
            for facet_key,facet_val in sorted(getattr(self.filters, facet_filter).items(), key=lambda x: x[1]['count'], reverse=sort_order_bool):
                for i in facet_key:
                    try:
                        if case_insensitive:
                            if re.search(filter_search, str(i).lower()):
                                __nested_output_formatter__(out_format=out_format, out_path=out_path)
                                break   #found it already, no need to evaluate rest of facet_key[i] items
                        else:
                            if re.search(filter_search, str(i)):
                                __nested_output_formatter__(out_format=out_format, out_path=out_path)
                                break   #found it already, no need to evaluate rest of facet_key[i] items
                        
                    except AttributeError as e:
                        logging.warning(i, str(e))
                        pass
        
        else:
            for key,val in vars(self.filters).items():
                facet_filter = key
                for facet_key,facet_val in sorted(val.items(), key=lambda x: x[1]['count'], reverse=sort_order_bool):
                    for i in facet_key:
                        try:
                            if case_insensitive:
                                if re.search(filter_search, str(i).lower()):
                                    __nested_output_formatter__(out_format=out_format, out_path=out_path)
                                    break   #found it already, no need to evaluate rest of facet_key[i] items
                            else:
                                if re.search(filter_search, str(i)):
                                    __nested_output_formatter__(out_format=out_format, out_path=out_path)
                                    break   #found it already, no need to evaluate rest of facet_key[i] items
                        except AttributeError as e:
                            logging.warning(i, str(e))
                            pass
        return(out_dict)

    def create_or_update_label(self, name, color='', display_name='', workspace_name='', **kwargs):
        """passing the 'name' of an already-created label will update it to the values submitted for 'color' and 'displayName'
        
        optional arg 'color' must be one of 'red','green','blue','purple','brown','gray','yellow','bronze','lime','teal','pink','silver'. submitting anything else (or omitting) will default to 'blue'
        
        if optional arg 'display_name' is not submitted, it will default to the same as 'name'
        """
        if color and color not in self._label_colors:
            logging.warning(f"{color} not one of {','.join(self._label_colors)}; setting to default")
            color = 'blue'
        elif not color:
            color = 'blue'
        if not display_name:
            display_name = name
        if not workspace_name:
            workspace_name = self._default_workspace_name
        if self.__verify_workspace__(workspace_name):
            label_endpoint = f"/labels/{name}"
            label_payload = {'properties': {'color':color,'displayName':display_name}}
            r = self.__workspace_query_helper__('create_or_update_label', method='put', endpoint=label_endpoint, payload=label_payload, data_plane=False, workspace_name=workspace_name)
            
            label_properties = {'color':r.json()['properties'].get('color'),'displayName':r.json()['properties'].get('displayName')}
            if kwargs.get('noprint'):
                return(label_properties)
            else:
                print(f"created new label '{name}' in {workspace_name}\n")
                print(json.dumps(label_properties, indent=2))
        else:
            logging.error(f"{workspace_name} not found")
            raise Exception(workspace_name)
    
    def get_labels(self, workspace_name='', **kwargs):
        if not workspace_name:
            workspace_name = self._default_workspace_name
        if self.__verify_workspace__(workspace_name):
            label_endpoint = f"/labels"
            r = self.__workspace_query_helper__('get_labels', method='get', endpoint=label_endpoint, data_plane=False, workspace_name=workspace_name)
            
            label_properties = {}
            for label in r.json()['value']:
                label_properties[label['name']] = {'color':label['properties'].get('color'),'displayName':label['properties'].get('displayName')}
            if kwargs.get('noprint'):
                return(label_properties)
            else:
                if label_properties:
                    print(f"current labels in {workspace_name}\n")
                    print(json.dumps(label_properties, indent=2))
                else:
                    print(f"no labels exist for {workspace_name}")
        else:
            logging.error(f"{workspace_name} not found")
            raise Exception(workspace_name)

    def update_assets(self, query_filter, new_state=None, labels=None, apply_labels=True, remove_labels=False, workspace_name=''):
        """this function will update asset states and/or labels, depending on the submitted arguments. at least one of 'new_state' and/or 'labels' must be submitted.
        
        'new_state' expects a value in <mdeasm.Workspaces object>._state_map; e.g.: new_state='Approved', new_state='RequiresInvestigation', new_state=easm._state_map['Dependency']
        
        'labels' expects a list or comma-separated string of already-created labels available within the workspace. labels can be created/verified with create_or_update_label() and/or get_labels(). if a non-existent label is submitted, this will create it.
        
        when 'labels' are submitted, the default action will be to apply them to the assets found by 'query_filter'.
        
        if you want to instead remove labels from assets, submit 'apply_labels=False' and/or 'remove_labels=True'. if both 'apply_labels=True' and 'remove_labels=True' are submitted, 'remove_labels=True' will take precedence.
        
        this function will print the taskId value for the submitted update action, as well as append that taskId to the <mdeasm.Workspaces object>.task_ids list. this, or any other, taskId can be polled for completion progress with poll_asset_state_change()
        """
        if not new_state and not labels:
            logging.error("must submit one of 'new_state' and/or 'labels'")
            raise Exception("must submit one of 'new_state' and/or 'labels'")
        if new_state and new_state in self._state_map:
            new_state = self._state_map[new_state]
        if new_state and new_state not in self._state_map.values():
            logging.error(f"new_state not a valid value: {new_state}; must be one of {', '.join([v for v in self._state_map.values()])}")
            raise Exception(f"new_state: {new_state}")
        if remove_labels or not apply_labels:
            label_action = False
        else:
            label_action = True
        asset_update_payload = {'labels':{},'state':new_state,'externalId':None,'transfers':None}
        if not workspace_name:
            workspace_name = self._default_workspace_name
        if labels and isinstance(labels, str):
            labels = labels.split(',')
            already_created_labels = self.get_labels(workspace_name=workspace_name, noprint=True)
            for label in labels:
                label = label.strip()
                if label not in already_created_labels:
                    logging.warning(f"label '{label}' not available within {workspace_name}; creating it with defaults")
                    self.create_or_update_label(name=label)
                asset_update_payload['labels'][label] = label_action
        logging.debug(asset_update_payload)
        if self.__verify_workspace__(workspace_name):
            try:
                logging.debug(f"update_asset_state query_filter: {query_filter}")
                asset_count_payload = {'filters': [query_filter]}
                asset_count_r = self.__workspace_query_helper__('update_asset_state', method='post', endpoint='reports/assets:summarize', payload=asset_count_payload)
                asset_count = asset_count_r.json()['assetSummaries'][0]['count']
                if asset_count >= 100000:
                    logging.error(f"asset count for query_filter {query_filter} returned {asset_count} assets; unable to process asset changes for > 100000 assets for a single query")
                    raise Exception(f"asset_count >= 100000: {asset_count}")
                else:
                    logging.info(f"asset count < 100000: {asset_count}, continuing")
                    pass
            except:
                logging.warning(f"unable to retrieve asset count for update_asset_state...will try anyways")
                pass
            if not hasattr(self, 'task_ids'):
                setattr(self, 'task_ids', [])
            
            params = {'filter': query_filter}
            r = self.__workspace_query_helper__('update_asset_state', method='patch', endpoint='assets', params=params, payload=asset_update_payload)
            
            print(f"task id for asset update action: {r.json()['id']}")
            self.task_ids.append(r.json()['id'])
            #return(self.task_ids)
        else:
            logging.error(f"{workspace_name} not found")
            raise Exception(workspace_name)

    def poll_asset_state_change(self, task_id='', workspace_name=''):
        if not task_id and not hasattr(self, 'task_ids'):
            setattr(self, 'task_ids', [])
        #if not task_id and (hasattr(self, 'task_ids') and len(self.task_ids) == 0):
        #    logging.error('no task_id argument submitted and no tasks in self.task_ids')
        #    raise Exception
        if task_id and not hasattr(self, 'task_ids'):
            setattr(self, 'task_ids', [])
            self.task_ids.append(task_id)
        if not workspace_name:
            workspace_name = self._default_workspace_name
        if self.__verify_workspace__(workspace_name):
            r = self.__workspace_query_helper__('poll_asset_state_change', method='get', endpoint='tasks', workspace_name=workspace_name)
            if r.json()['totalElements'] == 0:
                logging.error("no tasks found for workspace: {workspace_name}")
                raise Exception
            else:
                for task in r.json()['content']:
                    if task_id and task_id == task['id']:
                        print(f"\ntask id:\n\t{task['id']}")
                        print(f"task query:\n\t{task['metadata']['filter']}")
                        print(f"task actions:\n\t{task['metadata']['assetUpdateRequest']}")
                        print(f"task status:\n\t{task['state']}")
                        print(f"task started:\n\t{task['startedAt']}")
                        print(f"total estimated assets to be updated:\n\t{task['metadata']['estimated']}")
                        print(f"current task completion percentage:\n\t{task['metadata']['progress']}%")
                    elif task['state'] != 'complete':
                        print(f"\ntask id:\n\t{task['id']}")
                        print(f"task query:\n\t{task['metadata']['filter']}")
                        print(f"task actions:\n\t{task['metadata']['assetUpdateRequest']}")
                        print(f"task started:\n\t{task['startedAt']}")
                        print(f"total estimated assets to be updated:\n\t{task['metadata']['estimated']}")
                        print(f"current task completion percentage:\n\t{task['metadata']['progress']}%")
                    elif task['state'] == 'complete':
                        print(f"\ntask id:\n\t{task['id']}")
                        print(f"task query:\n\t{task['metadata']['filter']}")
                        print(f"task actions:\n\t{task['metadata']['assetUpdateRequest']}")
                        print((f"task started:\n\t{task['startedAt']}"))
                        print(f"task completed:\n\t{task['completedAt']}")
                        print(f"total assets updated:\n\t{task['metadata']['estimated']}")

    def asset_lists(self):
        """retrieves and prints the current AssetList objects available within the Workspaces object
        """
        asset_lists_out = []
        for k,v in vars(self).items():
            if isinstance(v, AssetList):
                asset_lists_out.append(k)
        if not asset_lists_out:
            print('no AssetList attributes found')
        else:
            print(f"\n".join(asset_lists_out))
    
    def facet_filters(self):
        """retreives and prints the current FacetFilter objects available within the Workspaces object 
        """
        facet_filters_out = []
        for v in vars(self).values():
            if isinstance(v, FacetFilter):
                for k in vars(v).keys():
                    facet_filters_out.append(k)
        if not facet_filters_out:
            print('no FacetFilter attributes found')
        else:
            print(f"\n".join(facet_filters_out))

    def get_workspace_asset_summaries(self, query_filters=[], metric_categories=[], metrics=[], group_by='', workspace_name=''):
        """submit one of:
        
                query_filters: must be a valid EASM query
            
                metric_categories: expects one of <mdeasm.Workspaces object>._metric_categories
            
                metrics: expects one of <mdeasm.Workspaces object>._metrics
            
            details are accessible through the <mdeasm.Workspaces object>.asset_summaries attribute; also prints <mdeasm.Workspaces object>.asset_summaries upon completion
        """
 
        if (not query_filters and not metric_categories and not metrics) or (query_filters and metric_categories and metrics) or (query_filters and metric_categories and not metrics) or (query_filters and not metric_categories and metrics) or (not query_filters and metric_categories and metrics):
            logging.error('must submit one and only one of: query_filters, metric_categories, metrics')
            raise Exception(f"query_filters: {query_filters}; metric_categories: {metric_categories}; metrics: {metrics}")

        if query_filters and isinstance(query_filters, str):
            query_filters = [query_filters]
            logging.debug(query_filters)
        if query_filters and not isinstance(query_filters, list):
            logging.error(f"invalid query_filters; must be a list of valid EASM queries")
            raise Exception(type(query_filters), query_filters)

        if metric_categories and isinstance(metric_categories, str):
            metric_categories = [metric_categories]
            logging.debug(metric_categories)
        if metric_categories and (not isinstance(metric_categories, list) or not all(met_cat in self._metric_categories for met_cat in metric_categories)):
            logging.error(f"invalid metric_categories; must be a list and items be one of {self._metric_categories}")
            raise Exception(metric_categories)

        if metrics and isinstance(metrics, str):
            metrics = [metrics]
            logging.debug(metric_categories)
        if metrics and (not isinstance(metrics, list) or not all(met in self._metrics for met in metrics)):
            logging.error(f"invalid metrics; must be a list and items be one of {self._metrics}")
            raise Exception(metrics)

        if not workspace_name:
            workspace_name = self._default_workspace_name
        if self.__verify_workspace__(workspace_name):
            payload = {'metricCategories': metric_categories, 'metrics': metrics, 'filters': query_filters, 'groupBy': None}
            r = self.__workspace_query_helper__('get_workspace_asset_summaries', method='post', endpoint='reports/assets:summarize', payload=payload, workspace_name=workspace_name)
            
            submitted = query_filters + metric_categories + metrics
            if not hasattr(self, 'asset_summaries'):
                setattr(self, 'asset_summaries', {})
            for idx,summary in enumerate(r.json()['assetSummaries']):
                if (submitted[idx] == summary['metricCategory']) or (submitted[idx] == summary['metric']) or (submitted[idx] == summary['filter']):
                    self.asset_summaries[submitted[idx]] = {'count':summary['count'], 'updatedAt':summary['updatedAt']}
                else:
                    logging.warning(f"{submitted[idx]} NOT EQUAL to any of {summary['metricCategory']}, {summary['metric']}, {summary['filter']}")
            
            print(json.dumps(self.asset_summaries, indent=2))

class Asset:
    _exclude_attributes = [
        'alexaInfos','domainAsset','guids','hostCore','responseBodyMinhashSignatures','fullDomMinhashSignatures','responseBodyHashSignatures','scanmetadata','sources']
    _exclude_keys = {
            'firstSeenCrawlGuid','firstSeenPageGuid','firstSeenResourceGuid','lastSeenCrawlGuid','lastSeenPageGuid','lastSeenResourceGuid','responseBodyMinhash','resources','sources'}
    def __init__(self, *args, **kwargs) -> None:
        pass

    def __parse_workspace_assets__(self, asset_object, get_recent=True, last_seen_days_back=30, date_range_start='', date_range_end=''):
        if date_range_start:
            try:
                datetime.date.fromisoformat(date_range_start)
                date_range_start = f"{date_range_start} 00:00:00"
                date_start = datetime.datetime.fromisoformat(date_range_start)
                logging.debug(f"date_start {date_start}")
            except ValueError:
                logging.error(f"{date_range_start} not in correct format; must be 'YYYY-MM-DD'")
                raise ValueError(f"Invalid isoformat string: '{date_range_start}'")
        if date_range_end:
            try:
                datetime.date.fromisoformat(date_range_end)
                date_range_end = f"{date_range_end} 00:00:00"
                date_end = datetime.datetime.fromisoformat(date_range_end)
                logging.debug(f"date_end {date_end}")
            except ValueError:
                logging.error(f"{date_range_end} not in correct format; must be 'YYYY-MM-DD'")
                raise ValueError(f"Invalid isoformat string: '{date_range_end}'")
        if date_range_start and date_range_end:
            if date_end < date_start:
                logging.error(f"date_range_start {date_range_start} cannot be a later date than date_range_end {date_range_end}")
                raise Exception(f"date_range_start: {date_range_start}, date_range_end: {date_range_end}")
        datetime_offset = datetime.timedelta(days=+last_seen_days_back)
        datetime_now = datetime.datetime.now(tz=datetime.timezone.utc)
        last_seen = (datetime_now - datetime_offset)
        is_ssl_cert = False
        if asset_object['kind'] == 'sslCert':
            is_ssl_cert = True
        for key,val in asset_object.items():
            if key in self._exclude_attributes:
                pass
            elif isinstance(val, str):
                setattr(self, key, val)
            elif isinstance(val, int):
                setattr(self, key, val)
            elif isinstance(val, bool):
                setattr(self, key, val)
            elif isinstance(val, list) and len(val) > 0:
                setattr(self, key, val)
            elif isinstance(val, dict):
                for sub_key,sub_val in val.items():
                    if sub_key in self._exclude_attributes:
                        pass
                    elif isinstance(sub_val, list) and len(sub_val) == 0:
                        pass
                    elif isinstance(sub_val, (str, int, bool, dict, float)):
                        setattr(self, sub_key, sub_val)
                    elif isinstance(sub_val, list) and len(sub_val) > 0 and not is_ssl_cert:
                        attrib_list = []
                        for sub_sub_val in sub_val:
                            try:
                                if get_recent or last_seen_days_back or date_range_start or date_range_end:
                                    if (
                                        (get_recent and 'recent' in sub_sub_val and sub_sub_val.get('recent') == True) or 
                                        ('lastSeen' in sub_sub_val and parser.parse(sub_sub_val.get('lastSeen')) >= last_seen) or 
                                        (date_range_start and date_range_end and 'firstSeen' in sub_sub_val and 'lastSeen' in sub_sub_val and date_start.astimezone(tz=datetime.timezone.utc) >= parser.parse(sub_sub_val.get('firstSeen')) and parser.parse(sub_sub_val.get('lastSeen')) >= date_end.astimezone(tz=datetime.timezone.utc)) or 
                                        (date_range_start and not date_range_end and 'lastSeen' in sub_sub_val and parser.parse(sub_sub_val.get('lastSeen')) >= date_start.astimezone(tz=datetime.timezone.utc)) or 
                                        (date_range_end and not date_range_start and 'lastSeen' in sub_sub_val and parser.parse(sub_sub_val.get('lastSeen')) <= date_start.astimezone(tz=datetime.timezone.utc))
                                    ):
                                        new_val = {k: sub_sub_val[k] for k in set(list(sub_sub_val.keys())) - self._exclude_keys}
                                        logging.debug(f"eval True: {sub_key} + {sub_sub_val}")
                                        attrib_list.append(new_val)
                                        #getattr(self, sub_key).append(new_val)
                                    else:
                                        logging.debug(f"eval False: {sub_key} + {sub_sub_val}")
                                        pass
                                else:
                                    new_val = {k: sub_sub_val[k] for k in set(list(sub_sub_val.keys())) - self._exclude_keys}
                                    logging.debug(f"no eval: {sub_key} + {sub_sub_val}")
                                    attrib_list.append(new_val)
                                    #getattr(self, sub_key).append(new_val)
                            except Exception as e:
                                logging.error(sub_key, sub_sub_val, str(e))
                                pass
                        if attrib_list:
                            setattr(self, sub_key, attrib_list)
                    elif isinstance(sub_val, list) and len(sub_val) > 0 and is_ssl_cert:
                        setattr(self, sub_key, sub_val)
                    else:
                        logging.info(f"unknown attribute type in {asset_object['id']} -- {sub_key}:{sub_val} -- {type(sub_key)}")
                        pass
        return(self)

    def to_dict(self):
        dict_with_vals = {}
        for k,v in vars(self).items():
            dict_with_vals[k] = v
        print(dict_with_vals)

    def pretty(self, indent=2):
        dict_with_vals = {}
        for k,v in vars(self).items():
            dict_with_vals[k] = v
        print(json.dumps(dict_with_vals, indent=indent))

class AssetList:
    def __init__(self, *args, **kwargs) -> None:
        self.assets = list()

    def __add_asset__(self, cls):
        self.assets.append(cls)

class FacetFilter:
    def __init__(self, *args, **kwargs) -> None:
        pass
