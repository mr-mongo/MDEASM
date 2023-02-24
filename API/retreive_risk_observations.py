#!/usr/bin/python3

#easiest to import mdeasm.py if it is in the same directory as this retreive_risk_observations.py script
import mdeasm

# name of the EASM resource
workspace_name = ''

tenant_id = ''
subscription_id = ''

# service principal needs to have Contributor permissions on EASM resource
client_id = ''
client_secret = ''

easm = mdeasm.Workspaces(workspace_name=workspace_name, tenant_id=tenant_id, subscription_id=subscription_id, client_id=client_id, client_secret=client_secret)

#the get_workspace_risk_observations() funnction will print the names of all risk observation details retreived
#as well as where to access the asset and facet filter attributes

#retrieve asset details for low severity observations
#easm.get_workspace_risk_observations('low')

#retrieve asset details for medium severity observations
#easm.get_workspace_risk_observations('medium')

#retrieve asset details for high severity observations
easm.get_workspace_risk_observations('high')

#retrieve asset details for ALL observations
#easm.get_workspace_risk_observations()

