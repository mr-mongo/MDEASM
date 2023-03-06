#!/usr/bin/python3
import sys

#easiest to import mdeasm.py if it is in the same directory as this retreive_risk_observations.py script
#requires mdeasm.py VERSION 1.2
import mdeasm

if mdeasm._VERSION < 1.2:
    sys.exit(f"requires mdeasm.py VERSION 1.2; current version: {mdeasm._VERSION}")

easm = mdeasm.Workspaces(workspace_name=mdeasm.workspace_name, tenant_id=mdeasm.tenant_id, subscription_id=mdeasm.subscription_id, client_id=mdeasm.client_id, client_secret=mdeasm.client_secret)

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

