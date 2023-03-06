#!/usr/bin/python3
import sys

#easiest to import mdeasm.py if it is in the same directory as this retreive_risk_observations.py script
#requires mdeasm.py VERSION 1.3
import mdeasm

if mdeasm._VERSION < 1.3:
    sys.exit(f"requires mdeasm.py VERSION 1.3; current version: {mdeasm._VERSION}")
#
# run either Option 1 or Option 2 (comment out each line in the section you are not running)

easm = mdeasm.Workspaces(workspace_name=mdeasm.workspace_name, tenant_id=mdeasm.tenant_id, subscription_id=mdeasm.subscription_id, client_id=mdeasm.client_id, client_secret=mdeasm.client_secret)

all_approved_assets = f"state = \"{easm._state_map['Approved']}\""

#enter one of: Candidate,Dependency,MonitorOnly,RequiresInvestigation,Dismissed
new_state = easm._state_map['']

#####################################
#####################################
# Option 1
#  change state of all Approved assets to another state
#  new state should _really_ be empty
#  move 200 assets from new state back to Approved

# this will submit the change, but that change will take a while to complete
easm.update_assets(query_filter=all_approved_assets, new_state=new_state)

move_all_approved_assets_task = easm.task_id[0]
print(f"move_all_approved_assets_task task id: {move_all_approved_assets_task}")

# poll the easm resource for the status of the change
# DO NOT proceed until 100% complete
easm.poll_asset_state_change(task_id=move_all_approved_assets_task)

assets_to_move_back_to_approved = f"state = \"{new_state}\""

# DO NOT run this until the poll above shows complete / 100% progress
# this will get the first 200 assets in new_state
easm.get_workspace_assets(query_filter=assets_to_move_back_to_approved, max_page_size=100, max_page_count=2)

for i in range(0, len(easm.assetList.assets), 50):
    asset_uiid_list = []
    for asset in easm.assetList.assets[i:i+50]:
        asset_uiid_list.append(asset.uuid)
    asset_uuid_str = '","'.join(asset_uiid_list)
    update_state_query = f"uuid in (\"{asset_uuid_str}\") AND state !empty"
    easm.update_assets(query_filter=update_state_query, new_state=easm._state_map['Approved'])

# this will take a few minutes to complete the change, even after function finishes
# confirm in the UI that 200 assets are back in Approved state

#####################################
#####################################
# Option 2
#  get all but first 200 Approved assets
#  change all but first 200 Approved assets to a new state
#  50 at a time

# get all approved assets except first 200
# depending on total number of approved assets, this may take a while
# ~1 minute per 1000 assets, depending on internet connection and any timeout errors
easm.get_workspace_assets(query_filter=all_approved_assets, page=2, max_page_size=100, get_all=True)

# iterate through all Approved asset except first 200
# and move 50 at a time to new_state
# this will likely take even longer than query above
for i in range(0, len(easm.assetList.assets), 50):
    asset_uiid_list = []
    for asset in easm.assetList.assets[i:i+50]:
        asset_uiid_list.append(asset.uuid)
    
    asset_uuid_str = '","'.join(asset_uiid_list)
    update_state_query = f"uuid in (\"{asset_uuid_str}\") AND state !empty"
    easm.update_assets(query_filter=update_state_query, new_state=new_state)
    
    # this will create several hundred state change tasks
    # so not polling any of them for status or completion
