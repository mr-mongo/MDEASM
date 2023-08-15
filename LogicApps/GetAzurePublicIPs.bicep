param location string = resourceGroup().location
param appNameSuffix string = uniqueString(resourceGroup().id, utcNow())

@description('The name of the EASM Resource Group')
param easmRG string

@description('The name of the EASM Workspace')
param easmWorkspace string

@description('Client ID of the Service Principal to assign Contributor rights to EASM Resource Group')
param servicePrincipalClientID string

@description('Client Secret of the Service Principal which will be stored in the Key Vault')
@secure()
param keyVaultSecretSPValue string

@allowed([
  'premium'
  'standard'
])
@description('Key Vault SKU name')
param keyVaultSku string = 'standard'

@description('The name of the Key Vault resource')
param kvName string = 'kv-mdeasm'

@allowed([
  'Approved'
  'Candidate'
  'Dependency'
  'Monitor Only'
  'Requires Investigation'
])
@description('State to assign to the IPs in the EASM Workspace')
param assetState string = 'Dependency'

@description('Label to asssign to the IPs in the EASM Workspace')
param assetLabel string = 'AzureIP'

var key_vault_secret_name = 'mdeasm-service-principal'
var logic_app_name = 'GetAzurePublicIPs'
var key_vault_name = '${kvName}-${appNameSuffix}'
var connections_key_vault_name = 'keyvault-${appNameSuffix}'
var asset_state_mapping = {
  Approved: 'confirmed'
  Candidate: 'candidate'
  Dependency: 'associatedThirdparty'
  'Monitor Only': 'associatedPartner'
  'Requires Investigation': 'candidateInvestigate'
}

resource keyVault 'Microsoft.KeyVault/vaults@2022-07-01' = {
  name: key_vault_name
  location: location
  properties: {
    sku: {
      family: 'A'
      name: keyVaultSku
    }
    tenantId: subscription().tenantId
    enabledForDeployment: false
    enabledForDiskEncryption: false
    enabledForTemplateDeployment: false
    enableRbacAuthorization: true
    networkAcls: {
      defaultAction: 'Allow'
      bypass: 'AzureServices'
    }
  }
}

resource keyVaultSecretEasm 'Microsoft.KeyVault/vaults/secrets@2021-10-01' = {
  name: key_vault_secret_name
  parent: keyVault
  properties: {
    value: keyVaultSecretSPValue
  }
}

resource logicAppKeyVaultConnection 'Microsoft.Web/connections@2018-07-01-preview' = {
  name: connections_key_vault_name
  location: location
  kind: 'V1'
  properties: {
    displayName: 'keyvault'
    api: {
      id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'keyvault')
    }
    parameterValueType: 'Alternative'
    alternativeParameterValues: {
      vaultName: key_vault_name
    }
  }
}

resource keyVaultRoleAssignmentUser 'Microsoft.Authorization/roleAssignments@2020-10-01-preview' = {
  name: guid(resourceGroup().id, keyVault.id)
  scope: keyVault
  properties: {
    principalId: MDEASM_GetAzurePublicIPs_LogicApp.identity.principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
    principalType: 'ServicePrincipal'
  }
}

resource resourceGroupRoleAssignmentContributor_LogicApp 'Microsoft.Authorization/roleAssignments@2020-10-01-preview' = {
  name: guid(resourceGroup().id, 'b24988ac-6180-42a0-ab88-20f7382dd24c')
  scope: resourceGroup()
  properties: {
    principalId: MDEASM_GetAzurePublicIPs_LogicApp.identity.principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b24988ac-6180-42a0-ab88-20f7382dd24c')
    principalType: 'ServicePrincipal'
  }
}

resource resourceGroupRoleAssignmentContributor_ServicePrincipal 'Microsoft.Authorization/roleAssignments@2020-10-01-preview' = {
  name: guid(resourceGroup().id, servicePrincipalClientID)
  scope: resourceGroup()
  properties: {
    principalId: servicePrincipalClientID
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b24988ac-6180-42a0-ab88-20f7382dd24c')
    principalType: 'ServicePrincipal'
  }
}

module subscriptionRoleAssignmentReader 'module_RoleAssignmentReader.bicep' = {
  name: 'subscriptionRoleAssignmentReader'
  scope: subscription()
  params: {
    principalId: MDEASM_GetAzurePublicIPs_LogicApp.identity.principalId
  }
}

resource MDEASM_GetAzurePublicIPs_LogicApp 'Microsoft.Logic/workflows@2017-07-01' = {
  name: logic_app_name
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    state: 'Enabled'
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      parameters: {
        '$connections': {
          defaultValue: {}
          type: 'Object'
        }
        asset_state: {
          defaultValue: asset_state_mapping[assetState]
          type: 'String'
        }
        client_id: {
          defaultValue: servicePrincipalClientID
          type: 'String'
        }
        easm_label: {
          defaultValue: assetLabel
          type: 'String'
        }
        easm_location: {
          defaultValue: location
          type: 'String'
        }
        easm_rg: {
          defaultValue: easmRG
          type: 'String'
        }
        easm_workspace: {
          defaultValue: easmWorkspace
          type: 'String'
        }
        subscription_id: {
          defaultValue: subscription().subscriptionId
          type: 'String'
        }
        tenant_id: {
          defaultValue: subscription().tenantId
          type: 'String'
        }
      }
      triggers: {
        Recurrence: {
          recurrence: {
            frequency: 'Week'
            interval: 1
          }
          evaluatedRecurrence: {
            frequency: 'Week'
            interval: 1
          }
          type: 'Recurrence'
        }
      }
      actions: {
        Create_Label_if_not_exists: {
          runAfter: {
            Get_Workspace_Label: [
              'Failed'
            ]
          }
          type: 'Http'
          inputs: {
            authentication: {
              audience: environment().resourceManager
              clientId: '@parameters(\'client_id\')'
              secret: '@body(\'Get_SpSecret\')?[\'value\']'
              tenant: '@parameters(\'tenant_id\')'
              type: 'ActiveDirectoryOAuth'
            }
            body: '@json(concat(\'{"properties":{"displayName":"\',parameters(\'easm_label\'),\'"}}\'))'
            method: 'PUT'
            queries: {
              'api-version': '2022-04-01-preview'
            }
            uri: '${environment().resourceManager}/subscriptions/@{parameters(\'subscription_id\')}/resourceGroups/@{parameters(\'easm_rg\')}/providers/Microsoft.Easm/workspaces/@{parameters(\'easm_workspace\')}/labels/@{parameters(\'easm_label\')}'
          }
        }
        Dedup_public_ips: {
          runAfter: {
            For_each_topology: [
              'Succeeded'
            ]
          }
          type: 'Compose'
          inputs: '@skip(reverse(union(variables(\'public_ips\'), array(\'[]\'))),1)'
        }
        For_each_public_ip: {
          foreach: '@variables(\'public_ips\')'
          actions: {
            Get_Asset_UUID: {
              runAfter: {}
              type: 'Http'
              inputs: {
                authentication: {
                  audience: 'https://easm.defender.microsoft.com/'
                  clientId: '@parameters(\'client_id\')'
                  secret: '@body(\'Get_SpSecret\')?[\'value\']'
                  tenant: '@parameters(\'tenant_id\')'
                  type: 'ActiveDirectoryOAuth'
                }
                method: 'GET'
                queries: {
                  'api-version': '2023-05-01-preview'
                }
                uri: 'https://@{parameters(\'easm_location\')}.easm.defender.microsoft.com/subscriptions/@{parameters(\'subscription_id\')}/resourceGroups/@{parameters(\'easm_rg\')}/workspaces/@{parameters(\'easm_workspace\')}/assets/@{base64(concat(\'ipAddress$$\',item()))}'
              }
            }
            Update_Asset_State_and_Label: {
              runAfter: {
                Get_Asset_UUID: [
                  'Succeeded'
                ]
              }
              type: 'Http'
              inputs: {
                authentication: {
                  audience: 'https://easm.defender.microsoft.com/'
                  clientId: '@parameters(\'client_id\')'
                  secret: '@body(\'Get_SpSecret\')?[\'value\']'
                  tenant: '@parameters(\'tenant_id\')'
                  type: 'ActiveDirectoryOAuth'
                }
                body: '@variables(\'update_body\')'
                headers: {
                  'Content-Type': 'application/json'
                }
                method: 'POST'
                queries: {
                  'api-version': '2023-05-01-preview'
                  filter: '@{concat(\'uuid = "\',body(\'Get_Asset_UUID\')?[\'uuid\'],\'"\')}'
                }
                uri: 'https://@{parameters(\'easm_location\')}.easm.defender.microsoft.com/subscriptions/@{parameters(\'subscription_id\')}/resourceGroups/@{parameters(\'easm_rg\')}/workspaces/@{parameters(\'easm_workspace\')}/assets'
              }
            }
          }
          runAfter: {
            Set_update_body: [
              'Succeeded'
            ]
          }
          type: 'Foreach'
        }
        For_each_topology: {
          foreach: '@body(\'List_Resource_Topologies\')?[\'value\']'
          actions: {
            For_each_resource: {
              foreach: '@item()?[\'properties\']?[\'topologyResources\']'
              actions: {
                Is_InternetFacing: {
                  actions: {
                    For_each_InternetFacing: {
                      foreach: '@item()?[\'info\']'
                      actions: {
                        Is_PublicIp: {
                          actions: {
                            Append_to_public_ips: {
                              runAfter: {}
                              type: 'AppendToArrayVariable'
                              inputs: {
                                name: 'public_ips'
                                value: '@item()?[\'value\']'
                              }
                            }
                          }
                          runAfter: {}
                          expression: {
                            and: [
                              {
                                equals: [
                                  '@item()?[\'name\']'
                                  'PublicIp'
                                ]
                              }
                            ]
                          }
                          type: 'If'
                        }
                      }
                      runAfter: {}
                      type: 'Foreach'
                    }
                  }
                  runAfter: {}
                  expression: {
                    and: [
                      {
                        equals: [
                          '@item()?[\'networkZones\']'
                          'InternetFacing'
                        ]
                      }
                    ]
                  }
                  type: 'If'
                }
              }
              runAfter: {}
              type: 'Foreach'
            }
          }
          runAfter: {
            List_Resource_Topologies: [
              'Succeeded'
            ]
          }
          type: 'Foreach'
          runtimeConfiguration: {
            concurrency: {
              repetitions: 1
            }
          }
        }
        Get_SpSecret: {
          runAfter: {
            Initialize_update_body: [
              'Succeeded'
            ]
          }
          type: 'ApiConnection'
          inputs: {
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'keyvault\'][\'connectionId\']'
              }
            }
            method: 'get'
            path: '/secrets/@{encodeURIComponent(\'${key_vault_secret_name}\')}/value'
          }
        }
        Get_Workspace_Label: {
          runAfter: {
            Set_deduped_public_ips: [
              'Succeeded'
            ]
          }
          type: 'Http'
          inputs: {
            authentication: {
              audience: environment().resourceManager
              clientId: '@parameters(\'client_id\')'
              secret: '@body(\'Get_SpSecret\')?[\'value\']'
              tenant: '@parameters(\'tenant_id\')'
              type: 'ActiveDirectoryOAuth'
            }
            headers: {
              Authorization: ''
            }
            method: 'GET'
            queries: {
              'api-version': '2022-04-01-preview'
            }
            uri: '${environment().resourceManager}/subscriptions/@{parameters(\'subscription_id\')}/resourceGroups/@{parameters(\'easm_rg\')}/providers/Microsoft.Easm/workspaces/@{parameters(\'easm_workspace\')}/labels/@{parameters(\'easm_label\')}'
          }
        }
        Initialize_public_ips: {
          runAfter: {}
          type: 'InitializeVariable'
          inputs: {
            variables: [
              {
                name: 'public_ips'
                type: 'array'
              }
            ]
          }
        }
        Initialize_update_body: {
          runAfter: {
            Initialize_public_ips: [
              'Succeeded'
            ]
          }
          type: 'InitializeVariable'
          inputs: {
            variables: [
              {
                name: 'update_body'
                type: 'object'
              }
            ]
          }
        }
        List_Resource_Topologies: {
          runAfter: {
            Get_SpSecret: [
              'Succeeded'
            ]
          }
          type: 'Http'
          inputs: {
            authentication: {
              type: 'ManagedServiceIdentity'
            }
            method: 'GET'
            queries: {
              'api-version': '2020-01-01'
              includeResourceInformation: 'true'
            }
            uri: '${environment().resourceManager}/subscriptions/@{parameters(\'subscription_id\')}/providers/Microsoft.Security/topologies'
          }
        }
        Set_deduped_public_ips: {
          runAfter: {
            Dedup_public_ips: [
              'Succeeded'
            ]
          }
          type: 'SetVariable'
          inputs: {
            name: 'public_ips'
            value: '@outputs(\'Dedup_public_ips\')'
          }
        }
        Set_update_body: {
          runAfter: {
            Create_Label_if_not_exists: [
              'Succeeded'
              'Skipped'
            ]
          }
          type: 'SetVariable'
          inputs: {
            name: 'update_body'
            value: '@json(concat(\'{"state":"\',parameters(\'asset_state\'),\'", "labels": {"\',parameters(\'easm_label\'),\'": true}}\'))'
          }
        }
      }
      outputs: {}
    }
    parameters: {
      '$connections': {
        value: {
          keyvault: {
            connectionId: logicAppKeyVaultConnection.id
            connectionName: connections_key_vault_name
            connectionProperties: {
              authentication: {
                type: 'ManagedServiceIdentity'
              }
            }
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'keyvault')
          }
        }
      }
    }
  }
}
