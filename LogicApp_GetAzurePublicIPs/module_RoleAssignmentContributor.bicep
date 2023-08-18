targetScope = 'resourceGroup'

param principalId string
var contributor_role = 'b24988ac-6180-42a0-ab88-20f7382dd24c'

resource logicAppRoleAssignmentReader 'Microsoft.Authorization/roleAssignments@2020-10-01-preview' = {
  name: guid(resourceGroup().id, contributor_role)
  properties: {
    principalId: principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', contributor_role)
    principalType: 'ServicePrincipal'
  }
}
