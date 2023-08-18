targetScope = 'subscription'

param principalId string
var reader_role = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'

resource logicAppRoleAssignmentReader 'Microsoft.Authorization/roleAssignments@2020-10-01-preview' = {
  name: guid(subscription().tenantId, subscription().id)
  scope: subscription()
  properties: {
    principalId: principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', reader_role)
    principalType: 'ServicePrincipal'
  }
}
