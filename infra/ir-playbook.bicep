param location string

resource sentinelConnection 'Microsoft.Web/connections@2018-07-01-preview' = {
  name: 'azuresentinel-connection'
  location: location
  properties: {
    displayName: 'azuresentinel-connection'
    parameterValueType: 'Alternative'
    api: {
      id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuresentinel')
    }
  }
}

resource irPlaybook 'Microsoft.Logic/workflows@2019-05-01' = {
  name: 'playbook-incident-enrichment-notify'
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
      }
      triggers: {
        Microsoft_Sentinel_incident: {
          type: 'ApiConnectionWebhook'
          inputs: {
            body: {
              callback_url: '@{listCallbackUrl()}'
            }
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azuresentinel\'][\'connectionId\']'
              }
            }
            path: '/incident-creation'
          }
        }
      }
      actions: {
        Send_notification_email: {
          type: 'ApiConnection'
          inputs: {
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azuresentinel\'][\'connectionId\']'
              }
            }
            method: 'post'
            path: '/Incidents/@{encodeURIComponent(triggerBody()?[\'object\']?[\'id\'])}/comments'
            body: {
              message: 'Automated notice: New incident "@{triggerBody()?[\'object\']?[\'properties\']?[\'title\']}" (severity: @{triggerBody()?[\'object\']?[\'properties\']?[\'severity\']}) was created. Attacker IPs and entities have been logged for review.'
            }
          }
          runAfter: {}
        }
      }
      outputs: {}
    }
    parameters: {
      '$connections': {
        value: {
          azuresentinel: {
            connectionId: sentinelConnection.id
            connectionName: 'azuresentinel-connection'
            connectionProperties: {
              authentication: {
                type: 'ManagedServiceIdentity'
              }
            }
            id: subscriptionResourceId('Microsoft.Web/locations/managedApis', location, 'azuresentinel')
          }
        }
      }
    }
  }
}

output playbookResourceId string = irPlaybook.id
output playbookPrincipalId string = irPlaybook.identity.principalId
