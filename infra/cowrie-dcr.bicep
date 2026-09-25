param location string
param logAnalyticsWorkspaceResourceId string

resource cowrieDcr 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: 'dcr-cowrie-logs'
  location: location
  properties: {
    streamDeclarations: {
      'Custom-Cowrie_CL': {
        columns: [
          { name: 'TimeGenerated', type: 'datetime' }
          { name: 'RawData', type: 'string' }
        ]
      }
    }
    dataSources: {
      logFiles: [
        {
          name: 'cowrieLogDataSource'
          streams: [
            'Custom-Cowrie_CL'
          ]
          filePatterns: [
            '/home/cowrie/my-honeypot/var/log/cowrie/cowrie.json'
          ]
          format: 'text'
          settings: {
            text: {
              recordStartTimestampFormat: 'ISO 8601'
            }
          }
        }
      ]
    }
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: logAnalyticsWorkspaceResourceId
          name: 'cowrieWorkspace'
        }
      ]
    }
    dataFlows: [
      {
        streams: [           'Custom-Cowrie_CL'
        ]
        destinations: [
          'cowrieWorkspace'
        ]
        transformKql: 'source | extend TimeGenerated = now(), RawData = RawData'
        outputStream: 'Custom-Cowrie_CL'
      }
    ]
  }
}

output dcrId string = cowrieDcr.id

