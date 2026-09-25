param location string = 'centralus'
param logAnalyticsWorkspaceResourceId string

resource webDecoyDcr 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: 'dcr-webdecoy-logs'
  location: location
  properties: {
    streamDeclarations: {
      'Custom-WebDecoy_CL': {
        columns: [
          { name: 'TimeGenerated', type: 'datetime' }
          { name: 'RawData', type: 'string' }
        ]
      }
    }
    dataSources: {
      logFiles: [
        {
          name: 'webDecoyLogDataSource'
          streams: [
            'Custom-WebDecoy_CL'
          ]
          filePatterns: [
            '/home/webdecoy/app/access.json'
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
          name: 'webDecoyWorkspace'
        }
      ]
    }
    dataFlows: [
      {
        streams: [
          'Custom-WebDecoy_CL'
        ]
        destinations: [
          'webDecoyWorkspace'
        ]
        transformKql: 'source | extend TimeGenerated = now(), RawData = RawData'
        outputStream: 'Custom-WebDecoy_CL'
      }
    ]
  }
}

output dcrId string = webDecoyDcr.id
