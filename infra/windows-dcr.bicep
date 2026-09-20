param location string
param logAnalyticsWorkspaceResourceId string

resource windowsDcr 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: 'dcr-windows-logs'
  location: location
  properties: {
    dataSources: {
      windowsEventLogs: [
        {
          name: 'securityLogDataSource'
          streams: [
            'Microsoft-SecurityEvent'
          ]
          xPathQueries: [
            'Security!*[System[(EventID=4624 or EventID=4625 or EventID=4688)]]'
          ]
        }
        {
          name: 'sysmonLogDataSource'
          streams: [
            'Microsoft-Event'
          ]
          xPathQueries: [
            'Microsoft-Windows-Sysmon/Operational!*[System[(EventID=1 or EventID=3 or EventID=11 or EventID=22)]]'
          ]
        }
      ]
    }
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: logAnalyticsWorkspaceResourceId
          name: 'windowsWorkspace'
        }
      ]
    }
    dataFlows: [
      {
        streams: [
          'Microsoft-SecurityEvent'
        ]
        destinations: [
          'windowsWorkspace'
        ]
      }
      {
        streams: [
          'Microsoft-Event'
        ]
        destinations: [
          'windowsWorkspace'
        ]
      }
    ]
  }
}

output dcrId string = windowsDcr.id
