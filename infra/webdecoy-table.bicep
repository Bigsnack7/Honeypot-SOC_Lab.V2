param logAnalyticsWorkspaceName string

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: logAnalyticsWorkspaceName
}

resource webDecoyTable 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspace
  name: 'WebDecoy_CL'
  properties: {
    schema: {
      name: 'WebDecoy_CL'
      columns: [
        { name: 'TimeGenerated', type: 'datetime' }
        { name: 'RawData', type: 'string' }
      ]
    }
    retentionInDays: 30
  }
}

