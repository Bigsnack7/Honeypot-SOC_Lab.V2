param logAnalyticsWorkspaceName string

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: logAnalyticsWorkspaceName
}

resource cowrieTable 'Microsoft.OperationalInsights/workspaces/tables@2023-09-01' = {
  parent: workspace
  name: 'Cowrie_CL'
  properties: {
    schema: {
      name: 'Cowrie_CL'
      columns: [
        { name: 'TimeGenerated', type: 'datetime' }
        { name: 'RawData', type: 'string' }
      ]
    }
    retentionInDays: 30
  }
}

