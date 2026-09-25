param logAnalyticsWorkspaceName string
param deploymentTime string = utcNow()

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: logAnalyticsWorkspaceName
}

resource threatIntelConnector 'Microsoft.SecurityInsights/dataConnectors@2023-02-01-preview' = {
  scope: workspace
  name: guid(resourceGroup().id, 'microsoft-threat-intelligence-connector')
  kind: 'MicrosoftThreatIntelligence'
  properties: {
    tenantId: subscription().tenantId
    dataTypes: {
      microsoftEmergingThreatFeed: {
        lookbackPeriod: dateTimeAdd(deploymentTime, '-P7D')
        state: 'Enabled'
      }
      bingSafetyPhishingURL: {
        lookbackPeriod: dateTimeAdd(deploymentTime, '-P7D')
        state: 'Enabled'
      }
    }
  }
}

