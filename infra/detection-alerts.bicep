param location string
param workspaceId string
param alertEmail string

resource actionGroup 'Microsoft.Insights/actionGroups@2023-01-01' = {
  name: 'ag-honeypot-soc'
  location: 'global'
  properties: {
    groupShortName: 'HoneypotSOC'
    enabled: true
    emailReceivers: [
      {
        name: 'soc-email'
        emailAddress: alertEmail
        useCommonAlertSchema: true
      }
    ]
  }
}
