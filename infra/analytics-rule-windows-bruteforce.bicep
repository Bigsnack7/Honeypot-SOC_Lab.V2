param logAnalyticsWorkspaceName string

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: logAnalyticsWorkspaceName
}

resource windowsBruteForceRule 'Microsoft.SecurityInsights/alertRules@2023-11-01' = {
  scope: workspace
  name: guid(resourceGroup().id, 'windows-bruteforce-rule')
  kind: 'Scheduled'
  properties: {
    displayName: 'Windows RDP Brute Force Detected'
    description: 'Flags source IPs with 5+ failed RDP login attempts against the Windows honeypot within 5 minutes.'
    severity: 'Medium'
    enabled: true
    query: '''
      SecurityEvent
      | where EventID == 4625
      | summarize FailedAttempts = count(), Accounts = make_set(TargetAccount) by IpAddress, bin(TimeGenerated, 5m)
      | where FailedAttempts >= 5
      | extend SourceIP = IpAddress
    '''
    queryFrequency: 'PT5M'
    queryPeriod: 'PT5M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'CredentialAccess'
    ]
    techniques: [
      'T1110'
    ]
    entityMappings: [
      {
        entityType: 'IP'
        fieldMappings: [
          {
            identifier: 'Address'
            columnName: 'SourceIP'
          }
        ]
      }
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'Accounts'
          }
        ]
      }
    ]
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT1H'
        matchingMethod: 'AnyAlert'
      }
    }
  }
}
