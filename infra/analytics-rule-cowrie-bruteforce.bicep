param logAnalyticsWorkspaceName string

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: logAnalyticsWorkspaceName
}

resource cowrieBruteForceRule 'Microsoft.SecurityInsights/alertRules@2023-11-01' = {
  scope: workspace
  name: guid('cowrie-bruteforce-rule')
  kind: 'Scheduled'
  properties: {
    displayName: 'Cowrie SSH Brute Force Detected'
    description: 'Flags source IPs with 6+ failed SSH login attempts against the Cowrie honeypot within 24 hours, catching both rapid and slow/evasive brute-force patterns.'
    severity: 'Medium'
    enabled: true
    query: '''
      Cowrie_CL
      | extend Parsed = parse_json(RawData)
      | where tostring(Parsed.eventid) == "cowrie.login.failed"
      | extend SourceIP = tostring(Parsed.src_ip), Username = tostring(Parsed.username), Password = tostring(Parsed.password)
      | summarize FailedAttempts = count(), Usernames = make_set(Username), Passwords = make_set(Password) by SourceIP
      | where FailedAttempts >= 6
    '''
    queryFrequency: 'PT1H'
    queryPeriod: 'P1D'
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
    ]
  }
}
