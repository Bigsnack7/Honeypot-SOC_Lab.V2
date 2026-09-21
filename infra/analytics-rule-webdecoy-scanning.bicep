param logAnalyticsWorkspaceName string

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: logAnalyticsWorkspaceName
}

resource webDecoyScanningRule 'Microsoft.SecurityInsights/alertRules@2023-11-01' = {
  scope: workspace
  name: guid('webdecoy-scanning-rule')
  kind: 'Scheduled'
  properties: {
    displayName: 'Web Decoy Sensitive Path Scanning Detected'
    description: 'Flags source IPs probing multiple honeytoken paths (wp-login.php, .env, admin) within 10 minutes.'
    severity: 'Medium'
    enabled: true
    query: '''
      WebDecoy_CL
      | extend Parsed = parse_json(RawData)
      | where isnotempty(Parsed.honeytoken)
      | summarize ProbedPaths = make_set(tostring(Parsed.path)), ProbeCount = count() by SourceIP = tostring(Parsed.src_ip), bin(TimeGenerated, 10m)
      | where ProbeCount >= 3
    '''
    queryFrequency: 'PT10M'
    queryPeriod: 'PT10M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'Reconnaissance'
    ]
    techniques: [
      'T1595'
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
