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

resource cowrieAlert 'Microsoft.Insights/scheduledQueryRules@2022-06-15' = {
  name: 'alert-cowrie-ssh-bruteforce'
  location: location
  properties: {
    displayName: 'Cowrie SSH Brute Force Detected'
    description: 'Source IPs with 6+ failed SSH logins against the Cowrie honeypot in 24 hours (MITRE T1110).'
    severity: 2
    enabled: true
    evaluationFrequency: 'PT1H'
    windowSize: 'P1D'
    muteActionsDuration: 'PT1H'
    scopes: [
      workspaceId
    ]
    criteria: {
      allOf: [
        {
          query: '''
            Cowrie_CL
            | extend Parsed = parse_json(RawData)
            | where tostring(Parsed.eventid) == "cowrie.login.failed"
            | extend SourceIP = tostring(Parsed.src_ip)
            | summarize FailedAttempts = count() by SourceIP
            | where FailedAttempts >= 6
          '''
          timeAggregation: 'Count'
          operator: 'GreaterThan'
          threshold: 0
          failingPeriods: {
            numberOfEvaluationPeriods: 1
            minFailingPeriodsToAlert: 1
          }
        }
      ]
    }
    actions: {
      actionGroups: [
        actionGroup.id
      ]
    }
  }
}

resource windowsAlert 'Microsoft.Insights/scheduledQueryRules@2022-06-15' = {
  name: 'alert-windows-rdp-bruteforce'
  location: location
  properties: {
    displayName: 'Windows RDP Brute Force Detected'
    description: 'Source IPs with 5+ failed logons (4625) against the Windows honeypot in 5 minutes (MITRE T1110).'
    severity: 2
    enabled: true
    evaluationFrequency: 'PT5M'
    windowSize: 'PT5M'
    muteActionsDuration: 'PT1H'
    scopes: [
      workspaceId
    ]
    criteria: {
      allOf: [
        {
          query: '''
            SecurityEvent
            | where EventID == 4625
            | summarize FailedAttempts = count() by SourceIP = IpAddress
            | where FailedAttempts >= 5
          '''
          timeAggregation: 'Count'
          operator: 'GreaterThan'
          threshold: 0
          failingPeriods: {
            numberOfEvaluationPeriods: 1
            minFailingPeriodsToAlert: 1
          }
        }
      ]
    }
    actions: {
      actionGroups: [
        actionGroup.id
      ]
    }
  }
}

resource webAlert 'Microsoft.Insights/scheduledQueryRules@2022-06-15' = {
  name: 'alert-webdecoy-path-scanning'
  location: location
  properties: {
    displayName: 'Web Decoy Sensitive Path Scanning Detected'
    description: 'Source IPs probing 3+ honeytoken paths within 10 minutes (MITRE T1595).'
    severity: 2
    enabled: true
    evaluationFrequency: 'PT10M'
    windowSize: 'PT10M'
    muteActionsDuration: 'PT1H'
    scopes: [
      workspaceId
    ]
    criteria: {
      allOf: [
        {
          query: '''
            WebDecoy_CL
            | extend Parsed = parse_json(RawData)
            | where isnotempty(Parsed.honeytoken)
            | summarize ProbeCount = count() by SourceIP = tostring(Parsed.src_ip)
            | where ProbeCount >= 3
          '''
          timeAggregation: 'Count'
          operator: 'GreaterThan'
          threshold: 0
          failingPeriods: {
            numberOfEvaluationPeriods: 1
            minFailingPeriodsToAlert: 1
          }
        }
      ]
    }
    actions: {
      actionGroups: [
        actionGroup.id
      ]
    }
  }
}
