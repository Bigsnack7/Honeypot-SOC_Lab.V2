targetScope = 'resourceGroup'

param location string
param nsgName string
param vnetName string
param logAnalyticsWorkspaceName string

@description('Email address to receive detection alert notifications.')
param alertEmail string

@description('Set to true only during initial provisioning to allow package installs on decoy VMs. Redeploy with false once cloud-init has completed.')
param allowProvisioningEgress bool = false

@secure()
param adminPassword string

@secure()
param sshPublicKey string

@description('Object ID of the Azure Security Insights (Microsoft Sentinel) service principal in this tenant. Unused now that alert rules run as Azure Monitor scheduled query rules, kept for compatibility with existing pipeline parameters.')
param sentinelPrincipalId string

// A. Deploy the Network Security Group via Azure Verified Modules (AVM)
module nsg 'br/public:avm/res/network/network-security-group:0.5.0' = {
  name: 'nsgDeployment-${uniqueString(deployment().name)}'
  params: {
    name: nsgName
    location: location
    securityRules: concat([
      {
        name: 'Allow-Inbound-RDP'
        properties: {
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '3389'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 1001
          direction: 'Inbound'
        }
      }
      {
        name: 'Allow-Inbound-SSH'
        properties: {
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '22'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 1002
          direction: 'Inbound'
        }
      }
      {
        name: 'Allow-Inbound-HTTP'
        properties: {
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '80'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 1003
          direction: 'Inbound'
        }
      }
      {
        name: 'Allow-Inbound-SMB'
        properties: {
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '445'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 1004
          direction: 'Inbound'
        }
      }
      // Outbound allows must sit ABOVE the internet deny so telemetry can escape
      {
        name: 'Allow-Outbound-AzureMonitor'
        properties: {
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: 'AzureMonitor'
          access: 'Allow'
          priority: 100
          direction: 'Outbound'
        }
      }
      {
        name: 'Allow-Outbound-AzureActiveDirectory'
        properties: {
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: 'AzureActiveDirectory'
          access: 'Allow'
          priority: 110
          direction: 'Outbound'
        }
      }
      {
        name: 'Allow-Outbound-Storage'
        properties: {
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: 'Storage'
          access: 'Allow'
          priority: 120
          direction: 'Outbound'
        }
      }
      {
        name: 'Allow-Outbound-AzureResourceManager'
        properties: {
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: 'AzureResourceManager'
          access: 'Allow'
          priority: 130
          direction: 'Outbound'
        }
      }
      {
        name: 'Deny-Outbound-To-Internet'
        properties: {
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '*'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: 'Internet'
          access: 'Deny'
          priority: 1000
          direction: 'Outbound'
        }
      }
    ], allowProvisioningEgress ? [
      {
        name: 'Temp-Allow-Outbound-Provisioning'
        properties: {
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRanges: [
            '80'
            '443'
          ]
          sourceAddressPrefix: '*'
          destinationAddressPrefix: 'Internet'
          access: 'Allow'
          priority: 140
          direction: 'Outbound'
        }
      }
    ] : [])
  }
}

// B. Deploy the Virtual Network via Azure Verified Modules (AVM)
module vnet 'br/public:avm/res/network/virtual-network:0.5.1' = {
  name: 'vnetDeployment-${uniqueString(deployment().name)}'
  params: {
    name: vnetName
    location: location
    addressPrefixes: [
      '10.0.0.0/16'
    ]
    subnets: [
      {
        name: 'subnet-decoys'
        addressPrefix: '10.0.1.0/24'
        networkSecurityGroupResourceId: nsg.outputs.resourceId
      }
    ]
  }
}

// C. Deploy the Log Analytics Workspace
resource law 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: logAnalyticsWorkspaceName
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
    workspaceCapping: {
      dailyQuotaGb: 1
    }
  }
}

// D. Onboard Microsoft Sentinel (kept for the workbook dashboard / Sentinel data view;
// analytics rule creation is done via Azure Monitor scheduled query rules below instead,
// since Sentinel alert rule writes are blocked on Free Trial + spending-limit subscriptions)
resource sentinel 'Microsoft.OperationsManagement/solutions@2015-11-01-preview' = {
  name: 'SecurityInsights(${logAnalyticsWorkspaceName})'
  location: location
  plan: {
    name: 'SecurityInsights(${logAnalyticsWorkspaceName})'
    product: 'OMSGallery/SecurityInsights'
    publisher: 'Microsoft'
    promotionCode: ''
  }
  properties: {
    workspaceResourceId: law.id
  }
}

// D2. Complete Sentinel onboarding for the modern API
resource sentinelOnboarding 'Microsoft.SecurityInsights/onboardingStates@2023-02-01-preview' = {
  scope: law
  name: 'default'
  properties: {}
}

// Action Group: sends email when any detection rule fires.
// Replaces Sentinel's incident/notification layer, which required paid Sentinel alert rules.
resource honeypotAlertActionGroup 'Microsoft.Insights/actionGroups@2023-01-01' = {
  name: 'ag-honeypot-alerts'
  location: 'global'
  properties: {
    groupShortName: 'HoneypotAG'
    enabled: true
    emailReceivers: [
      {
        name: 'HoneypotAdmin'
        emailAddress: alertEmail
        useCommonAlertSchema: true
      }
    ]
  }
}

// M. Cowrie SSH Brute Force Detection
resource cowrieBruteForceRule 'Microsoft.Insights/scheduledQueryRules@2023-03-15-preview' = {
  name: 'cowrie-bruteforce-rule'
  location: location
  properties: {
    displayName: 'Cowrie SSH Brute Force Detected'
    description: 'Flags source IPs with 6+ failed SSH login attempts against the Cowrie honeypot within 24 hours, catching both rapid and slow/evasive brute-force patterns.'
    severity: 2
    enabled: true
    scopes: [
      law.id
    ]
    evaluationFrequency: 'PT1H'
    windowSize: 'P1D'
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
        }
      ]
    }
    actions: {
      actionGroups: [
        honeypotAlertActionGroup.id
      ]
    }
    autoMitigate: false
  }
  dependsOn: [
    cowrieTable
  ]
}

// N. Windows RDP Brute Force Detection
resource windowsBruteForceRule 'Microsoft.Insights/scheduledQueryRules@2023-03-15-preview' = {
  name: 'windows-bruteforce-rule'
  location: location
  properties: {
    displayName: 'Windows RDP Brute Force Detected'
    description: 'Flags source IPs with 5+ failed RDP login attempts against the Windows honeypot within 5 minutes.'
    severity: 2
    enabled: true
    scopes: [
      law.id
    ]
    evaluationFrequency: 'PT5M'
    windowSize: 'PT5M'
    criteria: {
      allOf: [
        {
          query: '''
            SecurityEvent
            | where EventID == 4625
            | summarize FailedAttempts = count() by IpAddress, bin(TimeGenerated, 5m)
            | where FailedAttempts >= 5
          '''
          timeAggregation: 'Count'
          operator: 'GreaterThan'
          threshold: 0
        }
      ]
    }
    actions: {
      actionGroups: [
        honeypotAlertActionGroup.id
      ]
    }
    autoMitigate: false
  }
  dependsOn: [
    windowsDcr
  ]
}

// O. Web Decoy Sensitive Path Scanning
resource webDecoyScanningRule 'Microsoft.Insights/scheduledQueryRules@2023-03-15-preview' = {
  name: 'webdecoy-scanning-rule'
  location: location
  properties: {
    displayName: 'Web Decoy Sensitive Path Scanning Detected'
    description: 'Flags source IPs probing multiple honeytoken paths (wp-login.php, .env, admin) within 10 minutes.'
    severity: 2
    enabled: true
    scopes: [
      law.id
    ]
    evaluationFrequency: 'PT10M'
    windowSize: 'PT10M'
    criteria: {
      allOf: [
        {
          query: '''
            WebDecoy_CL
            | extend Parsed = parse_json(RawData)
            | where isnotempty(Parsed.honeytoken)
            | summarize ProbeCount = count() by SourceIP = tostring(Parsed.src_ip), bin(TimeGenerated, 10m)
            | where ProbeCount >= 3
          '''
          timeAggregation: 'Count'
          operator: 'GreaterThan'
          threshold: 0
        }
      ]
    }
    actions: {
      actionGroups: [
        honeypotAlertActionGroup.id
      ]
    }
    autoMitigate: false
  }
  dependsOn: [
    webDecoyTable
  ]
}

// M2. Cowrie Pipeline Health (added after 2026-09-21 incident)
resource cowriePipelineSilentRule 'Microsoft.Insights/scheduledQueryRules@2023-03-15-preview' = {
  name: 'cowrie-pipeline-silent-rule'
  location: location
  properties: {
    displayName: 'Cowrie Honeypot - No Data Received'
    description: 'Fires when Cowrie_CL has received no events in 30+ minutes. VM heartbeat alone does not catch a crashed or misconfigured honeypot process - see INCIDENT_2026-09-21_provisioning_failures.md'
    severity: 2
    enabled: true
    scopes: [
      law.id
    ]
    evaluationFrequency: 'PT15M'
    windowSize: 'PT1H'
    criteria: {
      allOf: [
        {
          query: '''
            Cowrie_CL
            | summarize Latest = max(TimeGenerated)
            | where Latest < ago(30m)
          '''
          timeAggregation: 'Count'
          operator: 'GreaterThan'
          threshold: 0
        }
      ]
    }
    actions: {
      actionGroups: [
        honeypotAlertActionGroup.id
      ]
    }
    autoMitigate: false
  }
  dependsOn: [
    cowrieTable
  ]
}

// O2. WebDecoy Pipeline Health (added after 2026-09-21 incident)
resource webDecoyPipelineSilentRule 'Microsoft.Insights/scheduledQueryRules@2023-03-15-preview' = {
  name: 'webdecoy-pipeline-silent-rule'
  location: location
  properties: {
    displayName: 'Web Decoy Honeypot - No Data Received'
    description: 'Fires when WebDecoy_CL has received no events in 30+ minutes. Added after a 3-day silent outage where the web decoy crash-looped with no alert generated - see INCIDENT_2026-09-21_provisioning_failures.md'
    severity: 2
    enabled: true
    scopes: [
      law.id
    ]
    evaluationFrequency: 'PT15M'
    windowSize: 'PT1H'
    criteria: {
      allOf: [
        {
          query: '''
            WebDecoy_CL
            | summarize Latest = max(TimeGenerated)
            | where Latest < ago(30m)
          '''
          timeAggregation: 'Count'
          operator: 'GreaterThan'
          threshold: 0
        }
      ]
    }
    actions: {
      actionGroups: [
        honeypotAlertActionGroup.id
      ]
    }
    autoMitigate: false
  }
  dependsOn: [
    webDecoyTable
  ]
}

// M3. Cowrie Command Execution After Login
resource cowrieCommandExecutionRule 'Microsoft.Insights/scheduledQueryRules@2023-03-15-preview' = {
  name: 'cowrie-command-execution-rule'
  location: location
  properties: {
    displayName: 'Cowrie Command Execution After Login'
    description: 'An attacker logged in to the Cowrie honeypot and ran shell commands.'
    severity: 1
    enabled: true
    scopes: [
      law.id
    ]
    evaluationFrequency: 'PT15M'
    windowSize: 'PT15M'
    criteria: {
      allOf: [
        {
          query: '''
            Cowrie_CL
            | extend Parsed = parse_json(RawData)
            | where tostring(Parsed.eventid) == "cowrie.command.input"
            | extend SourceIP = tostring(Parsed.src_ip)
            | summarize CommandCount = count() by SourceIP
          '''
          timeAggregation: 'Count'
          operator: 'GreaterThan'
          threshold: 0
        }
      ]
    }
    actions: {
      actionGroups: [
        honeypotAlertActionGroup.id
      ]
    }
    autoMitigate: false
  }
  dependsOn: [
    cowrieTable
  ]
}

// N2. Windows Suspicious Process Creation
resource windowsProcessCreationRule 'Microsoft.Insights/scheduledQueryRules@2023-03-15-preview' = {
  name: 'windows-process-creation-rule'
  location: location
  properties: {
    displayName: 'Windows Suspicious Process Creation'
    description: 'Process creation (4688) of common attacker tools on the Windows honeypot.'
    severity: 1
    enabled: true
    scopes: [
      law.id
    ]
    evaluationFrequency: 'PT10M'
    windowSize: 'PT10M'
    criteria: {
      allOf: [
        {
          query: '''
            SecurityEvent
            | where EventID == 4688
            | where NewProcessName has_any ("powershell.exe", "cmd.exe", "certutil.exe", "bitsadmin.exe", "mshta.exe", "wmic.exe")
          '''
          timeAggregation: 'Count'
          operator: 'GreaterThan'
          threshold: 0
        }
      ]
    }
    actions: {
      actionGroups: [
        honeypotAlertActionGroup.id
      ]
    }
    autoMitigate: false
  }
  dependsOn: [
    windowsDcr
  ]
}

// M4. Cowrie Post-Exploit Command Sequences
resource cowriePostExploitSequencesRule 'Microsoft.Insights/scheduledQueryRules@2023-03-15-preview' = {
  name: 'cowrie-post-exploit-sequences-rule'
  location: location
  properties: {
    displayName: 'Cowrie Honeypot - Post-Exploit Command Sequence Detected'
    description: 'Flags known post-exploitation command patterns on the Cowrie shell - download-and-execute chains, permission changes, firewall/log tampering, cron persistence, and credential file access.'
    severity: 1
    enabled: true
    scopes: [
      law.id
    ]
    evaluationFrequency: 'PT10M'
    windowSize: 'PT10M'
    criteria: {
      allOf: [
        {
          query: '''
            Cowrie_CL
            | extend Parsed = parse_json(RawData)
            | where tostring(Parsed.eventid) == "cowrie.command.input"
            | extend Command = tostring(Parsed.input)
            | where Command has_any ("wget", "curl", "chmod", "iptables -F", "ufw disable", "crontab", "cat /etc/passwd", "cat /etc/shadow")
          '''
          timeAggregation: 'Count'
          operator: 'GreaterThan'
          threshold: 0
        }
      ]
    }
    actions: {
      actionGroups: [
        honeypotAlertActionGroup.id
      ]
    }
    autoMitigate: false
  }
  dependsOn: [
    cowrieTable
  ]
}

// N3. Windows Persistence Attempts
resource windowsPersistenceAttemptsRule 'Microsoft.Insights/scheduledQueryRules@2023-03-15-preview' = {
  name: 'windows-persistence-attempts-rule'
  location: location
  properties: {
    displayName: 'Windows Honeypot - Persistence Attempt Detected'
    description: 'Flags new scheduled tasks (4698) and new service installation (4697) on the Windows honeypot. No legitimate reason for these to occur here.'
    severity: 1
    enabled: true
    scopes: [
      law.id
    ]
    evaluationFrequency: 'PT10M'
    windowSize: 'PT10M'
    criteria: {
      allOf: [
        {
          query: '''
            SecurityEvent
            | where EventID in (4697, 4698)
          '''
          timeAggregation: 'Count'
          operator: 'GreaterThan'
          threshold: 0
        }
      ]
    }
    actions: {
      actionGroups: [
        honeypotAlertActionGroup.id
      ]
    }
    autoMitigate: false
  }
  dependsOn: [
    windowsDcr
  ]
}

// N4. Windows Discovery Commands
resource windowsDiscoveryCommandsRule 'Microsoft.Insights/scheduledQueryRules@2023-03-15-preview' = {
  name: 'windows-discovery-commands-rule'
  location: location
  properties: {
    displayName: 'Windows Honeypot - Discovery Commands Detected'
    description: 'Flags "just landed" recon commands (whoami, systeminfo, ipconfig, net user, nltest, etc.) typically run right after initial access, via Sysmon process creation.'
    severity: 2
    enabled: true
    scopes: [
      law.id
    ]
    evaluationFrequency: 'PT10M'
    windowSize: 'PT10M'
    criteria: {
      allOf: [
        {
          query: '''
            Event
            | where Source == "Microsoft-Windows-Sysmon" and EventID == 1
            | extend EvData = parse_xml(EventData).DataItem.EventData.Data
            | extend NewProcessName = tostring(EvData[4].["#text"])
            | where NewProcessName has_any ("whoami.exe", "systeminfo.exe", "ipconfig.exe", "nltest.exe", "net.exe", "net1.exe", "hostname.exe", "tasklist.exe", "quser.exe", "arp.exe", "route.exe", "nbtstat.exe")
          '''
          timeAggregation: 'Count'
          operator: 'GreaterThan'
          threshold: 0
        }
      ]
    }
    actions: {
      actionGroups: [
        honeypotAlertActionGroup.id
      ]
    }
    autoMitigate: false
  }
  dependsOn: [
    windowsDcr
  ]
}

// N5. Windows Event Log Clearing
resource eventLogClearingRule 'Microsoft.Insights/scheduledQueryRules@2023-03-15-preview' = {
  name: 'event-log-clearing-rule'
  location: location
  properties: {
    displayName: 'Windows Honeypot - Event Log Clearing Detected'
    description: 'Flags attempts to clear Windows event logs (EventID 1102/104) or wevtutil/Clear-EventLog command-line usage. No legitimate reason to occur on a honeypot - single hit is high confidence.'
    severity: 1
    enabled: true
    scopes: [
      law.id
    ]
    evaluationFrequency: 'PT10M'
    windowSize: 'PT10M'
    criteria: {
      allOf: [
        {
          query: '''
            SecurityEvent
            | where EventID in (1102, 104)
              or (EventID == 4688 and NewProcessName has_any ("wevtutil.exe", "powershell.exe", "pwsh.exe") and CommandLine has_any ("cl ", "clear-log", "Clear-EventLog", "wevtutil cl"))
          '''
          timeAggregation: 'Count'
          operator: 'GreaterThan'
          threshold: 0
        }
      ]
    }
    actions: {
      actionGroups: [
        honeypotAlertActionGroup.id
      ]
    }
    autoMitigate: false
  }
  dependsOn: [
    windowsDcr
  ]
}

// N6. Suspicious PowerShell Activity
resource powershellSuspiciousCommandsRule 'Microsoft.Insights/scheduledQueryRules@2023-03-15-preview' = {
  name: 'powershell-suspicious-commands-rule'
  location: location
  properties: {
    displayName: 'Windows Honeypot - Suspicious PowerShell Activity'
    description: 'Flags encoded commands, download cradles, AMSI bypass strings, and execution-policy bypass in PowerShell activity via Sysmon-captured command lines.'
    severity: 1
    enabled: true
    scopes: [
      law.id
    ]
    evaluationFrequency: 'PT10M'
    windowSize: 'PT10M'
    criteria: {
      allOf: [
        {
          query: '''
            Event
            | where Source == "Microsoft-Windows-Sysmon" and EventID == 1
            | extend EvData = parse_xml(EventData).DataItem.EventData.Data
            | extend NewProcessName = tostring(EvData[4].["#text"]), CommandLine = tostring(EvData[10].["#text"])
            | where NewProcessName has_any ("powershell.exe", "pwsh.exe")
            | where CommandLine has_any ("-enc", "-EncodedCommand", "IEX", "Invoke-Expression", "DownloadString", "DownloadFile", "amsiutils", "AmsiScanBuffer", "-ExecutionPolicy Bypass", "-exec bypass", "-WindowStyle Hidden", "-nop", "Invoke-Mimikatz")
          '''
          timeAggregation: 'Count'
          operator: 'GreaterThan'
          threshold: 0
        }
      ]
    }
    actions: {
      actionGroups: [
        honeypotAlertActionGroup.id
      ]
    }
    autoMitigate: false
  }
  dependsOn: [
    windowsDcr
  ]
}

// L. Create the Data Collection Rule for Windows (Security + Sysmon)
module windowsDcr './windows-dcr.bicep' = {
  name: 'windowsDcrDeployment-${uniqueString(deployment().name)}'
  params: {
    location: location
    logAnalyticsWorkspaceResourceId: law.id
  }
}

// E. Provision the Windows Decoy Virtual Machine
module windowsDecoy './windows-decoy.bicep' = {
  name: 'windowsDecoyDeployment-${uniqueString(deployment().name)}'
  params: {
    location: location
    subnetId: vnet.outputs.subnetResourceIds[0]
    adminPassword: adminPassword
    dcrId: windowsDcr.outputs.dcrId
  }
}

// H. Create the custom table for Cowrie logs
module cowrieTable './cowrie-table.bicep' = {
  name: 'cowrieTableDeployment-${uniqueString(deployment().name)}'
  params: {
    logAnalyticsWorkspaceName: law.name
  }
}

// I. Create the Data Collection Rule for Cowrie
module cowrieDcr './cowrie-dcr.bicep' = {
  name: 'cowrieDcrDeployment-${uniqueString(deployment().name)}'
  params: {
    location: location
    logAnalyticsWorkspaceResourceId: law.id
  }
  dependsOn: [
    cowrieTable
  ]
}

// F. Provision the Linux SSH Decoy (Cowrie)
module linuxDecoy './linux-ssh-decoy.bicep' = {
  name: 'linuxDecoyDeployment-${uniqueString(deployment().name)}'
  params: {
    location: location
    subnetId: vnet.outputs.subnetResourceIds[0]
    sshPublicKey: sshPublicKey
    dcrId: cowrieDcr.outputs.dcrId
  }
}

// J. Create the custom table for Web Decoy logs
module webDecoyTable './webdecoy-table.bicep' = {
  name: 'webDecoyTableDeployment-${uniqueString(deployment().name)}'
  params: {
    logAnalyticsWorkspaceName: law.name
  }
}

// K. Create the Data Collection Rule for Web Decoy
module webDecoyDcr './webdecoy-dcr.bicep' = {
  name: 'webDecoyDcrDeployment-${uniqueString(deployment().name)}'
  params: {
    logAnalyticsWorkspaceResourceId: law.id
  }
  dependsOn: [
    webDecoyTable
  ]
}

// G. Provision the Web App Decoy
module webDecoy './web-app-decoy.bicep' = {
  name: 'webDecoyDeployment-${uniqueString(deployment().name)}'
  params: {
    sshPublicKey: sshPublicKey
    dcrId: webDecoyDcr.outputs.dcrId
    allowProvisioningEgress: allowProvisioningEgress
  }
}

// P. Deploy the Sentinel Workbook Dashboard
module honeypotWorkbook './sentinel-workbook.bicep' = {
  name: 'honeypotWorkbookDeployment-${uniqueString(deployment().name)}'
  params: {
    location: location
    logAnalyticsWorkspaceResourceId: law.id
  }
  dependsOn: [
    sentinel
    sentinelOnboarding
  ]
}

// Q. Action group for future SOAR notifications (legacy scheduledQueryRules removed - superseded by native Sentinel analytics rules above)
module detectionAlerts './detection-alerts.bicep' = {
  name: 'detectionAlertsDeployment-${uniqueString(deployment().name)}'
  params: {
    alertEmail: alertEmail
  }
  dependsOn: [
    cowrieTable
    webDecoyTable
  ]
}

// S. Deploy the incident enrichment/notification playbook (SOAR).
// No longer auto-triggered by a Sentinel automation rule (removed, since it required
// paid Sentinel incidents). Wire this playbook's HTTP trigger URL into honeypotAlertActionGroup
// as a webhook receiver if you want it to keep firing automatically.
module irPlaybook './ir-playbook.bicep' = {
  name: 'irPlaybookDeployment-${uniqueString(deployment().name)}'
  params: {
    location: location
  }
  dependsOn: [
    sentinel
    sentinelOnboarding
  ]
}
