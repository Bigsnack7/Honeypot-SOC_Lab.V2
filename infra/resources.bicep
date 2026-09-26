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

@description('Object ID of the Azure Security Insights (Microsoft Sentinel) service principal in this tenant.')
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

// D. Onboard Microsoft Sentinel
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

// D2. Complete Sentinel onboarding for the modern API (alert rules require this)
resource sentinelOnboarding 'Microsoft.SecurityInsights/onboardingStates@2023-02-01-preview' = {
  scope: law
  name: 'default'
  properties: {}
}

// M. Analytics Rule: Cowrie SSH Brute Force Detection
resource cowrieBruteForceRule 'Microsoft.SecurityInsights/alertRules@2023-11-01' = {
  scope: law
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
      | summarize FailedAttempts = count(), Usernames = make_set(Username), Passwords = make_set(Password), AnyUsername = any(Username) by SourceIP
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
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'AnyUsername'
          }
        ]
      }
    ]
  }
  dependsOn: [
    sentinel
    sentinelOnboarding
    cowrieTable
  ]
}

// N. Analytics Rule: Windows RDP Brute Force Detection
resource windowsBruteForceRule 'Microsoft.SecurityInsights/alertRules@2023-11-01' = {
  scope: law
  name: guid('windows-bruteforce-rule')
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
    ]
  }
  dependsOn: [
    sentinel
    sentinelOnboarding
    windowsDcr
  ]
}

// O. Analytics Rule: Web Decoy Sensitive Path Scanning
resource webDecoyScanningRule 'Microsoft.SecurityInsights/alertRules@2023-11-01' = {
  scope: law
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
  dependsOn: [
    sentinel
    sentinelOnboarding
    webDecoyTable
  ]
}

// M2. Analytics Rule: Cowrie Pipeline Health (added after 2026-09-21 incident)
resource cowriePipelineSilentRule 'Microsoft.SecurityInsights/alertRules@2023-11-01' = {
  scope: law
  name: guid('cowrie-pipeline-silent-rule')
  kind: 'Scheduled'
  properties: {
    displayName: 'Cowrie Honeypot - No Data Received'
    description: 'Fires when Cowrie_CL has received no events in 30+ minutes. VM heartbeat alone does not catch a crashed or misconfigured honeypot process - see INCIDENT_2026-09-21_provisioning_failures.md'
    severity: 'Medium'
    enabled: true
    query: '''
      Cowrie_CL
      | summarize Latest = max(TimeGenerated)
      | where Latest < ago(30m)
    '''
    queryFrequency: 'PT15M'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'Impact'
    ]
  }
  dependsOn: [
    sentinel
    sentinelOnboarding
    cowrieTable
  ]
}

// O2. Analytics Rule: WebDecoy Pipeline Health (added after 2026-09-21 incident)
resource webDecoyPipelineSilentRule 'Microsoft.SecurityInsights/alertRules@2023-11-01' = {
  scope: law
  name: guid('webdecoy-pipeline-silent-rule')
  kind: 'Scheduled'
  properties: {
    displayName: 'Web Decoy Honeypot - No Data Received'
    description: 'Fires when WebDecoy_CL has received no events in 30+ minutes. Added after a 3-day silent outage where the web decoy crash-looped with no alert generated - see INCIDENT_2026-09-21_provisioning_failures.md'
    severity: 'Medium'
    enabled: true
    query: '''
      WebDecoy_CL
      | summarize Latest = max(TimeGenerated)
      | where Latest < ago(30m)
    '''
    queryFrequency: 'PT15M'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'Impact'
    ]
  }
  dependsOn: [
    sentinel
    sentinelOnboarding
    webDecoyTable
  ]
}

// M3. Analytics Rule: Cowrie Command Execution After Login
resource cowrieCommandExecutionRule 'Microsoft.SecurityInsights/alertRules@2023-11-01' = {
  scope: law
  name: guid('cowrie-command-execution-rule')
  kind: 'Scheduled'
  properties: {
    displayName: 'Cowrie Command Execution After Login'
    description: 'An attacker logged in to the Cowrie honeypot and ran shell commands.'
    severity: 'High'
    enabled: true
    query: '''
      Cowrie_CL
      | extend Parsed = parse_json(RawData)
      | where tostring(Parsed.eventid) == "cowrie.command.input"
      | extend SourceIP = tostring(Parsed.src_ip), Command = tostring(Parsed.input)
      | summarize CommandCount = count(), Commands = make_set(Command, 20) by SourceIP
    '''
    queryFrequency: 'PT15M'
    queryPeriod: 'PT15M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'Execution'
    ]
    techniques: [
      'T1059'
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
  dependsOn: [
    sentinel
    sentinelOnboarding
    cowrieTable
  ]
}

// N2. Analytics Rule: Windows Suspicious Process Creation
resource windowsProcessCreationRule 'Microsoft.SecurityInsights/alertRules@2023-11-01' = {
  scope: law
  name: guid('windows-process-creation-rule')
  kind: 'Scheduled'
  properties: {
    displayName: 'Windows Suspicious Process Creation'
    description: 'Process creation (4688) of common attacker tools on the Windows honeypot.'
    severity: 'High'
    enabled: true
    query: '''
      SecurityEvent
      | where EventID == 4688
      | where NewProcessName has_any ("powershell.exe", "cmd.exe", "certutil.exe", "bitsadmin.exe", "mshta.exe", "wmic.exe")
      | project TimeGenerated, Computer, Account, NewProcessName, ParentProcessName, CommandLine
      | extend HostName = Computer
    '''
    queryFrequency: 'PT10M'
    queryPeriod: 'PT10M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'Execution'
    ]
    techniques: [
      'T1059'
    ]
    entityMappings: [
      {
        entityType: 'Host'
        fieldMappings: [
          {
            identifier: 'HostName'
            columnName: 'HostName'
          }
        ]
      }
    ]
  }
  dependsOn: [
    sentinel
    sentinelOnboarding
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

// S. Deploy the incident enrichment/notification playbook (SOAR)
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

// T. Wire the playbook to run automatically when a new incident is created
resource incidentAutomationRule 'Microsoft.SecurityInsights/automationRules@2023-11-01' = {
  scope: law
  name: guid(resourceGroup().id, 'run-ir-playbook-on-incident-creation')
  properties: {
    displayName: 'Run IR playbook on incident creation'
    order: 1
    triggeringLogic: {
      isEnabled: true
      triggersOn: 'Incidents'
      triggersWhen: 'Created'
    }
    actions: [
      {
        order: 1
        actionType: 'RunPlaybook'
        actionConfiguration: {
          logicAppResourceId: irPlaybook.outputs.playbookResourceId
          tenantId: subscription().tenantId
        }
      }
    ]
  }
  dependsOn: [
    sentinel
    sentinelOnboarding
    playbookSentinelResponderRole
    sentinelAutomationContributorRole
  ]
}

// U. Grant the playbook's managed identity permission to comment on / update incidents
resource playbookSentinelResponderRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, 'playbook-incident-enrichment-notify', 'Microsoft Sentinel Responder')
  scope: resourceGroup()
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '3e150937-b8fe-4cfb-8069-0eaf05ecd056')
    principalId: irPlaybook.outputs.playbookPrincipalId
    principalType: 'ServicePrincipal'
  }
  dependsOn: [
    irPlaybook
  ]
}

// V. Grant Microsoft Sentinel's own service principal permission to run playbooks in this resource group
resource sentinelAutomationContributorRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, 'Microsoft Sentinel Automation Contributor')
  scope: resourceGroup()
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'f4c81013-99ee-4d62-a7ee-b3f1f648599a')
    principalId: sentinelPrincipalId
    principalType: 'ServicePrincipal'
  }
}
