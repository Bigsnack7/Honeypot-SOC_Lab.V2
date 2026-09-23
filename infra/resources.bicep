targetScope = 'resourceGroup'

param location string
param nsgName string
param vnetName string
param logAnalyticsWorkspaceName string

@secure()
param adminPassword string

@secure()
param sshPublicKey string

// A. Deploy the Network Security Group via Azure Verified Modules (AVM)
module nsg 'br/public:avm/res/network/network-security-group:0.5.0' = {
  name: 'nsgDeployment-${uniqueString(deployment().name)}'
  params: {
    name: nsgName
    location: location
    securityRules: [
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
        name: 'Allow-Outbound-Internet-Setup'
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
    ]
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
    enabled: false
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
    enabled: false
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
    enabled: false
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
