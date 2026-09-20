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

// E. Provision the Windows Decoy Virtual Machine
module windowsDecoy './windows-decoy.bicep' = {
  name: 'windowsDecoyDeployment-${uniqueString(deployment().name)}'
  params: {
    location: location
    subnetId: vnet.outputs.subnetResourceIds[0]
    adminPassword: adminPassword
  }
}

// F. Provision the Linux SSH Decoy (Cowrie)
module linuxDecoy './linux-ssh-decoy.bicep' = {
  name: 'linuxDecoyDeployment-${uniqueString(deployment().name)}'
  params: {
    location: location
    subnetId: vnet.outputs.subnetResourceIds[0]
    sshPublicKey: sshPublicKey
  }
}
