param location string = 'eastus'

@description('Set to true only during initial provisioning to allow package installs. Redeploy with false once cloud-init has completed.')
param allowProvisioningEgress bool = false

resource webNsg 'Microsoft.Network/networkSecurityGroups@2023-11-01' = {
  name: 'nsg-web-decoy'
  location: location
  properties: {
    securityRules: concat([
      {
        name: 'Allow-Inbound-HTTP'
        properties: {
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '80'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 1001
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

resource webVnet 'Microsoft.Network/virtualNetworks@2023-11-01' = {
  name: 'vnet-web-decoy'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.1.0.0/16'
      ]
    }
    subnets: [
      {
        name: 'subnet-web-decoy'
        properties: {
          addressPrefix: '10.1.1.0/24'
          networkSecurityGroup: {
            id: webNsg.id
          }
        }
      }
    ]
  }
}

output subnetId string = webVnet.properties.subnets[0].id
