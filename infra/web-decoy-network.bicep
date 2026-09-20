param location string = 'eastus'

resource webNsg 'Microsoft.Network/networkSecurityGroups@2023-11-01' = {
  name: 'nsg-web-decoy'
  location: location
  properties: {
    securityRules: [
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
    ]
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
