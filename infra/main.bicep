targetScope = 'subscription'

param location string = 'eastus2'
param resourceGroupName string = 'rg-honeypot-soc-lab'
param nsgName string = 'nsg-honeypot-soc'
param vnetName string = 'vnet-honeypot-soc'

// 1. Create the Resource Group container
resource rg 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: resourceGroupName
  location: location
}

// 2. Deploy the core Network Security Group inside the Resource Group
module nsg 'br/public:avm/res/network/network-security-group:0.5.0' = {
  scope: rg
  name: 'nsgDeployment'
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

// 3. Deploy the Isolated Virtual Network (VNET) mapped to our firewall
module vnet 'br/public:avm/res/network/virtual-network:0.5.1' = {
  scope: rg
  name: 'vnetDeployment'
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
