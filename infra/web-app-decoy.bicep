param location string = 'eastus'
param adminUsername string = 'azureuser'
param dcrId string

@secure()
param sshPublicKey string

var vmName = 'vm-web-decoy'
var cloudInitContent = loadTextContent('cloud-init-webdecoy.yaml')

module network './web-decoy-network.bicep' = {
  name: 'webDecoyNetworkDeployment-${uniqueString(deployment().name)}'
  params: {
    location: location
  }
}

resource publicIp 'Microsoft.Network/publicIPAddresses@2023-11-01' = {
  name: '${vmName}-pip'
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}

resource nic 'Microsoft.Network/networkInterfaces@2023-11-01' = {
  name: '${vmName}-nic'
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet: {
            id: network.outputs.subnetId
          }
          privateIPAllocationMethod: 'Dynamic'
          publicIPAddress: {
            id: publicIp.id
          }
        }
      }
    ]
  }
}

resource
