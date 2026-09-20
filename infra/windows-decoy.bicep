targetScope = 'resourceGroup'

param location string
param subnetId string // Expecting a single string resource ID string
param vmName string = 'vm-win-decoy'
param adminUsername string = 'azureuser'

@secure()
param adminPassword string

// 1. Create a Public IP address so internet threat actors can reach our trap
resource publicIP 'Microsoft.Network/publicIPAddresses@2023-11-01' = {
  name: '${vmName}-pip'
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
    dnsSettings: {
      domainNameLabel: 'honeypot-win-${uniqueString(resourceGroup().id)}'
    }
  }
}

// 2. Create the Network Interface Card (NIC) connecting the VM to our isolated subnet
resource nic 'Microsoft.Network/networkInterfaces@2023-11-01' = {
  name: '${vmName}-nic'
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          publicIPAddress: {
            id: publicIP.id
          }
          subnet: {
            id: subnetId // Properly maps the resolved subnet ID string
          }
        }
      }
    ]
  }
}

// 3. Provision the Windows Server VM instance
resource vm 'Microsoft.Compute/virtualMachines@2024-03-01' = {
  name: vmName
  location: location
  properties: {
    hardwareProfile: {
      vmSize: 'Standard_D2s_v7'  // Standard_d2s had no capacity in eastus2 for this subscription
    }
    osProfile: {
      computerName: vmName
      adminUsername: adminUsername
      adminPassword: adminPassword
    }
    storageProfile: {
      imageReference: {
        publisher: 'MicrosoftWindowsServer'
        offer: 'WindowsServer'
        sku: '2022-datacenter-g2'
        version: 'latest'
      }
      osDisk: {
        createOption: 'FromImage'
        managedDisk: {
          storageAccountType: 'Standard_LRS'
        }
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: nic.id
        }
      ]
    }
  }
}

