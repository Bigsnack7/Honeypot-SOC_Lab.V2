targetScope = 'resourceGroup'

param location string
param subnetId string // Expecting a single string resource ID string
param vmName string = 'vm-win-decoy'
param adminUsername string = 'azureuser'
param dcrId string = ''

@secure()
param adminPassword string

var sysmonScriptContent = loadTextContent('install-sysmon.ps1')

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
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    hardwareProfile: {
      vmSize: 'Standard_D2s_v7' // Standard_d2s had no capacity in eastus2 for this subscription
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

// 4. Install Sysmon via the Custom Script Extension (script embedded inline, no external fetch needed)
resource sysmonInstall 'Microsoft.Compute/virtualMachines/extensions@2023-09-01' = {
  parent: vm
  name: 'InstallSysmon'
  location: location
  properties: {
    publisher: 'Microsoft.Compute'
    type: 'CustomScriptExtension'
    typeHandlerVersion: '1.10'
    autoUpgradeMinorVersion: true
    protectedSettings: {
      commandToExecute: 'powershell -ExecutionPolicy Unrestricted -Command "$content = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(\'${base64(sysmonScriptContent)}\')); Set-Content -Path C:\\install-sysmon.ps1 -Value $content; powershell -ExecutionPolicy Unrestricted -File C:\\install-sysmon.ps1"'
    }
  }
}

// 5. Install Azure Monitor Agent (Windows variant)
resource amaExtension 'Microsoft.Compute/virtualMachines/extensions@2023-09-01' = {
  parent: vm
  name: 'AzureMonitorWindowsAgent'
  location: location
  properties: {
    publisher: 'Microsoft.Azure.Monitor'
    type: 'AzureMonitorWindowsAgent'
    typeHandlerVersion: '1.16'
    autoUpgradeMinorVersion: true
  }
  dependsOn: [
    sysmonInstall
  ]
}

// 6. Associate the DCR (built in Stage D) with this VM — skipped until dcrId is provided
resource dcrAssociation 'Microsoft.Insights/dataCollectionRuleAssociations@2023-03-11' = if (!empty(dcrId)) {
  name: 'dcr-association-windecoy'
  scope: vm
  properties: {
    dataCollectionRuleId: dcrId
  }
}



