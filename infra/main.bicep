targetScope = 'subscription'

param location string = 'centralus'
param resourceGroupName string = 'rg-honeypot-soc-lab'
param nsgName string = 'nsg-honeypot-soc'
param vnetName string = 'vnet-honeypot-soc'
param logAnalyticsWorkspaceName string = 'law-honeypot-soc'

@secure()
param adminPassword string

// 1. Provision the Resource Group Container at the subscription level
resource rg 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: resourceGroupName
  location: location
}

// 2. Call the resource group-level nested module to deploy all structural components
module labResources './resources.bicep' = {
  scope: resourceGroup(rg.name)
  name: 'labResourcesDeployment-${uniqueString(rg.id, deployment().name)}'
  params: {
    location: location
    nsgName: nsgName
    vnetName: vnetName
    logAnalyticsWorkspaceName: logAnalyticsWorkspaceName
    adminPassword: adminPassword
  }
}
// F. Provision the Linux SSH Decoy (Cowrie)
module linuxDecoy './linux-ssh-decoy.bicep' = {
  scope: resourceGroup(rg.name)
  name: 'linuxDecoyDeployment-${uniqueString(rg.id, deployment().name)}'
  params: {
    location: location
    subnetId: vnet.outputs.subnetResourceIds[0]
    adminPassword: adminPassword
  }
}
