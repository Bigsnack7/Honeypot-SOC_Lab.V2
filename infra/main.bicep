targetScope = 'subscription'

param location string = 'centralus'
param resourceGroupName string = 'rg-honeypot-soc-lab'
param nsgName string = 'nsg-honeypot-soc'
param vnetName string = 'vnet-honeypot-soc'
param logAnalyticsWorkspaceName string = 'law-honeypot-soc'

@description('Email address to receive detection alert notifications.')
param alertEmail string

@description('Set to true only for the first deployment (or a full VM rebuild) so decoy VMs can reach package mirrors during cloud-init. Redeploy with false afterward.')
param allowProvisioningEgress bool = false

@secure()
param adminPassword string

@secure()
param sshPublicKey string

// 1. Provision the Resource Group Container at the subscription level
resource rg 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: resourceGroupName
  location: location
}

// 2. Call the resource group-level nested module to deploy all structural components
// (this now includes the Sentinel-native analytics rules directly inside resources.bicep)
module labResources './resources.bicep' = {
  scope: resourceGroup(rg.name)
  name: 'labResourcesDeployment-${uniqueString(rg.id, deployment().name)}'
  params: {
    location: location
    nsgName: nsgName
    vnetName: vnetName
    logAnalyticsWorkspaceName: logAnalyticsWorkspaceName
    alertEmail: alertEmail
    allowProvisioningEgress: allowProvisioningEgress
    adminPassword: adminPassword
    sshPublicKey: sshPublicKey
  }
}
