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

// 3. Deploy the Sentinel-native analytics rules once the workspace exists
module cowrieBruteForceRule './infra/analytics-rule-cowrie-bruteforce.bicep' = {
  scope: resourceGroup(rg.name)
  name: 'cowrieBruteForceRuleDeployment-${uniqueString(rg.id, deployment().name)}'
  params: {
    logAnalyticsWorkspaceName: logAnalyticsWorkspaceName
  }
  dependsOn: [
    labResources
  ]
}

module webDecoyScanningRule './infra/analytics-rule-webdecoy-scanning.bicep' = {
  scope: resourceGroup(rg.name)
  name: 'webDecoyScanningRuleDeployment-${uniqueString(rg.id, deployment().name)}'
  params: {
    logAnalyticsWorkspaceName: logAnalyticsWorkspaceName
  }
  dependsOn: [
    labResources
  ]
}

module windowsBruteForceRule './infra/analytics-rule-windows-bruteforce.bicep' = {
  scope: resourceGroup(rg.name)
  name: 'windowsBruteForceRuleDeployment-${uniqueString(rg.id, deployment().name)}'
  params: {
    logAnalyticsWorkspaceName: logAnalyticsWorkspaceName
  }
  dependsOn: [
    labResources
  ]
}
