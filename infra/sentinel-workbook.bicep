param location string
param logAnalyticsWorkspaceResourceId string

var workbookContent = '''
{
  "version": "Notebook/1.0",
  "items": [
    {
      "type": 1,
      "content": {
        "json": "# Honeypot SOC Dashboard\nLive detections and attacker activity across the Windows RDP, Linux SSH (Cowrie), and web app decoys."
      }
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "SecurityIncident\n| summarize count() by Severity",
        "size": 0,
        "title": "Incidents by Severity",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "visualization": "piechart"
      }
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "SecurityIncident\n| summarize count() by bin(TimeGenerated, 1h)\n| render timechart",
        "size": 0,
        "title": "Incidents Over Time",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "visualization": "timechart"
      }
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "union\n(Cowrie_CL | extend Parsed = parse_json(RawData) | extend SourceIP = tostring(Parsed.src_ip), Source = \"Cowrie SSH\"),\n(WebDecoy_CL | extend Parsed = parse_json(RawData) | extend SourceIP = tostring(Parsed.src_ip), Source = \"Web Decoy\"),\n(SecurityEvent | where EventID == 4625 | extend SourceIP = IpAddress, Source = \"Windows RDP\")\n| where isnotempty(SourceIP)\n| summarize Count = count() by SourceIP, Source\n| top 15 by Count desc",
        "size": 0,
        "title": "Top Attacking IPs (All Decoys)",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "visualization": "table"
      }
    },
    {
      "type": 3,
      "content": {
        "version": "KqlItem/1.0",
        "query": "SecurityAlert\n| mv-expand Tactics\n| summarize count() by tostring(Tactics)\n| render barchart",
        "size": 0,
        "title": "MITRE ATT&CK Tactics Breakdown",
        "queryType": 0,
        "resourceType": "microsoft.operationalinsights/workspaces",
        "visualization": "barchart"
      }
    }
  ],
  "$schema": "https://github.com/Microsoft/Application-Insights-Workbooks/blob/master/schema/workbook.json"
}
'''

resource honeypotWorkbook 'Microsoft.Insights/workbooks@2022-04-01' = {
  name: guid('honeypot-soc-workbook')
  location: location
  kind: 'shared'
  properties: {
    displayName: 'Honeypot SOC Dashboard'
    serializedData: workbookContent
    category: 'sentinel'
    sourceId: logAnalyticsWorkspaceResourceId
    version: '1.0'
  }
}
