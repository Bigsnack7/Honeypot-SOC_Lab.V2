# Download Sysmon
$sysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
$sysmonZip = "C:\Sysmon.zip"
$sysmonDir = "C:\Sysmon"

Invoke-WebRequest -Uri $sysmonUrl -OutFile $sysmonZip
Expand-Archive -Path $sysmonZip -DestinationPath $sysmonDir -Force

# Download a well-known community-maintained Sysmon config
$configUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
$configPath = "C:\Sysmon\sysmonconfig.xml"

Invoke-WebRequest -Uri $configUrl -OutFile $configPath

# Install Sysmon with the config (64-bit assumed for D-series VMs)
Start-Process -FilePath "C:\Sysmon\Sysmon64.exe" -ArgumentList "-accepteula -i C:\Sysmon\sysmonconfig.xml" -Wait -NoNewWindow
