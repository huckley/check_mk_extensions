# Windows PKI check**mk** 2.2 Plugin

This repository contains [check**mk**](https://checkmk.com/) plugin to monitor ssl Certificates in a Windows PKI

### the monitored host needs Download and install PowerShell PKI module from the PowerShell Gallery using PowerShell
```PowerShell
Install-Module -Name PSPKI
```
see also https://github.com/PKISolutions/PSPKI

### local checkmk agent config
it is recommended that you ad this snippet to the plugin secrtion in C:\ProgramData\checkmk\agent\check_mk.user.yml
```C:\ProgramData\checkmk\agent\check_mk.user.yml
    execution:
        - pattern: $CUSTOM_PLUGINS_PATH$\windowspki.ps1
          async: yes
          timeout: 300
          cache_age: 3600
          retry_count: 2
```
### maybe you have to adjust the filters in the powershell script
I decide to not watch every template type, so I add some filter in the powershell script.
I know it is ugly, so any suggestions are welcome.

### don't forget to restart the checkmk service after that

### other implementaions
https://blog.zabbix.com/json-is-your-friend-certificate-monitoring-on-microsoft-ca-server/20697/