#### look for suspicious PowerShell activity
`grep -i "powershell" /var/log/sysmon.log | grep -E "EncodedCommand|IEX"`

### find rare parent-child process combos
`grep "WINWORD.exe -> cmd.exe" /var/log/command-trails.log`

### hunt users with odd login times
`last -a | grep -v "tty" | grep "03:"`

### look for outbound to uncommon ports
```grep "DST Port: 4444" /var/log/network-flow.log```

### long command strings that might be obfuscated
`grep -E '.{100,}' /var/log/bash.log`

### check if RDP was enabled unexpectedly
`reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections`

###  lateral movement trace: WMI usage
`grep "wmic" /var/log/process-histories.log`

### uncommon DNS queries
`grep -E ".*\.xyz|.*\.click" /var/log/dns.log`

### hunt for script downloads
`grep -Ei "curl|wget|Invoke-WebRequest" /var/log/web-activity.log`

### potential persistence via scheduled tasks
`schtasks /query /fo LIST /v | grep "cmd.exe"`
