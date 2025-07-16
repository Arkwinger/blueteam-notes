# check for Sysmon installation
sc query sysmon

# view config file location
reg query HKLM\SYSTEM\CurrentControlSet\Services\Sysmon

# list recent Sysmon logs
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | Select-Object -First 10

# monitor process creation (Event ID 1)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1}

# look for command line execution with suspicious keywords
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | 
Where-Object { $_.Message -match "powershell|cmd|EncodedCommand" }

# find unsigned binaries
Get-WinEvent -FilterXPath "*[System/EventID=1 and EventData[Data[@Name='Signed']='false']]" -LogName Microsoft-Windows-Sysmon/Operational

# check for network connections (Event ID 3)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=3}

# detect image load abuse (Event ID 7)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=7}

# search for rare parent-child relationships
grep "ParentImage" sysmon.log | grep "WINWORD.exe"


grep "Timestamp" sysmon.log | grep "2023-01-18 02"
EventID 12
