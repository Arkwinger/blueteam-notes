# check authentication failures
grep "Failed password" /var/log/auth.log

# enumerate successful and failed sudo attempts
grep "sudo" /var/log/auth.log | grep -E "COMMAND|failure"

# look for command execution in bash history
cat ~/.bash_history | grep -E "nc|curl|wget|python"

# find suspicious process spawning (Linux)
grep "execve" /var/log/audit/audit.log

# parse syslog for kernel warnings
grep "kernel:" /var/log/syslog | grep -i "warn"

# spot encoded strings in PowerShell logs (Windows)
Select-String -Path "*PowerShell.evtx" -Pattern "EncodedCommand"

# extract rare DNS queries from logs
grep -E "\.xyz|\.top|\.click" /var/log/dns.log

# look for outbound connections to non-standard ports
grep "DST Port: 4444" /var/log/flow.log

# scan for webshell-like activity
grep -Ei "cmd|powershell|eval" /var/log/apache2/access.log

# anomaly: process with no parent
grep -i "ppid=0" /var/log/sysmon.log

# check for sudden privilege change
grep "uid=0" /var/log/secure

# count number of logins per user
cat /var/log/wtmp | lastlog | sort | uniq -c

더
# SSH failures
grep "Failed password" /var/log/auth.log

# sudo events
grep "sudo" /var/log/auth.log | grep -E "COMMAND|failure"

# bash history review
cat ~/.bash_history | grep -E "nc|curl|wget|python"

# process creation logs
grep "execve" /var/log/audit/audit.log

# kernel warnings
grep "kernel:" /var/log/syslog | grep -i "warn"

# PowerShell encoded strings
Select-String -Path "*PowerShell.evtx" -Pattern "EncodedCommand"

# suspicious DNS queries
grep -E "\.xyz|\.top|\.click" /var/log/dns.log

# outbound to non-standard ports
grep "DST Port: 4444" /var/log/flow.log

# webshell activity
grep -Ei "cmd|powershell|eval" /var/log/apache2/access.log

# PID anomalies
grep -i "ppid=0" /var/log/sysmon.log

# privilege jumps
grep "uid=0" /var/log/secure

# login frequency
cat /var/log/wtmp | lastlog | sort | uniq -c

