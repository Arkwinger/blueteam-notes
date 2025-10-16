# list scheduled cron jobs
```
cat /etc/crontab
ls /etc/cron.d/
```
# dump local DNS cache
```
ipconfig /displaydns
```
# view current firewall rules
```
iptables -L
ufw status verbose
```
# check active network connections
```
netstat -antp
ss -tulwn
```
# get a list of system users
```
cat /etc/passwd | cut -d ":" -f1
```
# find processes listening on ports
```
lsof -i -P -n | grep LISTEN
```
# show login activity
```
last -a
who -a
```
# search bash history for file transfers
```
grep -Ei "scp|rsync|wget|curl" ~/.bash_history
```
# review sudo access attempts
```
grep "sudo" /var/log/auth.log
```
# grab recent kernel messages
```
dmesg | tail
```
# simple memory dump (Windows)
```
winpmem.exe -o memory.raw
```
# review boot logs
```
journalctl -b
```
# check mounted filesystems
```
df -h
mount
```
# see local ARP table
```
arp -a
```

