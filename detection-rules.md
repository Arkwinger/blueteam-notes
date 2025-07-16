encoded-powershell-command.md

  title: Encoded PowerShell Command
description: Detects suspicious use of PowerShell with -EncodedCommand flag
author: yourname
status: experimental
date: 2025-07-17
logsource:
  product: windows
  service: powershell
detection:
  selection:
    CommandLine|contains: "EncodedCommand"
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1059.001
  - powershell
  - encoded

    CommandLine CONTAINS "EncodedCommand"
CommandLine CONTAINS "IEX"
Image CONTAINS "powershell.exe"
