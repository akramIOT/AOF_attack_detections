# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| Webshell manager user agent | Web, WAF, proxy | S | N | N | I | Y |
| Webshell OS probe `echo :OSPROBE_%OS%:END` | Web, EDR, network | S | N | N | | Y |
| Console user agents (`CyberStrikeAI/<version>`) | Proxy | S | N | N | I | Y |
| Console certificate `CN=CyberStrikeAI` | Network, internet scans | | | N | | |
| Implant headers, check-in paths and default user agent | Proxy, network | S | N | N | | Y |
| Implant 5-second interval with no jitter | EDR | | N | | | |
| TCP implant magic `CSB1` | Network | | | N | | |
| curl one-liner implant | EDR, disk | S | N | N | | Y |
| Persistence: SystemUpdate Run value and task | EDR, registry | S | N | | | |
| Persistence: @reboot cron and `.bashrc # cs` | EDR, disk | S | N | | | Y |
| Persistence: com.apple.systemupdate LaunchAgent | EDR, disk | S | N | | | Y |
| Compiled implant (build path, headers, persistence strings) | Disk, memory | | | | | Y |
| File names and hashes from real attacks | EDR | | N | | I | |
| Console host: binary, implant builds, listeners, data files | EDR, proxy | | N | | | Y |
| Reported servers and C2 addresses | Sign-in, proxy, firewall, DNS, CloudTrail | | N | N (generated) | I | |
| AWS credentials used at machine speed | CloudTrail | | N (behaviors) | | | |
