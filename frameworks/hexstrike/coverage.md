# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| HexStrike user agents and generated exploit user agent | Web, WAF, proxy, sign-in, CloudTrail | S | N | N | I | Y |
| `<hexstrikeXSSTest123>` probe | Web, WAF | S | N | N | | |
| HexStrike server and its child tools | EDR | S | N | | | Y |
| `which` burst on /health | EDR | | N | | | |
| Python listening on 8888, /health and /api/command | EDR, network | | N | N | | |
| AI assistant wired to a HexStrike server | EDR, proxy, disk | S | N | N | | Y |
| HexStrike files in /tmp | EDR, disk | | N | | | |
