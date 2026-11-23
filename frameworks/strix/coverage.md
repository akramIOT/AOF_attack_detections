# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| Strix CLI, install or sandbox on a host | EDR | S | N | | | Y |
| Strix run folders and reports | EDR, disk | | N | | | Y |
| Strix telemetry (Scarf, PostHog) | DNS, TLS, proxy, EDR | S | N | N | I | Y |
| Results viewer page and agent steering API | Network, proxy | S | N | N | | |
| Gambit campaign addresses and domains (shared with Cairn) | Sign-in, proxy, firewall, DNS | | N | N (generated) | I | |
| Model traffic from the Strix host | Proxy, TLS | behaviors | behaviors | | behaviors | |
| Out-of-band lookups from your servers | DNS, EDR | behaviors | behaviors | behaviors | behaviors | |
| Kali tools and page reads against your sites | Web, WAF, proxy | behaviors | behaviors | behaviors | behaviors | |
