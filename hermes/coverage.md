# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| Hermes with approvals off (yolo) | EDR | S | N | | | |
| godmode jailbreak skill and prefill | EDR, disk | S | N | | | Y |
| Replaced persona (Red Team Operator, GH0ST) and loot folder | EDR, disk | S | N | | | Y |
| Attack tools and file servers under Hermes | EDR | | N | | | |
| Telegram control, Hermes WebUI and dashboard | EDR, network | | N | N | | |
| Hermes results served from web servers | Web, proxy | | N | N | | |
| Carbonato Docker API abuse, host escape and persistence | EDR, network, firewall | S | N | N | | Y |
| Campaign addresses, domains and Hades/VShell hashes | Sign-in, proxy, firewall, DNS, EDR | | N | N (generated) | I | |
| Model traffic from the Hermes host | Proxy, TLS | behaviors | behaviors | | behaviors | |
