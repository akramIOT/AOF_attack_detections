# Coverage

Which behavior each platform covers. S = Sigma rule (converted in `generated/`), N = hand-written native query or rule, I = indicator feed.

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| Published campaign addresses and domains | Network, DNS, proxy, sign-in, web | S (DNS) | N, I | N, I | I | |
| Coding agent in bypass mode starting attack tools | EDR | S | N | | | |
| Cairn worker and dispatcher command lines | EDR | S | N | | | |
| Cairn task snapshots, provider keys, competition skill | EDR, disk | S | N | | | Y |
| Cairn server listening or exposed | EDR, network | | N | N | | Y |
| Coding-agent CLIs calling model gateways from servers | Proxy | S | N | | | |
| Cairn prompts inside model requests | Decrypted traffic, AI gateway | | | N | | Y |
| Claude Code page reader next to scanning | Web, WAF | S | N | N | | |
| Kali worker toolchain from one source | Web, WAF, proxy | | N | N (ffuf) | | |
| One site probed through rotating proxies | Web, WAF | | N | | | |
| Configuration and backup file theft | Web, WAF | | N | | | |
| WSUS admin and sync API reached from outside | Web | S | N | N | | |
| Uploader shells, skimmer loaders, cron re-injection | EDR, disk, web content | | N | N (loader) | | Y |
| Card data staged, dumped and wiped | Database audit | | N | | | |
| Kerberos enumeration and SMB or WinRM fan-out | Domain controllers | | N | | | |
