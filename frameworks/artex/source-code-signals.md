# Signals in the ARTEX source code

What a blue team can see from ARTEX, read from the code itself: [BaaRai/ARTEX](https://github.com/BaaRai/ARTEX) at commit `f787b5f` (November 2026), and the agent library it builds against, [BaaRai/Norma](https://github.com/BaaRai/Norma) v0.4.11 (`go.mod` replaces `Autumn-27/norma` with it). File references are to those trees. Renamed builds and forks can differ.

**Fragility** says what it takes for an operator to remove the signal: *code* means a rebuild, *config* means an environment variable or a UI setting, *flag* means a command-line option the model or operator can pass.

## How ARTEX behaves on the wire

ARTEX is a planner and a pool of worker agents (three by default, `server/manager.go:338`) that run real tools from one host. It has no beacon. Idle workers poll the local database every 800 ms (`server/engine.go:1167`), busy workers renew their claim in the database every 15 seconds (`db/exploration.go:37`), and the only periodic network traffic is the server-sent events ping to the operator's browser every 20 seconds (`server/server.go:3395`). Nothing reaches a target on a timer.

Inside one worker, tool calls run one at a time. A target sees up to three interleaved, strictly serial streams from one address: a command, a pause while the model thinks, the next command. Each intent runs for at most 20 minutes (`db/db.go:287-289`). When the budget or the task deadline hits, the shell tool is withdrawn and every stream stops at once (`agent/wrapup.go:76-82`, `agent/taskclock.go:38-54`). A technique is tried about three times and then dropped (`stagnationMinRepeats`, `agent/tools.go:45`).

## Target-facing signals

| Signal | Code | Log source | Fragility |
|---|---|---|---|
| WebFetch sends `GET` with `user-agent: norma/0.4`, a 30 second timeout, and refuses `.js`, `.css`, image, font and media URLs, so it reads pages but never their assets | Norma `tool/webfetch.go:177-204, 232-243` | Web, WAF, proxy | Code. `ARTEX_TARGET_USER_AGENT` does not replace it (`egress/egress.go:459`) |
| After a proxy-type error WebFetch retries the same URL once directly, past the recording proxy | Norma `tool/webfetch.go:238-249` | Web | Code |
| The enrichment engine sends one `GET` to each newly recorded site: `Go-http-client/1.1`, `Accept-Encoding: gzip`, `Connection: close`, redirects not followed, certificate checks off, 12 second timeout, at most once per 5 minutes per asset | `enrich/enrich.go:58-59, 104-128, 247` | Web, WAF | Config: under a noise profile `ARTEX_TARGET_USER_AGENT` replaces the Go default |
| api-recon skill scripts send `Mozilla/5.0 (spa-api-recon)` and `Mozilla/5.0 (spa-api-recon spider)` | `skills/api-recon/scripts/harvest_static.py:23`, `spider_mpa.py:22` | Web, WAF | Code (skill files are editable on disk) |
| Proxied tools keep their user agent but lose their TLS fingerprint: the recording proxy (go-mitmproxy) rebuilds every ClientHello with Go `crypto/tls`, so curl, sqlmap, nuclei and headless Chromium all present Go's JA3/JA4, with no GREASE and no session resumption. HTTP/1.1 header names are canonicalized and sent as Host, User-Agent, Content-Length, then the rest alphabetically | `traffic/` with go-mitmproxy v1.9.2 `attacker.go` | Zeek `ssl`, TLS-aware WAF or load balancer | Config: only when traffic capture is off. If interception fails, the host is tunneled untouched for a minute (`traffic/traffic.go:629`), so one source shows mixed fingerprints |
| Pinned toolchain from the Dockerfile: sqlmap 1.9.9, ffuf v2.3.0, nuclei v3.11.1, httpx v1.12.0, katana v1.8.0, dalfox v3.2.4, bbot 3.0.2, nmap, Playwright 1.64.1 with headless Chromium, and bookworm's curl 7.88.1 and Wget 1.21.3 | `Dockerfile:71-220` | Web, WAF, proxy | Flag for each scanner's user agent; base image for curl and Wget |
| Noise profiles pace requests per host at 2, 5 or 20 a second, with jitter of at most min(jitter/rate, 250 ms), so gaps settle at 500 to 750 ms, 200 to 240 ms or 50 to 55 ms. The agents also get matching scanner flags such as nmap `-T2 --max-rate 2 --max-retries 2` and sqlmap `--delay=0.5 --threads=1` | `egress/egress.go:50-57`, `agent/noise_profile.go:56-67` | Web, WAF | Config: off by default |
| On 429 or 503 the governor honors `Retry-After` and pauses the whole host. Only bodiless `GET`, `HEAD` and `OPTIONS` are retried | `egress/egress.go` | Web | Config |
| Seeded safety rules block HTTP `DELETE` from curl, wget, requests, httpx, aiohttp and axios, and paths such as `/delete`, `/remove`, `/purge` and `/reset-all`, so ARTEX sources rarely delete what they create | `db/db.go:437-720`, `deleteEndpointPathPattern` at `:688` | Web | Config: rules can be deleted in the UI |
| Workers register their own accounts on the target, keep the credentials per task and reuse them across workers. Captcha, email codes and MFA go to a person through `ask_operator`, which pauses the agent until someone answers | `agent/worker.go:285-290`, `agent/tools_creds.go:92-117` | Web, Entra ID sign-in logs | Prompt (UI-editable) |
| Interactive shells driven through `shell_send` get Enter as a carriage return and multi-line input wrapped in `ESC[200~` and `ESC[201~`. No completion marker is echoed | Norma `tool/shell_tools.go:150, 225-245`, `tool/shell_session.go:24-35` | Syslog, auditd TTY, EDR | Code |
| Seeded asset blocklist: `.gov`, `.gov.cn`, `.edu`, `.edu.cn` | `db/db.go:375-397` | | Config |

## Signals on the host that runs ARTEX

| Signal | Code | Log source | Fragility |
|---|---|---|---|
| UI, API and SSE on 8787; unauthenticated recording proxy on 8788. Loopback by default, every interface in the Docker image | `cmd/artex/main.go:101-103`, `Dockerfile:243-245` | EDR network events, internal scans | Flag |
| Agent `bash` is a symlink to the artex binary in a temporary `artex-exec-` folder, run as uid/gid 10001, with `ARTEX_EXEC_BASH`, `ARTEX_EXEC_UID`, `ARTEX_EXEC_GID` and `ARTEX_EXEC_HOME` set | `server/execpriv.go:25`, `server/execpriv_unix.go:539-575` | EDR process events | Code |
| MCP servers start as `artex __artex-exec-drop <uid> <gid> -- <cmd>` | `server/execpriv_unix.go:539-575` | EDR process events | Code |
| Agent shells carry `HTTP_PROXY=http://artex-pace:artex-pace@127.0.0.1:8788`, sent as `Proxy-Authorization: Basic YXJ0ZXgtcGFjZTphcnRleC1wYWNl` | `egress/pace.go:20`, `agent/worker.go:229-252` | EDR, loopback capture | Code |
| Enrichment resolves every new domain with UDP/53 straight to 1.1.1.1, 1.0.0.1, 8.8.8.8, 8.8.4.4, 9.9.9.9, 149.112.112.112, 208.67.222.222 and 208.67.220.220, past the local resolver | `enrich/enrich.go:71-76`, dnsx `DefaultResolvers` | EDR network events, firewall | Code |
| Recording proxy CA `CN=mitmproxy, O=mitmproxy`, RSA 2048, valid from 48 hours before creation for three years. Every leaf certificate reuses the CA public key. Files under `<data>/traffic/_ca/` | go-mitmproxy `cert/self_sign_ca.go:44-74, 333-365` | Certificate inventory, Zeek `x509` on internal traffic | Code (shared by every go-mitmproxy) |
| Opt-in update check: `GET https://api.github.com/repos/BaaRai/ARTEX/releases/latest` with `User-Agent: artex-update-check`, at most once a day | `server/update_check.go:18-71` | TLS-inspecting proxy | Config |
| Keenable search sends `X-Keenable-Title: ARTEX` to api.keenable.ai | `agent/worker.go:46` | TLS-inspecting proxy | Config |
| Finding alerts go straight to DingTalk, Feishu, WeCom, Telegram, a webhook or SMTP, never through the proxy | `notify/http.go:111-125` | Proxy, firewall | Config |
| Task archives to S3 under `artex/tasks/task-<task>-<archive>-<sha256>.tar.zst` | `archivestore/s3.go:76-79` | CloudTrail data events | Config |
| Browser extension `ARTEX Traffic Capture` posts to `/api/traffic/ingest` in batches of ten | `extension/manifest.json`, `extension/background.js:10-11, 148-151` | Browser extension inventory, proxy | Code |
| Console: title `ARTEX — Autonomous Penetration Testing Console`, favicon mmh3 `-576220750`, `/icon.png` mmh3 `-1898746557`, `GET /api/health` returns `{"ok":true}` without a token, the login username is always `ARTEX`, `/api` responses send `Access-Control-Allow-Origin: *` and no `Server` header | `web/src/config/app-config.ts:12-13`, `server/auth.go:287-293`, `server/server.go:1099-1103, 4525` | Internet and internal scans | Code |

## Signals inside model requests

Where outbound model traffic is inspected (an AI gateway, a TLS-inspecting proxy, DLP), ARTEX requests carry fixed strings that the UI cannot edit away:

- Tool function names such as `record_fact`, `list_findings`, `insert_assets`, `save_task_credential`, `search_all_worker_traces`, `graph_overview`, `add_intent`, `prove_goal`, `steer_work` and `shell_send` (`agent/tools_insert.go:681`, `agent/tools.go:2321`, `db/db.go:314-321`).
- The data envelope `[[ARTEX_DATA nonce=<32 hex> field=<name>]]` and its neutralizer `artex-data-marker-removed` (`agent/data_envelope.go:21-56`).
- The tool output frame `<<<UNTRUSTED_OUTPUT <nonce>>>>>` and the headings `Untrusted content handling (prompt-injection defense):` and `Untrusted data rule (code-owned):` (`agent/untrusted_prompt.go:11, 32`).
- Target account passwords in clear text in the worker's first message (`agent/tools_creds.go:92-117`).
- MCP `clientInfo` `{"name":"artex","version":"0.2"}` (`mcphttp/client.go`).

Model calls use Go's default user agent unless a profile sets one, and no `anthropic-beta` or SDK headers (`agent/provider.go`).

## Where the branded strings come from

The indicators that name ARTEX, such as `artex-pentest/1.0`, `X-ARTX-KEY` or the folder `C:\ProgramData\artx5v\`, come from reporting on ARTEX intrusions in the wild, not from the public code. None of them appears in the BaaRai/ARTEX tree or its history. The reports themselves explain why: Wiz saw a new user agent assigned to each password spray burst and more than 15 strings across victims, and Eye Security notes that "the agents label their own work". The worker agents write their own curl commands, web shells and test files, and the model often names them after the tool. That makes these strings real, worth hunting and easy to lose: the next run, model or operator can pick different ones.

Every one of them stays in `iocs/indicators.csv` with the publication it first appeared in:

| Strings | First published by | Context |
|---|---|---|
| `artex-readonly/1.0`, `artex-pentest/1.0`, `artex-audit/1.0`, `artex-verify/1.0`, `artex-spawn/1`, `ARTEX-worker/1.0`, `artex-i21861-canary`, `Mozilla/5.0 ARTeX`, `Mozilla/5.0 (Windows NT 10.0; Win64; x64) ARTeX-authorized-pentest`, `Mozilla/5.0 (X11; Linux x86_64) artex-verify/1.0` | Datadog Security Labs, "On the hunt for ARTEX: understanding agentic attacks in AWS environments", November 9, 2026 | IOC table from AWS intrusions. `Mozilla/5.0 ARTeX` was also on Cognito SignUp calls from 154.64.252.77 on October 26 and 27 |
| `zzz_nonexistent_abc.txt`, `Notexist-xyz` | Datadog Security Labs, November 9, 2026 | Placeholder S3 object names requested before guessing |
| `/zzz-nonexistent-xyz123` | Wiz Research, "ARTEX in the Wild: Storm-0940 Expands Targeting of IT and Software Vendors", October 22, 2026 | Requested before every fuzzing run to learn what not found looks like |
| `ReconProbe/1.0` | Wiz Research, October 22, 2026 | Named in the text as a self-describing user agent, not in the IOC table |
| `norma/0.4` | Wiz Research, October 22, 2026 | In the IOC table. It is also the hard-coded WebFetch default in the agent library |
| `azure-toolkit/1.0` | Microsoft Threat Intelligence, "AI-driven, large-scale nation-state campaign using ARTEX enables supply chain compromise", October 21, 2026 | Storm-0940 sign-ins and Graph activity through compromised ConnectWise applications |
| `C:\ProgramData\artx5v\`, `art18-` | CrowdStrike, "VAPOR PANDA Uses AI-Driven ARTEX to Grow Global Espionage Campaign", October 29, 2026 | Host and command-line markers in VAPOR PANDA intrusions |
| `artex-probe-<five digits>`, `ArtexProbe` | Google Threat Intelligence Group, "ARTEX and Friends: Enter Agentic Offensive Frameworks", October 31, 2026 | Files and accounts the agents created while probing access |
| `X-ARTX-KEY`, `### ARTX-AGENT`, `ARTEX_WRITE_PROBE`, `ARTX_PERSIST_OK`, `artex_control_marker_zz9q`, `ARTEX-PROBE-0001`, `Mozilla/5.0 (compatible; ArtExVerify/1.0)` | Eye Security, "How we defended against an AI-driven attack", November 12, 2026 | Web shell header and response marker, data markers and a user agent from one intrusion. Later compiled in MalwareMustDie MMD-072-2026 |
| `artex-enrich/1.0`, `scopeweaver`, `Mozilla/5.0 (spa-api-recon)` | ExtraHop, "ARTEX: Inside an Agentic Attack Framework", November 15, 2026 | A renamed ARTEX build run in a lab. `spa-api-recon` is also in the public code's API recon skill |

The public code and these reports describe two layers of the same tool. The code fixes what every run does, which is what the hunts in this repository's 1.1.0 release look for. The reports show what the agents chose to do in particular intrusions, which the 1.0.0 indicators cover. Hunt for both.

## What the code does not contain

The Go code and the agent prompts have no Entra ID, Microsoft Graph, Okta or Azure tooling, no password spraying, Kerberos or lateral movement module, and no persistence step. Those behaviors come from what the operator and the model choose to run with the tools in the image. Hunts that depend on them stay valid, but their signals come from the operator, not from ARTEX itself.
