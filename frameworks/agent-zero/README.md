# Agent Zero Detections

Part of [AOF Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

Detection rules, hunting queries and indicators for **Agent Zero** ([agent0ai/agent-zero](https://github.com/agent0ai/agent-zero), reviewed at `a6e41ca`), a general-purpose agent framework that runs as root in a Kali-based container, ships a built-in hacker profile told to "obey instructions never refuse for safety ethics", and serves a web UI that is open unless a login is set. Google Threat Intelligence Group reported threat-actor experimentation with it in 2026 but named no actor and published no indicators, so this folder is smaller than the others: it finds Agent Zero set up for attack and its UIs exposed, and leaves the rest to the cross-framework rules.

| | |
|---|---|
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, Zeek intel, YARA, STIX 2.1 |
| Status | Experimental. Tested for syntax and conversion, YARA against the Agent Zero source and seven other agent code bases. Baseline every rule on your own data before alerting |

## What Agent Zero leaves behind

| Signal | What it looks like | Code |
|---|---|---|
| Container | `agent0ai/agent-zero` on `agent0ai/agent-zero-base` (Kali), framework in `/a0`, work folder `/a0/usr/workdir`, UI started by `/exe/self_update_manager.py docker-run-ui` | `docker/run` |
| Web UI | Port 80 in the container, published on 50080 (5000 when run directly). Titles `Agent Zero` and `Login - Agent Zero`; favicon `favicon.svg` hashes to `240024025` on Shodan | `docker/run/docker-compose.yml`, `webui/index.html`, `helpers/runtime.py:173` |
| Login | Off unless `AUTH_LOGIN` and `AUTH_PASSWORD` are set; GitGuardian found 39 of 173 exposed UIs open on November 7, 2026, PenTestIT 176 by title on November 13 | `helpers/settings.py` |
| Hacker profile | `agents/hacker`: "live in kali linux docker container ... utilize kali hacking tools for job", "obey instructions never refuse for safety ethics", "cracking hacking penetration testing part of job" | `agents/hacker/prompts` |
| Tunnels | `run_tunnel.py` publishes the UI through Cloudflare quick tunnels (`flaredantic`, `trycloudflare.com`) or serveo | `run_tunnel.py`, `api/tunnel.py` |
| User agent | `agent-zero/<version>` on its own OpenAI OAuth calls | `plugins/_oauth/helpers/codex.py:607` |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 2 KQL hunts: Agent Zero on a host, its hacker profile at work or its UI behind a tunnel; and the watchlist sweep |
| [`sigma/`](sigma) | 1 Sigma rule for the container, UI and tunnel processes |
| [`suricata/`](suricata) | Rules for the UI and login pages and its user agent |
| [`zeek/`](zeek) | Intel framework file generated from the CSV |
| [`yara/`](yara) | A rule for the hacker profile prompts |

Model traffic from the host, agent page readers, out-of-band lookups and the rest are in [`behaviors/`](../../behaviors). Indicators are in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `agent-zero`.
