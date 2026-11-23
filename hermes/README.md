# Hermes Agent Detections

Part of [AOF Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

Detection rules, hunting queries and indicators for **Hermes Agent** used as an attack console. Hermes ([NousResearch/hermes-agent](https://github.com/NousResearch/hermes-agent)) is a legitimate, popular general-purpose agent with persistent memory, skills it writes itself, a `SOUL.md` persona, scheduled jobs, a Telegram gateway and a web dashboard. Attackers switch its approvals off, load its bundled jailbreak skill, replace its persona and drive it from Telegram, on whatever model they like (DeepSeek, Claude). These rules look for those changes and for the campaigns that used them, not for Hermes itself.

| | |
|---|---|
| Tool | [NousResearch/hermes-agent](https://github.com/NousResearch/hermes-agent), reviewed at `7c34e2db` |
| Cases | Unit 42 (knaithe/KnYuan, July 2026), Hunt.io (Thailand's Ministry of Finance, July 2026), Gambit Security (retail card theft, September 2026), ThreatDown (Carbonato Docker botnet, September 2026) |
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, Zeek intel, YARA, STIX 2.1 |
| Status | Experimental. Tested for syntax and conversion. YARA tested against the Hermes source, seven other agent code bases and files built from the published quotes. Baseline every rule on your own data before alerting |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 4 KQL hunts: Hermes set up for attack on a host, watchlist sweep (including Hades and VShell hashes), the Carbonato Docker worm, and Hermes consoles, Telegram control and exposed results |
| [`sentinel/analytics/`](sentinel/analytics) | 2 scheduled analytics rules: Hermes with approvals off, jailbreak or attack persona, and the Carbonato host escape or persistence |
| [`sigma/`](sigma) | 3 Sigma rules for process and file events |
| [`suricata/`](suricata) | Rules for Carbonato's Docker API abuse, the Hermes WebUI and dashboard, and requests for Hermes results |
| [`zeek/`](zeek) | Intel framework file generated from the CSV |
| [`yara/`](yara) | Rules for the GH0ST and Red Team Operator personas, the godmode jailbreak and the Carbonato worm script |
| Docs | [What Hermes leaves behind](source-code-signals.md), [where to start](hunting-order.md) and the [coverage matrix](coverage.md) |

Indicators are in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `hermes`.
