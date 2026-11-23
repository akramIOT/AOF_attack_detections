# CyberStrikeAI Detections

Part of [AOF Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

Detection rules, hunting queries and indicators for **CyberStrikeAI**, a Go operator console whose AI agents run about 90 security tools, and which also builds its own implants, runs C2 listeners, manages webshells and takes orders over chat platforms. Tool approval is off by default. Team Cymru tied a CyberStrikeAI server to the campaign that compromised more than 600 FortiGate firewalls, Kaspersky found its implants in attacks on education organizations in Africa and Latin America, and Elastic traced an AWS intrusion to one of its consoles.

| | |
|---|---|
| Tool | [AIPentest/CyberStrikeAI](https://github.com/AIPentest/CyberStrikeAI) (first published as Ed1s0nZ/CyberStrikeAI), reviewed at `af6cf750` |
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, Zeek intel, YARA, STIX 2.1 |
| Status | Experimental. Tested for syntax and conversion. YARA tested against implants compiled from the stock template for Windows, Linux and macOS, and against the CyberStrikeAI source. Baseline every rule on your own data before alerting |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 5 KQL hunts: the webshell manager and its OS probe, watchlist sweep, implant persistence and file names, implant check-ins (headers, paths and the 5-second interval), and a CyberStrikeAI console on your network |
| [`sentinel/analytics/`](sentinel/analytics) | 2 scheduled analytics rules: webshell manager or OS probe, and implant persistence |
| [`sigma/`](sigma) | 7 Sigma rules for web, proxy, process, registry and macOS file events |
| [`suricata/`](suricata) | Rules for the webshell manager, the OS probe and its answer, console user agents and certificate, implant headers, task polls, default user agent and TCP magic |
| [`zeek/`](zeek) | Intel framework file generated from the CSV |
| [`yara/`](yara) | Rules for compiled implants, the console, the curl one-liner and persistence files |
| Docs | [What CyberStrikeAI leaves behind](source-code-signals.md), [where to start](hunting-order.md) and the [coverage matrix](coverage.md) |

The AWS pattern from Elastic's intrusion report is a cross-framework hunt: [`behaviors/sentinel/hunting/08-aws-credentials-used-at-machine-speed.kql`](../../behaviors/sentinel/hunting/08-aws-credentials-used-at-machine-speed.kql).

Indicators are in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `cyberstrikeai`.
