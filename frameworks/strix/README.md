# Strix Detections

Part of [AOF Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

Detection rules, hunting queries and indicators for **Strix**, an open-source Python AI penetration testing agent that runs teams of agents in a Kali sandbox container, with every tool proxied through Caido. It works with any model LiteLLM reaches. In the retail card-theft campaign Gambit Security reported, the operator ran Strix 146 times in deep mode against 138 hosts on GLM 5.2 and DeepSeek v4 Pro through OpenRouter, and handed what it found to Cairn for exploitation.

| | |
|---|---|
| Tool | [usestrix/strix](https://github.com/usestrix/strix) (PyPI `strix-agent`), reviewed at `a1ccf777` |
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, Zeek intel, YARA, STIX 2.1 |
| Status | Experimental. Tested for syntax and conversion, Suricata on crafted traffic, YARA against the Strix source and four other agent code bases. Baseline every rule on your own data before alerting |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 3 KQL hunts: Strix on a host, watchlist sweep (including the Gambit campaign indicators shared with Cairn), and Strix telemetry and results viewers |
| [`sentinel/analytics/`](sentinel/analytics) | 1 scheduled analytics rule: Strix on a host or reporting from your network |
| [`sigma/`](sigma) | 3 Sigma rules for process, DNS and proxy logs |
| [`suricata/`](suricata) | Rules for Strix telemetry (DNS, TLS and the finding report), the results viewer page and its agent steering API |
| [`zeek/`](zeek) | Intel framework file generated from the CSV |
| [`yara/`](yara) | Rules for the Strix package, the sandbox entrypoint and run records |
| Docs | [What Strix leaves behind](source-code-signals.md), [where to start](hunting-order.md) and the [coverage matrix](coverage.md) |

What Strix does to a target looks like the stock tools it runs and like any agent, so the cross-framework rules carry most of the target-side detection: model API calls from servers (hunt 02), AI agent page readers next to attack traffic (hunt 03), rotating proxies (hunt 04) and out-of-band lookups from your servers (hunt 09) in [`behaviors/`](../../behaviors).

Indicators are in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `strix`.
