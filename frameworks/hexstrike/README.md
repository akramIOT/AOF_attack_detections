# HexStrike Detections

Part of [AOF Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors).

Detection rules, hunting queries and indicators for **HexStrike AI**, an MCP tool server that hands about 150 security tools to whatever AI assistant the operator already uses. It has no model of its own, binds every interface without authentication, and runs every tool through a shell. Criminals discussed it for NetScaler exploitation within hours of disclosure in 2025, and GTIG and Mandiant have seen it in intrusions.

| | |
|---|---|
| Tool | [0x4m4/hexstrike-ai](https://github.com/0x4m4/hexstrike-ai), version 6.0, reviewed at `d689933` |
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, Zeek intel, YARA, STIX 2.1 |
| Status | Experimental. Tested for syntax and conversion, YARA tested against the HexStrike source. Baseline every rule on your own data before alerting |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 4 KQL hunts: user agents and the XSS probe, watchlist sweep, the HexStrike server on a host, and AI assistants wired to a HexStrike server |
| [`sentinel/analytics/`](sentinel/analytics) | 2 scheduled analytics rules: user agent or XSS probe, and the server or MCP client on a host |
| [`sigma/`](sigma) | 3 Sigma rules for web, process and proxy logs |
| [`suricata/`](suricata) | Rules for its user agents, the XSS probe, the tool and command API on 8888 and the health response |
| [`zeek/`](zeek) | Intel framework file generated from the CSV |
| [`yara/`](yara) | Rules for the server and client scripts, MCP client configurations that use HexStrike, and generated exploit scripts |
| Docs | [What HexStrike leaves behind](source-code-signals.md), [where to start](hunting-order.md) and the [coverage matrix](coverage.md) |

Indicators are in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `hexstrike`.
