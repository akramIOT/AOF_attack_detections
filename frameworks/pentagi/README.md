# PentAGI Detections

Part of [AOF Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors), including the server callback hunt that covers PentAGI's worker ports.

Detection rules, hunting queries and indicators for **PentAGI**, the multi-agent penetration testing platform from VXControl. It splits a goal into subtasks for specialist agents that run Kali tools in a container per engagement, and keeps them moving with a reflector that answers in the user's voice. Google's threat intelligence group and Mandiant have seen it in intrusions since August 2026.

| | |
|---|---|
| Tool | [vxcontrol/pentagi](https://github.com/vxcontrol/pentagi), open source with a commercial edition, reviewed at `cffed94` |
| Seen in | Mandiant incident response engagements (GTIG), a PaperCut exploitation operator's infrastructure (Hunt.io), more than 700 internet-reachable consoles (Talos) |
| Platforms | Microsoft Sentinel and Defender XDR, Sigma, Suricata, Zeek intel, YARA, STIX 2.1 |
| Status | Experimental. Tested for syntax and conversion, YARA tested against the PentAGI source. Baseline every rule on your own data before alerting |

## What is in this folder

| Folder | Contents |
|---|---|
| [`sentinel/hunting/`](sentinel/hunting) | 5 KQL hunts: indicator and watchlist sweeps, PentAGI on a host you monitor, every page fetched twice at once, and console traffic in proxy logs |
| [`sentinel/analytics/`](sentinel/analytics) | 2 scheduled analytics rules: the agent command wrapper, and the update check from your network |
| [`sigma/`](sigma) | 3 Sigma rules for process, DNS and proxy logs |
| [`suricata/`](suricata) | Rules for the PentAGI certificate, the update service, console pages, prompts in model traffic and callbacks to the worker ports, plus generated address rules |
| [`zeek/`](zeek) | Intel framework file generated from the CSV |
| [`yara/`](yara) | Rules for the PentAGI server binary and source, its prompt templates and the agent command wrapper |
| Docs | [What PentAGI leaves behind](source-code-signals.md), [where to start](hunting-order.md) and the [coverage matrix](coverage.md) |

Indicators are in [`../../iocs/indicators.csv`](../../iocs/indicators.csv) with `framework` set to `pentagi`; the per-framework lists are in [`../../feeds/by-framework/pentagi/`](../../feeds/by-framework/pentagi).

## Quick start

**Microsoft Sentinel.** Upload `feeds/sentinel-watchlist.csv` as the `AOF_IOCs` watchlist and run `sentinel/hunting/02-watchlist-indicator-sweep.kql`, which filters it to PentAGI rows. Import the analytics rules from `sentinel/analytics/`.

**Suricata.** Add `suricata/pentagi.rules` and `suricata/pentagi-ip.rules`. The certificate and DNS rules work on encrypted traffic.

**YARA.** Scan container images, Docker hosts and model-gateway logs with `yara/pentagi.yar`.

## Confidence

Exposed consoles in the CSV are marked low: an exposed console is not proof of malicious use. The update service is legitimate; a hit means PentAGI runs on that host, not that it attacked anyone.
