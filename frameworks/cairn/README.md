# Cairn Detections

Part of [AOF Attack Detections](../../README.md). Shared indicators and feeds live at the repository root; the rules for behaviors that every agentic framework shows are in [`behaviors/`](../../behaviors), including the coding-agent, model gateway, rotating proxy, configuration theft and Kerberos hunts first written for Cairn.

Detection rules, hunting queries and indicators for **Cairn**, the open-source engine that hands an intrusion to coding agents. Cairn drives Claude Code, Codex or Pi inside a Kali container with their safety prompts switched off, and keeps going from an origin to a goal for hours. Criminal operators have used it to break into online retailers, plant uploader web shells and card skimmers, and attack Japanese web applications and WSUS servers since mid-2026.

Maintained by [ThreatDefence](https://threatdefence.com). Built from a review of the Cairn source code and the public reporting on Cairn operations.

| | |
|---|---|
| Tool | [oritera/Cairn](https://github.com/oritera/Cairn), first published April 2026, debuted at the Tencent Cloud Hackathon AI penetration testing challenge |
| Actors | NorForge clusters AIA0001 (Chinese-language, e-commerce access in the US, Japan and Australia), AIA0002 (English-language, card and crypto theft) and AIA0003; a financially motivated operator Gambit Security tracked using Hermes, Strix and Cairn; unattributed operators in the Japanese breach wave (JPCERT/CC Case E) |
| Targets | E-commerce and payment sites, web applications, WSUS servers, cloud accounts, Active Directory |
| Platforms | Microsoft Sentinel and Defender XDR, Sigma (with Elastic, Splunk and Sentinel conversions), Suricata, Zeek intel, YARA, STIX 2.1 |
| Status | Experimental. Tested for syntax and conversion, YARA tested against the Cairn source. Baseline every rule on your own data before alerting |

## What is in the repository

| Folder | Contents |
|---|---|
| [`iocs/indicators.csv`](../../iocs/indicators.csv) | 72 indicators: host artifacts and command-line markers from the code, prompt strings, user agents, worker names, campaign addresses, domains and skimmer URLs. Each row has its source, confidence and a review date for addresses. This file is the single source for every feed |
| [`feeds/`](../../feeds) | Generated from the CSV: STIX 2.1 bundle, Sentinel watchlist and plain lists of addresses, domains, URLs and user agents |
| [`sentinel/hunting/`](sentinel/hunting) | 6 KQL hunts specific to Cairn; 6 more in [`behaviors/`](../../behaviors/sentinel/hunting) |
| [`sentinel/analytics/`](sentinel/analytics) | 2 scheduled analytics rules; 2 more in [`behaviors/`](../../behaviors/sentinel/analytics) |
| [`sigma/`](sigma) | 3 Sigma rules for process, file and DNS logs; 4 more in [`behaviors/`](../../behaviors/sigma) |
| [`generated/`](../../generated) | The Sigma rules converted by `tools/convert.py`. [`SUMMARY.md`](../../generated/SUMMARY.md) shows which rule converted to which backend |
| [`suricata/`](suricata) | Rules for an exposed Cairn server, Cairn prompts in model traffic, campaign domains and the skimmer loader, plus generated address rules. The page reader, Kali ffuf and WSUS rules are in [`behaviors/`](../../behaviors/suricata) |
| [`zeek/`](zeek) | Intel framework file generated from the CSV |
| [`yara/`](yara) | Rules for the Cairn source and prompts, worker workspace files, the Pi provider key file, uploader shells and the skimmer loader |
| Docs | [What Cairn leaves behind](source-code-signals.md), [where to start](hunting-order.md) and the [coverage matrix](coverage.md) |
| [`tools/`](../../tools) | Feed builder, Sigma converter and validator |

## Quick start

**Microsoft Sentinel.** Upload `feeds/sentinel-watchlist.csv` as a watchlist with the alias `AOF_IOCs` and the search key `value`, then run `sentinel/hunting/02-watchlist-indicator-sweep.kql` (it filters the watchlist to Cairn rows). Import the analytics rules from `sentinel/analytics/`. The hunts also run in Defender XDR advanced hunting where the tables exist.

**Suricata.** Add `suricata/cairn.rules` and `suricata/cairn-ip.rules` to your rule files. HTTP rules need cleartext or decrypted traffic. DNS and TLS SNI rules work on encrypted traffic.

**Zeek.** Load `zeek/intel/cairn.intel` through the Intel framework.

**YARA.** Scan container layers, home folders, `/tmp` and web roots with `yara/cairn.yar`.

**Sigma.** Convert with `sigma convert -t <backend> -p <pipeline> sigma/`, or use the conversions in `generated/`.

**Threat intelligence platforms.** Import `feeds/stix2.1-bundle.json`.

## Confidence

| Level | Meaning | How to use it |
|---|---|---|
| High | Specific to Cairn or its campaigns: its command lines, paths, container names, prompt strings, worker names, skimmer and C2 domains | Alert |
| Medium | Reported campaign addresses, Claude Code's page reader, prompt text shared with similar tools | Alert after baselining, or hunt |
| Low | Common or legitimate: agent CLI user agents, Kali ffuf, hosting ASNs, proxy providers, port 8000 | Context for another finding only |

Addresses come from VPS and hosting providers and get reassigned. Every address has a `review_by` date 180 days after it was reported. Check before you block.

## Testing

```bash
pip install -r tools/requirements.txt
python3 tools/validate.py            # from the repository root
python3 tools/convert.py
```

No rule in this repository has been tested against a captured Cairn intrusion, so treat every rule as experimental until it has run on your own data.

## Contributing

Pull requests are welcome. Add new indicators to `iocs/indicators.csv` with their source, run `python3 tools/build_feeds.py` and `python3 tools/validate.py`, and commit the regenerated files. Report false positives as issues, with the rule name and the shape of the event (no customer data).

## License

MIT. See [LICENSE](../../LICENSE). Each indicator names its source in `iocs/indicators.csv`.

## Disclaimer

Provided as is, without warranty. A match is a lead, not a verdict. Absence of a match does not mean absence of compromise.
