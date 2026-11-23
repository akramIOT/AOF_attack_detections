# Changelog

## 2.8.0, November 21, 2026

- New behavior: one server calling several AI model APIs within 30 minutes, the provider failover described for autonomous offensive frameworks. KQL hunt 10, a Sentinel analytics rule, a Sigma correlation, and the Zeek notice `Model_API_Failover`. The single-API Zeek check is unchanged.
- New behavior: a server looking up a canary-token domain (`canarytokens.com`, `canarytokens.org`, `canary.tools`), which is the callback after something reads a planted token. KQL hunt 11, a Sentinel analytics rule, Sigma, Suricata (SIDs 9727060 to 9727062) and the Zeek notice `Canary_Token_Lookup`.

## 2.7.0, November 21, 2026

- Repository renamed from `agentic-attack-detections` to `AOF_attack_detections`. The display name is AOF Attack Detections. The Sentinel watchlist alias is now `AOF_IOCs`. Re-upload `feeds/sentinel-watchlist.csv` if you uploaded it as `AGENTIC_IOCs`.

## 2.6.0, November 21, 2026

- Hermes Agent added in `frameworks/hermes/`: 4 KQL hunts, 2 analytics rules, 3 Sigma rules, Suricata and YARA for Hermes turned into an attack console (approvals off, the bundled godmode jailbreak skill, replaced personas, Telegram control) and for the Carbonato Docker botnet that installs it, from a review of the Hermes source (NousResearch/hermes-agent at 7c34e2db) and reporting by Unit 42, Hunt.io, Gambit Security and ThreatDown. The indicators include the Thai Ministry of Finance case (Hades and VShell hashes) and Carbonato's infrastructure; the Gambit campaign rows now carry `hermes` too.
- Agent Zero added in `frameworks/agent-zero/`: 2 KQL hunts, 1 Sigma rule, Suricata and YARA for its container, hacker profile, exposed UI and tunnels. GTIG reported threat-actor experimentation but published no indicators, so this folder holds software fingerprints.
- AntiFox, the renamed ARTEX fork, in `frameworks/artex/`: hunt 31 for the IIS web shell to AWS enumeration sequence Arctic Wolf Labs reported, and indicators for its Alibaba Cloud consoles, exposed consoles, image, user agents and recording proxy.
- 515 indicators in total.

## 2.5.0, November 21, 2026

- Strix added in `frameworks/strix/`: 17 indicators, 3 KQL hunts, 1 analytics rule, 3 Sigma rules, Suricata and YARA, from a review of the Strix source code (usestrix/strix at a1ccf777) and reporting by Gambit Security, GitGuardian and PenTestIT. The Gambit retail campaign indicators are now tagged `cairn strix`: Strix found the flaws and Cairn exploited them.
- New behavior: servers looking up out-of-band testing domains (interactsh `oast.*`, Burp Collaborator, dnslog.cn and others), as a KQL hunt, Sigma, Suricata (SIDs 9727050 to 9727059) and a Zeek notice.

## 2.4.0, November 21, 2026

- Zeek package for the cross-framework behaviors in `behaviors/zeek/agentic-behaviors/`: model API calls from servers, Claude Code's page reader next to attack traffic, rotating proxy probing, configuration and backup file theft, WSUS probes, Kerberos enumeration, SMB and WinRM fan-out, and servers calling back to the address that probed them. Tested against a synthetic pcap in `behaviors/zeek/tests/`.
- `tools/validate.py` parses every Zeek package when Zeek is installed.
- The agent behaviors now detect agentic AI used for attack whatever the model, instead of centring on Claude Code. Hunt 02 reports servers calling any AI model API, with Chinese models (DeepSeek, Qwen, GLM, Kimi, MiniMax, Doubao, SiliconFlow and others) and model gateways ranked first, and no longer drops consoles calling from Go or Python. Hunt 01 and its analytics and Sigma rules add Qwen Code and Kimi CLI in auto-approve mode. Hunt 03, Sigma, Suricata (SIDs 9727012 to 9727014) and Zeek add the Qwen Code, Kimi CLI and opencode user agents. Endpoints and user agents come from the Qwen Code, Kimi CLI and opencode source. Hunts 01 to 03 have new file names; Sigma and analytics rules keep their paths and ids.

## 2.3.0, November 21, 2026

- CyberStrikeAI added in `frameworks/cyberstrikeai/`: 72 indicators, 5 KQL hunts, 2 analytics rules, 7 Sigma rules, Suricata and YARA, from a review of the CyberStrikeAI source code (AIPentest/CyberStrikeAI at af6cf750) and reporting by Team Cymru, Kaspersky, Elastic, Spectrum Security, PenTestIT, Huntback and the D4 Project. The YARA implant rule was tested against implants compiled from the stock template.
- The CyberStrikeAI webshell user agent that 1.0.0 listed as a related framework under ARTEX now belongs to the `cyberstrikeai` framework.
- New behavior hunt: AWS credentials used at machine speed from one outside address, from Elastic's CyberStrikeAI intrusion report.
- The feeds now carry IPv6 addresses (`ipv6.txt`) and MD5 hashes (`md5.txt`), in the STIX bundle and Zeek intel as well.
- The watchlist sweeps in the Cairn, PentAGI and HexStrike folders no longer call it the Cairn watchlist.

## 2.2.0, November 21, 2026

- HexStrike added in `frameworks/hexstrike/`: 20 indicators, 4 KQL hunts, 2 analytics rules, 3 Sigma rules, Suricata and YARA, from a review of the HexStrike source code (0x4m4/hexstrike-ai at d689933) and reporting by Check Point, GTIG, Elastic and Threat Landscape.
- The HexStrike user agents that 1.0.0 listed as a related framework under ARTEX now belong to the `hexstrike` framework.

## 2.1.0, November 21, 2026

- PentAGI added in `frameworks/pentagi/`: 39 indicators, 5 KQL hunts, 2 analytics rules, 3 Sigma rules, Suricata and YARA, from a review of the PentAGI source code (vxcontrol/pentagi at cffed94) and reporting by GTIG, Elastic, Talos, Hunt.io, RST Cloud, GitGuardian and Threat Landscape.
- New behavior hunt: a server calling back to the address that was probing it, which covers reverse shells to PentAGI's worker ports and to Cairn's host network.
- Correction carried into the indicators: the PentAGI console certificate's issuer is `CN=PentAGI CA`; the server certificate itself is `CN=localhost`, `O=PentAGI`, SAN `pentagi.local`.
- Three exposed consoles run ARTEX and PentAGI on one server and are tagged with both frameworks.

## 2.0.0, November 21, 2026

The repository becomes Agentic Attack Detections and covers more than one framework. It was `artex-detections`; GitHub redirects the old address. Later renamed to `AOF_attack_detections` (see 2.7.0).

- ARTEX rules moved from the root to `frameworks/artex/` (Sigma, Sentinel, Splunk, Elastic, Zeek, Suricata, YARA, osquery, tests and the ARTEX docs). `iocs/indicators.csv` and `feeds/` kept their paths.
- Cairn added in `frameworks/cairn/`: 71 indicators, 6 KQL hunts, 2 analytics rules, 3 Sigma rules, Suricata and YARA, from a review of the Cairn source code and reporting by NorForge, Gambit Security, JPCERT/CC and Scutum.
- New `behaviors/` folder for rules that do not depend on one framework: coding agents in bypass mode starting attack tools, agent CLIs calling model gateways from servers, Claude Code's page reader next to scanning, rotating-proxy probing, configuration and backup theft with WSUS probes, and Kerberos enumeration with SMB or WinRM fan-out.
- `iocs/indicators.csv` gains a `framework` column as its last column. `38.244.50.120` is shared by ARTEX and Cairn reporting and carries both.
- The Sentinel watchlist alias is now `AGENTIC_IOCs` for all frameworks; each framework's watchlist sweep filters it. Re-upload `feeds/sentinel-watchlist.csv` if you uploaded it as `ARTEX_IOCs`. The alias later became `AOF_IOCs` (see 2.7.0).
- `feeds/by-framework/` has the plain lists per framework. The STIX bundle has one tool per framework.
- Generated address rules and Zeek intel moved into each framework folder. `generated/` is now split by framework and `behaviors`.
- `docs/adding-a-framework.md` describes the layout and number ranges for the next framework.

## Unreleased

- Every branded indicator now names the publication it first appeared in: Datadog Security Labs (November 9, 2026) for the `artex-*` user agents and S3 placeholder names, Wiz Research (October 22) for `/zzz-nonexistent-xyz123`, `ReconProbe/1.0` and `norma/0.4`, Microsoft (October 21) for `azure-toolkit/1.0`, and Eye Security (November 12) for `X-ARTX-KEY`, `### ARTX-AGENT`, the probe markers and `ArtExVerify/1.0`. No indicator was removed.
- Context corrected: these strings are chosen at run time by the agents or the operator, which is why they are absent from the public code. 1.1.0 described them as coming from modified builds.
- `Mozilla/5.0 (compatible; ArtExVerify/1.0)` raised to high confidence, from Eye Security's primary report.
- New section in `docs/source-code-signals.md`: where the branded strings come from.

## 1.1.0, November 21, 2026

Detections drawn from a review of the ARTEX source code (BaaRai/ARTEX at f787b5f and the BaaRai/Norma v0.4.11 agent library it builds against). See [`docs/source-code-signals.md`](docs/source-code-signals.md).

- 31 new indicators in `iocs/indicators.csv`, each with the file it comes from: the `artex-update-check` user agent, the `X-Keenable-Title: ARTEX` header, the recording proxy credential `artex-pace:artex-pace`, the `__artex-exec-drop` launcher argument and `artex-exec-` shim folder, prompt and envelope markers in model requests, more tool function names, the console title and icon hash, port 8788, skill script names and the S3 archive prefix. Feeds rebuilt.
- Context of `norma/0.4` and both `spa-api-recon` user agents now points at the code that sends them.
- The branded user agents from 1.0.0 (`artex-pentest/1.0` and the rest) are now marked as coming from modified builds: they do not appear in the upstream ARTEX code. `artex-enrich/1.0` context corrected: upstream enrichment sends `Go-http-client/1.1`.
- New hunts:
  - 23 norma page reads and the Go enrichment probe that follows them.
  - 24 the ARTEX container toolchain seen from one source (refines 17).
  - 25 request rates that match the ARTEX noise profiles.
  - 26 headless browsers and ARTEX clients signing in, and the pause while a person relays the MFA code.
  - 27 accounts registered by a source that is also probing the application.
  - 28 ARTEX running on a monitored host (refines 20).
  - 29 ARTEX console and side-channel traffic in outbound proxy logs.
  - 30 bracketed-paste bytes in shell input.
- New analytics rules: ARTEX code-default user agents, and the ARTEX agent shell or proxy credential on a host.

## 1.0.0, November 20, 2026

First public release.

- 184 indicators in `iocs/indicators.csv`, each with its source, confidence and review date, built into STIX 2.1, a Sentinel watchlist, a Splunk lookup, a Zeek intel file, Suricata address rules and plain lists.
- 31 Sigma rules and 5 Sigma correlations, converted to Splunk, Sentinel and Elastic in `generated/`.
- 22 Microsoft Sentinel and Defender XDR hunts and 5 scheduled analytics rules.
- 9 Elastic ES|QL hunts and 5 Elastic detection rules.
- A Splunk app with 15 saved searches and macros.
- A Zeek detection script, 27 Suricata rules, 4 YARA rules and an osquery pack.
- Network tests against a synthetic pcap for Zeek and Suricata.
