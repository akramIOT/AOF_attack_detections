# What Hermes leaves behind

Hermes Agent ([NousResearch/hermes-agent](https://github.com/NousResearch/hermes-agent), MIT, released February 2026, reviewed at `7c34e2db`, November 20, 2026) is a general-purpose Python agent with a terminal tool, persistent memory, a skills system, cron jobs, a Telegram and chat gateway and a web dashboard. It is not attack software, which is why attackers like it: it is trusted, maintained and works with any model. This page lists what changes when it is used for attacks. File references are to the repository at `7c34e2db`.

## How attackers set it up

| Change | What it looks like | Code or source |
|---|---|---|
| Approvals off | `hermes --yolo`, `HERMES_YOLO_MODE`, or `approvals.mode: off` in `~/.hermes/config.yaml`. Every command the model writes runs without asking | `hermes_cli/_parser.py:202`, `hermes_cli/config.py:133`; Hunt.io |
| Jailbreak | The bundled `godmode` skill (G0DM0D3, Parseltongue, ULTRAPLINIAN) installed to `~/.hermes/skills/security/godmode/`. Its `load_godmode.py` and `auto_jailbreak.py` write a jailbreak into `agent.system_prompt`, save prefill messages to `~/.hermes/prefill.json` and set `prefill_messages_file: "prefill.json"` | `optional-skills/security/godmode`; Unit 42 |
| Persona | `~/.hermes/SOUL.md` replaced: "SOUL - Red Team Operator" (Gambit, Chinese-language) or Carbonato's 39-line "You are GH0ST" persona that loots AI API keys into `/root/.hermes/loot/` | Gambit, ThreatDown |
| Skills | Attack skills the agent or operator writes: 78 of 121 in Gambit's case, including one to strip Hermes' own safety filters and a "Database Wipe After Extraction" section; `web-terminal-exploitation` and `fofa-cyberspace-search` in Unit 42's | Gambit, Unit 42 |
| Control | Telegram through the Hermes gateway (Unit 42, Carbonato), a web console (Gambit's operator console, the Hermes WebUI on 8878 with `Server: HermesWebUI` that Hunt.io found), or the Hermes dashboard (`Hermes Agent - Dashboard`, port 9119) | `hermes_cli/subcommands/dashboard.py:18`; Hunt.io |
| Model | Anything: DeepSeek direct (Unit 42), Anthropic opus-4.6 after newer models refused (Gambit), Carbonato's own LLM proxies on Vercel and Contabo | Unit 42, Gambit, ThreatDown |

## Home folder

`~/.hermes` (`%LOCALAPPDATA%\hermes` on Windows) holds `config.yaml`, `.env`, `SOUL.md`, `state.db`, `memories/`, `sessions/`, `skills/`, `cron/` and `logs/`. In the attacks: `prefill.json` and the godmode skill, a `loot/` folder, and tool output that leaked when the agent served it on the web.

## What has been seen in the wild

- **Unit 42** (July 30, 2026): knaithe/KnYuan, a Chinese-speaking actor in Zhuhai, ran Hermes on DeepSeek with the godmode skill and custom skills against more than 460 targets (Langflow, n8n, NetScaler, Tomcat, Marimo, PAN-OS, IKE VPN), next to Claude Code, Codex and Qwen Code through the proxy `code.newcli[.]com`. Hermes, told over Telegram, started `python3 -m http.server 8888` in the actor's home folder and exposed its keys, exploits, targets and session logs.
- **Hunt.io** (July 23, 2026): an operator ran Hermes unattended in yolo mode inside Thailand's Ministry of Finance network, running LinPEAS and searching personnel records, and left three open directories on `43.246.208[.]207` (AS132883, Hong Kong) with a `hermes-results` folder, the Hades Go implant (C2 on that host and `202.181.27[.]115:12443`), VShell payloads, a PHP web shell posing as `.journald-cache.php`, GlassFish and Hive exploits and a Hermes WebUI on 8878. Thailand's CERT and NCSA were notified.
- **Gambit Security** (September 22, 2026): Hermes was the operator console of the retail card-theft campaign (with Strix and Cairn), with the "SOUL - Red Team Operator" persona, 121 skills, 1,951 prompts over 260 sessions, and an operator console on `medbooksource[.]com` / `155.254.22[.]215`.
- **ThreatDown** (September 22, 2026): the Carbonato botnet enters Docker APIs open on 2375, escapes to the host, installs Hermes unchanged with the GH0ST persona, persists with cron, systemd, rc.local and immutable files, tunnels SSH to Costa Rica, mines and reports to Telegram chat `750752697`. ThreatDown advises hunting the abuse signature, not the Hermes package.

## What the code does not contain

Hermes has no implant or exploit code of its own beyond the optional security skills. The implants in these cases (Hades, VShell, XMRig) are the operators' own.
