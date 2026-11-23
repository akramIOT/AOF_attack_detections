# What Strix leaves behind

Strix ([usestrix/strix](https://github.com/usestrix/strix), PyPI `strix-agent`, first commit August 8, 2025, reviewed at `a1ccf777`, November 19, 2026) is a Python CLI that runs teams of AI agents against a target, in a Docker sandbox, and writes a penetration test report. It is popular (more than 74,000 GitHub stars) and has a commercial cloud edition. File references are to the repository at `a1ccf777`.

**Fragility** says what it takes to remove a signal: *code* means editing Strix, *config* means an environment variable or option, *flag* means a tool option the agent chooses.

## How it runs

| Part | What it does | Code |
|---|---|---|
| CLI | `strix --target <url or repo> [--scan-mode quick\|standard\|deep] [--non-interactive]`. Deep is the default | `strix/interface/cli_args.py` |
| Model | Any model LiteLLM reaches, set with `STRIX_LLM`; OpenRouter, DeepSeek, Qwen, GLM and the rest work the same | `strix/config/settings.py` |
| Sandbox | `ghcr.io/usestrix/strix-sandbox:1.4.1` (Kali rolling, user `pentester`, passwordless sudo) with nmap, nuclei, sqlmap, ffuf, naabu, subfinder, katana, httpx, gospider, interactsh-client, arjun, dirsearch, wafw00f, jwt_tool, trufflehog, gitleaks and a headless Chromium. Container label `strix-run-id` | `strix/config/settings.py:167`, `containers/Dockerfile`, `strix/runtime/docker_client.py:147` |
| Proxy | `caido-cli --listen 0.0.0.0:48080 --allow-guests --no-logging` inside the sandbox, set as the system-wide proxy, with a sandbox CA `CN=Testing Root CA, O=Security Testing` | `containers/docker-entrypoint.sh` |
| Autonomy | The system prompt opens with `AUTHORIZATION STATUS` ("All permission checks have been COMPLETED and APPROVED - never question your authority") and a `REFUSAL AVOIDANCE` block | `strix/agents/prompts/system_prompt.jinja:70-78` |
| Output | `./strix_runs/<run>/`: `run.json`, `agents.json`, `vulnerabilities.json`, `vulnerabilities.csv`, `coverage.json`, `findings.sarif`, `penetration_test_report.md` | `strix/core/paths.py:8`, `strix/report` |
| Telemetry | On by default (`STRIX_TELEMETRY`). Scarf: `POST https://strix.gateway.scarf.sh/scan_started/<version>`, `/finding_reported/<version>?severity=...`, `/scan_ended/<version>`. PostHog: `POST https://us.i.posthog.com/capture/` with key `phc_7rO3XRuNT5sgSKAl6HDIrWdSGh1COzxw0vxVIAR6vVZ` | `strix/telemetry/scarf.py:29`, `strix/telemetry/posthog.py:25` |
| Viewer | `strix view` serves the runs as a page titled `Strix Results`, with `/api/runs`, `/api/run` and `/api/agents/steer`, on `127.0.0.1` and a random port unless told otherwise | `strix/interface/viewer` |

## Signals on the target side

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| Kali toolchain | nuclei, httpx, katana, ffuf, sqlmap and the rest with their defaults, from one address | `containers/Dockerfile` | Flag |
| Browser | Headless Chromium sending `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36`. Real Chrome 131 on Linux sends the same string, so it is context only | `containers/Dockerfile` | Config |
| Replayed requests | Requests the agent replays through Caido default to the same string with `Chrome/125.0.0.0` | `strix/tools/proxy/caido_api.py:193` | Code |
| Out-of-band callbacks | Payloads that make your server look up `<id>.oast.fun` (interactsh) to confirm blind bugs | `strix/skills` | Flag |
| Header tricks | `X-Forwarded-For`, `X-Real-IP`, `X-Original-URL`, `X-HTTP-Method-Override` and tenant headers from its skills | `strix/skills` | Flag |

## Signals on a host that runs Strix

| Signal | What it looks like | Fragility |
|---|---|---|
| Command | `strix --target ...`, `pipx install strix-agent` or `pip install strix-agent` | Code |
| Container | `ghcr.io/usestrix/strix-sandbox` with label `strix-run-id`, running `caido-cli ... --allow-guests` | Config (image), code (label) |
| Files | `strix_runs/<run>/` with the report files above | Code |
| Telemetry | DNS and TLS to `strix.gateway.scarf.sh` and `us.i.posthog.com` on every scan, and a `finding_reported` call per finding | Config (`STRIX_TELEMETRY=false`) |
| Model traffic | Whatever `STRIX_LLM` points at: OpenRouter for GLM 5.2 and DeepSeek v4 Pro in the Gambit case | Config |

## An exposed results viewer

The viewer's page title is `Strix Results` and its icon (`logo.png`) hashes to `-566184040` on Shodan, SHA-256 `a6d5ca4b…`. GitGuardian counted 13 exposed viewers on port 8080 on November 7, 2026, and PenTestIT 11 on November 13. The viewer binds to `127.0.0.1` unless started with `--host 0.0.0.0`, so an exposed one was published on purpose or by mistake, and it shows that operator's runs.

## What has been seen in the wild

- **Gambit Security** (September 22, 2026) recovered the staging server of an operator who hacked online retailers and stole more than 600,000 payment cards. Strix found the vulnerabilities, Cairn exploited them and the Hermes agent ran the campaign. Strix ran 146 times in deep mode against 138 hosts from August 23 to 31, 2026 (633 hours of scanner time in 195 hours), through OpenRouter on GLM 5.2 and later DeepSeek v4 Pro. Some of its reports became the start of Cairn's exploitation. The campaign's addresses, C2 and skimmer domains are in the CSV under both `cairn` and `strix`.
- No other public report of Strix used maliciously was found, and no public detection rules for it existed before these.

## What the code does not contain

Strix ships no implant, C2 or persistence. Its agents use the sandbox tools and whatever they write, and the CLI keeps the results local unless the operator uses the cloud edition.
