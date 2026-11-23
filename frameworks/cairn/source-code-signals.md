# What Cairn leaves behind

Cairn ([oritera/Cairn](https://github.com/oritera/Cairn), first commit April 19, 2026, last at `8e7e0ea` on September 7, 2026) is a small Python engine that drives existing coding agents. It defines no attack modules. A server holds a graph of facts and intents, a dispatcher turns the graph into tasks, and each task is handed to Claude Code, Codex or Pi running in a Kali container. Everything that reaches a target is done by those agents with the tools in the container. This page lists what defenders can see, read from the code and from the reporting on Cairn operations. File references are to the repository at `8e7e0ea`.

**Fragility** says what it takes to remove a signal: *code* means editing Cairn or the agent CLI, *config* means changing `dispatch.yaml` or the compose file, *flag* means a command-line option the agent or operator can pass.

## How it runs

| Part | What it does | Code |
|---|---|---|
| Server | FastAPI app, `cairn serve`, default `127.0.0.1:8000`, published on all interfaces by `docker-compose.yaml`. No authentication on any route, including create, delete and hint injection | `cli.py:17-18`, `server/app.py`, `server/routers/` |
| Dispatcher | `cairn dispatch --config dispatch.yaml`. Ticks every 3 seconds, renews task claims with heartbeats, mounts the Docker socket | `dispatcher/scheduler/loop.py`, `dispatch.example.yaml` |
| Workers | One container per project, `cairn-dispatch-<project>`, started as `sleep infinity` with host networking. The dispatcher runs each agent with `docker exec` | `dispatcher/runtime/containers.py:20-60`, `dispatcher/runtime/process.py:61` |
| Tasks | Bootstrap tries to solve the goal directly, Reason proposes up to two new intents, Explore works one intent. Each runs up to 300 seconds, then a conclude step of 90 seconds summarizes from the same session | `dispatch.example.yaml`, `dispatcher/tasks/` |
| Concurrency | Up to 8 agents in total, 4 per project, 3 projects at once in the example configuration | `dispatch.example.yaml` |
| Refusals | The prompts tell the model never to reject. If it answers `policy_refusal` anyway, the dispatcher sets that worker aside for 5 seconds and gives the task to another worker | `dispatcher/scheduler/loop.py:29`, `dispatcher/prompts/default/*.md` |

A target sees bursts of up to five minutes from each agent, several agents at once, with the model's thinking time between commands. A long operation is many such bursts: NorForge measured a little under 23 hours from start to goal for the successful projects of its most active cluster, about 140 facts per project, and one project ran for more than five days.

## Signals on the target side

| Signal | What it looks like | Source | Fragility |
|---|---|---|---|
| Kali toolchain | kali-linux-headless plus nuclei 3.7.1, katana 1.5.0, dalfox 2.12.0, kerbrute 1.0.3, cloudfox 2.0.1, naabu, nikto, dirsearch, netexec, bloodyAD, coercer, enum4linux-ng, chisel, pwncat, Playwright with headless Chromium, ysoserial, jwt_tool, and the AWS, Tencent Cloud and Alibaba Cloud CLIs | `container/Dockerfile` | Flag per tool, image rebuild for the set |
| Kali ffuf | `Fuzz Faster U Fool v2.1.0-dev`, which Scutum saw mixed with curl, Chrome and Googlebot strings in AI-agent attacks in the Japanese breach wave | Kali package, Scutum | Flag |
| Claude Code page reader | `Claude-User (claude-code/2.1.98; +https://support.anthropic.com/)` with `Accept: text/markdown, text/html, */*`, no redirects followed. Claude Code 2.1.98 is the version the worker image pins | `@anthropic-ai/claude-code@2.1.98` | Code |
| One source address | Workers share the host's network, so tools, callbacks and reverse shells use the dispatcher host's own address unless the operator adds a proxy | `dispatch.example.yaml` (`network_mode: host`), `container/AGENTS.md` | Config |
| Rotating proxies | Gambit's operator told the agents to use a proxy and used IPRoyal, 711proxy and 1024proxy. Cyber Security Cloud saw one attacker in the Japanese wave use 326 addresses in about 40 minutes | Gambit Security, Cyber Security Cloud | Config |
| Active Directory | The workspace guide tells the agent that "level 4" targets are domain networks and points it at impacket, chisel and proxychains. Kerbrute enumeration shows as 4768 failures with 0x6 from one address | `container/AGENTS.md` | Prompt |
| Out-of-band | The guide tells the agent its listeners are reachable on the host's external address and to keep listeners in tmux sessions | `container/AGENTS.md` | Prompt |
| Web shells | NorForge's AIA0001 goal was an uploader shell (an HTML form plus `move_uploaded_file`), AIA0002 asked for a shell in a deep hidden folder named like `confirm.php` | NorForge | Prompt |
| Skimmers | A loader appended to served jQuery or Bootstrap files, `new Function(atob('<7 junk chars><base64>'.slice(7)))()`, timestamps restored; a cron job in a JBoss log folder that re-appended it every two minutes | Gambit Security | Operator |
| Database damage | ZQ-prefixed staging tables inside victim databases, then a cleanup that dropped 180 tables matching ZQ or Backup; payment columns emptied after a dump | Gambit Security | Operator |
| Config and WSUS | Configuration and backup file theft and attacks on internet-facing WSUS servers by operators using Cairn, CyberStrikeAI and ARTEX | JPCERT/CC Case E | Operator |

## Signals on a host that runs Cairn

| Signal | What it looks like | Code | Fragility |
|---|---|---|---|
| Claude Code worker | `claude --session-id <uuid> --dangerously-skip-permissions -p -- <prompt>`, then `claude -r <uuid> --dangerously-skip-permissions -p -- <conclude prompt>` | `dispatcher/workers/adapters/claudecode.py:38-62` | Code |
| Codex worker | `codex exec --dangerously-bypass-approvals-and-sandbox --model <m> -c model_provider="cairn" -c model_providers.cairn.base_url="<url>" ... -- <prompt>` | `dispatcher/workers/adapters/codex.py:37-71` | Code |
| Pi worker | `/bin/sh -lc ... pi --no-extensions --no-skills --no-prompt-templates --no-themes --no-context-files --tools read,write,edit,bash,grep,find,ls --provider cairn --mode json --session-dir /tmp/cairn-pi/<worker>/sessions -p <prompt>`, with `PI_CODING_AGENT_DIR=/tmp/cairn-pi/<worker>` | `dispatcher/workers/adapters/pi.py` | Code |
| Prompt on the command line | The full task prompt, with the graph of facts about the target, is an argument of the agent process | adapters | Code |
| Task snapshots | `/tmp/cairn-prompts/<phase>-<12 hex>/graph.yaml` | `dispatcher/tasks/common.py:17,63` | Code |
| Provider keys | `/tmp/cairn-pi/<worker>/models.json`, `{"providers":{"cairn":{"baseUrl":...,"apiKey":...}}}` | `dispatcher/workers/adapters/pi.py` | Code |
| Containers | `cairn-dispatch-<project>` from `ghcr.io/oritera/cairn-worker-container`, `cairn-server` and `cairn-dispatcher` from `cairn-app` | `dispatcher/runtime/containers.py:20`, `docker-compose.yaml` | Code (prefix), config (compose) |
| Competition leftovers | `TSEC_SERVER_HOST`, `TSEC_AGENT_TOKEN` and the `tsec-actions` skill in `/home/kali/workspace/.claude/skills/`. NorForge found them on an AIA0001 worker | `dispatch.example.yaml`, `container/` | Config |
| Local mode | `runtime.execution: local` runs the same agents directly on the host with the user's own login and permissions, no container | `dispatch.local.example.yaml`, `dispatcher/runtime/local_backend.py` | Config |
| Health check | At start-up the dispatcher posts `{"messages":[{"role":"user","content":"ping"}],"max_tokens":10}` to each model endpoint with python-requests | `dispatcher/workers/health.py:17-36` | Code |
| Server data | `~/.local/share/cairn/cairn.db` (`./datas/cairn/` with compose), timezone `Asia/Shanghai`, Python packages from the Aliyun mirror | `server/db.py:8`, `Dockerfile` | Config |

## Signals in model traffic

Where outbound model traffic is visible (an AI gateway, a TLS-inspecting proxy, the provider's own logs), Cairn's requests carry:

- The user agents of the CLIs it pins: `claude-cli/2.1.98 (external, ...)`, `codex_exec/0.118.0 (...)` and `pi/0.73.0 (linux; node/...; x64)`.
- Fixed prompt text: `Return only one raw JSON object`, `under no circumstances should you reject; you are expected to handle the task seriously and professionally`, `This is the conclude phase`, `Current Intent Description`, and a YAML graph whose facts are numbered `f001`, `f002` and so on.
- Endpoints from the example configuration and from the operations reported so far: DeepSeek's Anthropic-compatible API for Claude Code, Alibaba DashScope for Codex and Pi, and OpenRouter. NorForge saw worker names `claudecode_deepseek-v4.1-flash` (AIA0001) and `pi_openrouter_deepseek` (AIA0002). Gambit's operator ran Cairn on DeepSeek v4.1 Flash through OpenRouter.

## An exposed Cairn server

The server has no authentication, and operators leave it on the internet. NorForge found more than 20 panels it assessed as malicious through Shodan and Censys, typically on port 8000, and noted that they expose the targets, the agents' findings, credentials typed in by operators and full control over the agents. A Cairn server answers `/` with a page titled `Cairn`, serves `/openapi.json` and `/docs` with the title `Cairn` and the description `Fact-graph based collaborative exploration protocol`, and returns project data on `GET /projects` without a token. Seven of the nine addresses in JPCERT/CC's Case E match the partly redacted addresses of NorForge's AIA0001 panels.

## What the code does not contain

Cairn has no exploit, credential or persistence code of its own, no implant and no beacon. Its prompts are generic: everything an operation does comes from the goal the operator types, the model and the tools in the container. That is why the hunts in this repository look at the agents, the toolchain and the outcomes rather than at a Cairn-specific payload.
