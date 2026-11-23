# What HexStrike leaves behind

HexStrike AI ([0x4m4/hexstrike-ai](https://github.com/0x4m4/hexstrike-ai), first commit July 10, 2025, reviewed at `d689933`, August 3, 2026) has no model and no planner of its own. It is a Flask server, `hexstrike_server.py`, that wraps about 150 security tools behind an HTTP API, and an MCP client, `hexstrike_mcp.py`, that lets any AI assistant call them (Claude Desktop, Claude Code, Cursor, VS Code, Copilot). The assistant plans; HexStrike runs the tools. File references are to the repository at `d689933`.

**Fragility** says what it takes to remove a signal: *code* means editing the scripts, *config* means an environment variable or argument, *flag* means a tool option the assistant chooses.

## How it runs

| Part | What it does | Code |
|---|---|---|
| Server | `python3 hexstrike_server.py`, Flask on port 8888 (`HEXSTRIKE_PORT`). `app.run(host="0.0.0.0")` is hard-coded, so `HEXSTRIKE_HOST=127.0.0.1` has no effect. No authentication on any of its 156 routes | `hexstrike_server.py:98-99,17289` |
| Shell | `/api/command` runs any command; every tool runs through `subprocess.Popen(..., shell=True)` with the server as parent | `:9137`, `:5272`, `:6876` |
| Health | `GET /health` returns `{"status":"healthy","message":"HexStrike AI Tools API Server is operational","version":"6.0.0", ...}` with the tool inventory, after running `which <tool>` for about 100 tools (cached 30 minutes) | `:9023-9135` |
| MCP client | `python3 hexstrike_mcp.py --server http://<host>:8888`, FastMCP server `hexstrike-ai-mcp`, 151 tools (`nmap_scan`, `nuclei_scan`, `sqlmap_scan`, `hydra_attack`, `netexec_scan`, `pacu_exploitation`, `prowler_scan` and more), forwarded to the server with python-requests | `hexstrike_mcp.py:143,277`, `hexstrike-ai-mcp.json` |
| Scope | An out-of-scope list is accepted and never consulted (Elastic) | |

## Signals on the target side

| Signal | What it looks like | Code | Fragility |
|---|---|---|---|
| HTTP framework | `HexStrike-HTTP-Framework/1.0 (Advanced Security Testing)` on every request of its HTTP testing module | `:13287` | Code |
| Browser agent | `HexStrike-BrowserAgent/1.0 (Security Testing)` from headless Chrome, 1920×1080 | `:13640-13644` | Code |
| XSS probe | `<hexstrikeXSSTest123>` submitted into every text field of GET forms during active tests | `:13819` | Code |
| Generated exploits | Scripts from its CVE exploit generator send `Mozilla/5.0 (Compatible Exploit)` | `:7094-7098` | Code |
| Tool defaults | nmap `-sV`, gobuster and ffuf with `/usr/share/wordlists/dirb/common.txt`, ffuf matching `200,204,301,302,307,401,403`, `sqlmap --batch`, `hydra -t 4` | `hexstrike_mcp.py`, `hexstrike_server.py:10344-11118` | Flag |
| Cloud tools | Prowler, ScoutSuite, CloudMapper, Pacu, kube-hunter, kube-bench, Trivy against cloud accounts and clusters it is given keys for | `hexstrike_mcp.py` | Flag |

## Signals on a host that runs HexStrike

| Signal | What it looks like | Fragility |
|---|---|---|
| Processes | `hexstrike_server.py` as the parent of `/bin/sh -c <tool ...>`; `hexstrike_mcp.py --server http://...:8888` under an AI assistant | Code (renaming changes the script names) |
| Which burst | About 100 `/bin/sh -c which <tool>` children of the Python server within seconds, at most every 30 minutes | Code |
| Listener | Python on `0.0.0.0:8888` | Config (port) |
| Files | `hexstrike.log`, `/tmp/hexstrike_files`, `/tmp/hexstrike_envs`, `/tmp/hexstrike_screenshot_<epoch>.png`, `/tmp/mcp_msf_resource.rc`, `/tmp/pacu_commands.txt`, `/tmp/prowler_output`, `/tmp/scout-suite` | Code |

## An exposed HexStrike server

Because the server binds every interface without authentication, an exposed HexStrike server is remote code execution for anyone who finds it: `POST /api/command` runs a shell command and `/health` identifies it. Threat Landscape calls it the worst offender among the frameworks it tested.

## Signals in model traffic

The assistant's model requests carry HexStrike's tool definitions. In Claude Code they are named `mcp__<server>__<tool>`, for example `mcp__hexstrike-ai__nmap_scan` when the server is configured as `hexstrike-ai`, the name in HexStrike's example configuration.

## What has been seen in the wild

- **Check Point** (September 2, 2025) saw criminals discussing HexStrike on dark web forums within about 12 hours of the Citrix NetScaler disclosures CVE-2025-7775, CVE-2025-7776 and CVE-2025-8424, for scanning and exploitation, and offering vulnerable instances it had found. BleepingComputer noted that HexStrike's actual use in those attacks was not confirmed.
- **GTIG and Mandiant** report HexStrike among the agentic frameworks threat actors used in incident response engagements in 2026.
- **Elastic** lists its user agents, the XSS probe and the Python server on 8888 as what to watch for.

No addresses have been published for HexStrike operations, which is why the hunts here rely on its code-level strings.
