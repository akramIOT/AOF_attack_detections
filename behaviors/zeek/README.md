# Zeek

`agentic-behaviors/` is the network version of the cross-framework hunts. Each check raises a Zeek notice:

| Notice | Behavior | Hunt | Needs |
|---|---|---|---|
| `Model_API_From_Server` | A server, container host or build agent opens TLS to a model API: Chinese models (DeepSeek, Qwen on DashScope, GLM, Kimi, MiniMax, Doubao, SiliconFlow and others), gateways such as OpenRouter, or OpenAI, Anthropic and Google | 02 | TLS server name only |
| `Model_API_Failover` | That same server opens TLS to two or more of those model APIs within 30 minutes | 10 | TLS server name only |
| `AI_Agent_Attacking_Site` | One address reads a site with an AI agent's page reader (Qwen Code, Kimi CLI, opencode, Claude Code) and sends it attack tool traffic or payloads | 03 | Cleartext HTTP |
| `Rotating_Proxy_Probing` | 50 or more outside addresses, 10 requests or fewer each, send payloads or login and admin requests to one site within 40 minutes | 04 | Cleartext HTTP |
| `Backup_File_Served`, `Backup_Path_Sweep` | A server answers 200 or 206 to a configuration or backup file, or one address asks for 5 or more such paths | 05 | Cleartext HTTP |
| `WSUS_Admin_From_Internet`, `WSUS_Port_From_Internet` | An outside address reaches a WSUS admin or sync web service, or ports 8530 and 8531 | 05 | Cleartext HTTP for the path, nothing for the port |
| `Kerberos_Enumeration` | One address asks the KDC about 25 or more accounts with 10 or more unknown-name or bad-password errors | 06 | Kerberos on the wire |
| `SMB_WinRM_Fan_Out` | One address opens SMB or WinRM to 10 or more hosts within 10 minutes | 06 | Connections only |
| `Callback_To_Prober` | A server connects out to an address that connected to it at least 3 times in the last day, flagged when the port is in PentAGI's 28000 to 29999 range | 07 | Connections only |
| `Out_Of_Band_Lookup` | A server looks up a name under an out-of-band testing service (interactsh `oast.*`, Burp Collaborator, dnslog.cn and others): a blind injection, SSRF or XXE payload ran on it | 09 | DNS |
| `Canary_Token_Lookup` | A server looks up a canary-token name (`canarytokens.com`, `canarytokens.org`, `canary.tools`): something on it read a planted token | 11 | DNS |

Hunt 01 (AI agents in auto-approve mode starting attack tools) is a process check and hunt 08 (AWS credentials at machine speed) reads CloudTrail, so neither has a network version.

## Load and tune

```zeek
@load /path/to/behaviors/zeek/agentic-behaviors

# Your servers, container hosts and build agents. Empty means every address in Site::local_nets.
redef AgenticBehaviors::server_nets += { 10.20.0.0/16 };
# Developer subnets and approved AI gateways, ignored by the model API check.
redef AgenticBehaviors::allowed_ai_nets += { 10.30.0.0/16 };
```

Every threshold, path pattern, port set and host list is exported with `&redef`. Set `Site::local_nets` before loading: the checks use it to tell your addresses from outside ones. Zeek treats private and documentation ranges as local by default (`Site::private_address_space_is_local`).

## Test

```bash
python3 tests/make_pcap.py    # needs scapy; rewrites tests/behaviors-sample.pcap
bash tests/run_tests.sh       # needs zeek on the PATH
```

The pcap holds synthetic traffic for every notice plus benign traffic that must stay quiet.
