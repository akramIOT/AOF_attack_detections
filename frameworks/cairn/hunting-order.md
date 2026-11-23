# Where to start

Cairn operations are long and patient: a successful project in NorForge's most active cluster took a little under 23 hours, and Gambit's operator ran for months. Work in this order, because each step narrows the next.

1. **Sweep the indicators.** Load the watchlist and run the indicator sweep from July 1, 2026, the start of the Gambit campaign. A hit on a skimmer or C2 domain from a browser or a server means a page of yours may already carry a skimmer. No hit proves nothing: these operators rotate through residential proxies.
2. **Check your shops and web applications.** Run the Claude Code page reader, Kali toolchain, rotating proxy and configuration file hunts against your internet-facing applications. A 200 for a `.env` or a backup archive is the first row to read.
3. **Check what was written.** Run the uploader shell and skimmer hunt on your web servers, and the database hunt where you collect audit logs. A web process writing a PHP file or touching a JavaScript library is the point where probing became an intrusion.
4. **Check identity and the internal network.** Run the Kerberos and fan-out hunt. The worker image ships kerbrute, netexec and Impacket.
5. **Check your own hosts.** Run the coding-agent, host artifact and model traffic hunts. Cairn's local mode runs on any machine with Claude Code, Codex or Pi installed, so a developer laptop or a build server can be the attacker. An exposed Cairn server on your network also hands your targets and credentials to anyone who finds it.

## Tuning

- Developers use coding agents every day. The agent hunts look for bypass mode combined with attack tools, or for agent CLIs on servers; keep a list of the machines where that is expected.
- Scanners, uptime monitors and authorized tests match the web hunts. Keep a list of authorized testing sources and exclude them.
- The burst and proxy thresholds are starting points. Run each hunt over 30 days before enabling it and raise the threshold until the noise is gone.
- Treat a low-confidence indicator (agent CLI user agents, Kali ffuf, hosting ASNs, proxy providers) as context for another finding, never as a finding on its own.
