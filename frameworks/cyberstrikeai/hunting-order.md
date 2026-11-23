# Where to start

1. **Check your web servers for the webshell manager.** Search web and proxy logs for its user agent, and EDR for a web server process running `echo :OSPROBE_%OS%:END`. A hit means a webshell is already in place.
2. **Look for implants.** Run the persistence hunt (SystemUpdate Run value or task, @reboot cron, `.bashrc # cs`, com.apple.systemupdate) and the check-in hunt. Scan `C:\Windows\Temp`, `C:\ProgramData`, `/tmp` and home folders with the YARA implant rule: the build path survives stripping.
3. **Sweep the indicators.** Run the watchlist hunt for the Kaspersky C2 addresses, domains and hashes, the Elastic consoles and the Team Cymru servers. The Team Cymru addresses are from early 2026, so treat a match as a lead.
4. **Check your cloud.** If AWS keys or instance roles could have leaked, run the machine-speed AWS hunt in `behaviors/`.
5. **Check your own network.** Run the console hunt: a CyberStrikeAI console inside your estate is a C2 server.
