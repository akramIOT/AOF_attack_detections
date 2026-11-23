# Where to start

1. **Close Docker APIs.** Check for anything listening on 2375 from the internet, then run the Carbonato hunt.
2. **Sweep the indicators** with the watchlist hunt, including the Hades and VShell hashes from the Thai ministry case.
3. **Find Hermes and check how it is set up.** Hermes is legitimate, so look for yolo mode, the godmode skill, `prefill.json`, a replaced `SOUL.md` or a `loot/` folder. Scan `~/.hermes` with the YARA rules.
4. **Look for Telegram traffic from servers** and for Hermes consoles or file servers listening on hosts that should not run an agent.
5. **Run the model traffic hunt** in `behaviors/`: a server calling DeepSeek or a model gateway is the other half of the same picture.
