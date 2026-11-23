# Adding a framework

Every framework follows the same shape, so the tools, CI and feeds pick it up without changes beyond one line in the feed builder.

## Layout

```text
frameworks/<name>/
  README.md                 what the framework is, what is in the folder, quick start
  source-code-signals.md    what its code leaves behind, with file references and how hard each signal is to remove
  coverage.md               behavior by platform
  hunting-order.md          where to start
  sentinel/hunting/*.kql    numbered KQL hunts, NN-short-name.kql
  sentinel/analytics/*.yaml Sentinel scheduled rule templates
  sigma/<category>/*.yml    Sigma rules
  suricata/<name>.rules     hand-written rules
  yara/<name>.yar           YARA rules
```

`frameworks/<name>/suricata/<name>-ip.rules` and `frameworks/<name>/zeek/intel/<name>.intel` are generated. Do not edit them by hand.

## Steps

1. Add the framework to `FRAMEWORKS` in `tools/build_feeds.py`: display name, aliases, a one-line description, the actor label used for the framework's own operators, and the next free Suricata address-rule SID base.
2. Add its indicators to `iocs/indicators.csv` with `framework` set to its folder name. An indicator shared with another framework keeps one row with both names, space separated.
3. Put rules that would work for any agentic framework in `behaviors/` rather than in the framework folder. Coding-agent abuse, tool bursts, proxy rotation and post-exploitation patterns usually belong there.
4. Run `python3 tools/build_feeds.py`, `python3 tools/convert.py` and `python3 tools/validate.py`, and commit everything they regenerate.
5. Add the framework to the tables in the root `README.md`.

## Number ranges

| Framework | Suricata rules | Suricata address rules |
|---|---|---|
| ARTEX | 9726001 to 9726499 | from 9726500 |
| Cairn | 9727001 to 9727499 | from 9727500 |
| PentAGI | 9728001 to 9728499 | from 9728500 |
| HexStrike | 9729001 to 9729499 | from 9729500 |
| CyberStrikeAI | 9730001 to 9730499 | from 9730500 |
| Strix | 9731001 to 9731499 | from 9731500 |
| Hermes Agent | 9732001 to 9732499 | from 9732500 |
| Agent Zero | 9733001 to 9733499 | from 9733500 |
| Next framework | 9734001 to 9734499 | from 9734500 |

Rules in `behaviors/suricata/` keep the SID they were first published with. Sigma and Sentinel rule ids are UUIDv5 values derived from the file path, so they stay stable as long as a file is not renamed.
