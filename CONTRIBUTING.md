# Contributing to AOF Attack Detections

Contributions are detection content for agentic offensive frameworks: indicators with a source, hunting queries, and rules. A match is a lead. Rules in this repository are experimental until they have run on real data.

By submitting a change you agree it can be distributed under the [MIT license](LICENSE).

## What to send

| Change | Where it goes |
|---|---|
| An indicator for one framework | [`iocs/indicators.csv`](iocs/indicators.csv), `framework` set to that folder name |
| An indicator shared by more than one framework | One row, `framework` values separated by spaces (`cairn strix`) |
| A behavior that would fire for any of these tools | [`behaviors/`](behaviors) |
| A fingerprint of one named tool | `frameworks/<name>/` |
| A new framework | [docs/adding-a-framework.md](docs/adding-a-framework.md) |

Leave customer data, live credentials, and private incident detail out of issues and pull requests. Describe the rule name and the shape of the event.

## Reporting a false positive

Open an issue. Include:

- The rule, hunt, or indicator value.
- The log source (process, proxy, DNS, cloud audit).
- Why the match is expected in a normal environment.

Do not attach customer logs.

## Indicators

[`iocs/indicators.csv`](iocs/indicators.csv) is the only indicator list edited by hand. Columns:

| Column | Required | Meaning |
|---|---|---|
| `type` | yes | `ipv4`, `ipv6`, `domain`, `url`, `user_agent`, `sha256`, `md5`, `string`, or another type already used in the file |
| `value` | yes | The indicator. One row per `type` and `value`. Duplicates fail the feed build |
| `confidence` | yes | `high`, `medium`, or `low`. See the table below |
| `context` | yes | What the value is and where it was seen |
| `actor` | yes | Who it is attributed to, or the framework's operator label |
| `source` | yes | Publication or review that established it |
| `source_url` | yes | Link to that source |
| `reported` | yes | Date the source reported it, `YYYY-MM-DD` |
| `review_by` | for addresses | `reported` plus 180 days for `ipv4` and `ipv6`. Cloud and VPS addresses are reassigned |
| `framework` | yes | Folder name, or several names separated by spaces. Each name must exist in `FRAMEWORKS` in [`tools/build_feeds.py`](tools/build_feeds.py) |

Confidence:

| Level | Use it when |
|---|---|
| High | The value is specific to a framework or a named campaign: user agents, command lines, paths, prompt strings, probe artifacts, reported C2 and skimmer domains, file hashes |
| Medium | The value was seen in a framework's activity and can change or be shared: reported addresses, generic agent user agents, prompt text shared with similar tools |
| Low | The value is common or legitimate on its own: AI model APIs, request-collection services, agent CLI user agents, hosting ASNs, proxy providers |

Do not put API keys, private keys, or session tokens in the CSV. A detection string that is a tool's published default (a fixed proxy login, a stock console account) is an indicator. A secret from a victim environment is not.

## Rules

- Sigma and Sentinel rule ids are UUIDv5 values derived from the file path. They stay stable if the file is not renamed. Do not rename a published rule file to reword a title.
- Suricata SIDs are unique across the repository. Hand-written rules use the range in [docs/adding-a-framework.md](docs/adding-a-framework.md). Rules in `behaviors/suricata/` keep the SID they were first published with.
- Number a new KQL hunt `NN-short-name.kql`, using the next free number in that folder.

## Generated files

Do not edit these by hand. Regenerate them and commit the result.

| Generator | Writes |
|---|---|
| `python3 tools/build_feeds.py` | `feeds/`, `feeds/by-framework/`, `frameworks/*/zeek/intel/*.intel`, `frameworks/*/suricata/*-ip.rules`, `frameworks/artex/splunk/lookups/artex_iocs.csv` |
| `python3 tools/convert.py` | `generated/` |

`tools/build_feeds.py` uses the Python standard library. `tools/convert.py` and `tools/validate.py` need the packages in [`tools/requirements.txt`](tools/requirements.txt). CI runs on Python 3.12.

## Before you open a pull request

```bash
pip install -r tools/requirements.txt
python3 tools/build_feeds.py
python3 tools/convert.py
python3 tools/validate.py
```

`tools/validate.py` checks Sigma, Sentinel, Elastic, Splunk, Suricata SIDs, YARA, Zeek when Zeek is installed, osquery, and that a feed rebuild does not change committed files. CI runs the validator, runs `tools/convert.py`, and fails if `generated/` differs from the commit.

If you changed Zeek packages and Zeek is on `PATH`:

```bash
bash behaviors/zeek/tests/run_tests.sh
bash frameworks/artex/tests/run_network_tests.sh   # also needs suricata
```

In the pull request, say which framework or behavior changed, the source of any new indicator, and what you ran. Update the root [`README.md`](README.md) when you add a framework or a shared behavior. Describe the detection change in the pull request. [`CHANGELOG.md`](CHANGELOG.md) is updated when a version is released.

## Secrets

Do not commit `.env` files, API keys, cloud credentials, or private keys. The repository is scanned for those before it is published. A pull request that adds one will be rejected.
