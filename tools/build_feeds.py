#!/usr/bin/env python3
"""Build every indicator feed from iocs/indicators.csv, the single source of truth for all frameworks.

    python3 tools/build_feeds.py

Each row names the framework(s) it belongs to in the "framework" column (space separated, for example "artex cairn").

Writes:
    feeds/ipv4.txt, ipv6.txt, domains.txt, urls.txt, user_agents.txt, sha256.txt, md5.txt   plain lists for all frameworks
    feeds/by-framework/<framework>/*.txt                                 the same lists per framework
    feeds/sentinel-watchlist.csv      Microsoft Sentinel watchlist (alias AOF_IOCs, search key "value")
    feeds/stix2.1-bundle.json         STIX 2.1 bundle: indicators, one tool per framework and the actors
    frameworks/<framework>/zeek/intel/<framework>.intel      Zeek Intel framework file
    frameworks/<framework>/suricata/<framework>-ip.rules     Suricata rules for the reported addresses
    frameworks/artex/splunk/lookups/artex_iocs.csv           Splunk lookup used by the ARTEX Splunk app

Standard library only, so it runs anywhere Python 3.9+ does.
"""
import csv
import datetime as dt
import hashlib
import json
import uuid
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "iocs" / "indicators.csv"
NOW = "2026-11-21T00:00:00.000Z"
NS = uuid.UUID("5b2d4b5e-6c3a-4f0e-9a1e-7d8c2f3a4b10")  # fixed namespace so STIX ids stay stable between builds

FRAMEWORKS = {
    "artex": {"name": "ARTEX", "sid": 9726500, "created": "2026_11_20",
              "aliases": ["ScopeWeaver", "LUCK", "Guanlan SEC", "ARTEX PRO", "AntiFox"],
              "description": "Open-source agentic AI penetration testing framework published by Autumn-27 in July 2026 and abused in real intrusions.",
              "own_actor": "ARTEX operators"},
    "cairn": {"name": "Cairn", "sid": 9727500, "created": "2026_11_21",
              "aliases": ["oritera/Cairn"],
              "description": "Open-source agentic problem-solving engine (oritera/Cairn, April 2026) that drives Claude Code, Codex and Pi coding agents in Kali containers; abused for web intrusions and payment-card theft since mid-2026.",
              "own_actor": "Cairn operators"},
    "pentagi": {"name": "PentAGI", "sid": 9728500, "created": "2026_11_21",
                "aliases": ["vxcontrol/pentagi", "Penetration Testing Artificial General Intelligence"],
                "description": "Open-source and commercial multi-agent penetration testing platform by VXControl that runs its tools in Kali Linux containers; abused in the wild since at least August 2026.",
                "own_actor": "PentAGI operators"},
    "hexstrike": {"name": "HexStrike", "sid": 9729500, "created": "2026_11_21",
                  "aliases": ["HexStrike AI", "0x4m4/hexstrike-ai"],
                  "description": "Open-source MCP tool server that exposes about 150 security tools to any AI assistant over an unauthenticated HTTP API; discussed for NetScaler exploitation in 2025 and seen by GTIG and Mandiant in intrusions.",
                  "own_actor": "HexStrike operators"},
    "cyberstrikeai": {"name": "CyberStrikeAI", "sid": 9730500, "created": "2026_11_21",
                      "aliases": ["AIPentest/CyberStrikeAI", "Ed1s0nZ/CyberStrikeAI", "DarkAI"],
                      "description": "Open-source Go operator console (Ed1s0nZ, later AIPentest, November 2025) whose AI agents run about 90 security tools and which builds its own implants, C2 listeners and webshell manager; tied to the FortiGate mass-exploitation infrastructure, an AWS intrusion and attacks on education organizations.",
                      "own_actor": "CyberStrikeAI operators"},
    "strix": {"name": "Strix", "sid": 9731500, "created": "2026_11_21",
              "aliases": ["usestrix/strix", "strix-agent"],
              "description": "Open-source Python AI penetration testing agent (usestrix/strix, August 2025) that runs teams of agents in a Kali sandbox container through a Caido proxy; used for vulnerability discovery in the 2026 retail card-theft campaign before Cairn exploitation.",
              "own_actor": "Strix operators"},
    "hermes": {"name": "Hermes Agent", "sid": 9732500, "created": "2026_11_21",
               "aliases": ["NousResearch/hermes-agent", "Hermes"],
               "description": "Open-source general-purpose AI agent from Nous Research with persistent memory, self-written skills, a SOUL.md persona, a Telegram gateway and a yolo mode; used as the attack console by knaithe/KnYuan, the Gambit retail card-theft operator, the Carbonato Docker botnet and against Thailand's Ministry of Finance.",
               "own_actor": "Hermes Agent operators"},
    "agent-zero": {"name": "Agent Zero", "sid": 9733500, "created": "2026_11_21",
                   "aliases": ["agent0ai/agent-zero", "AgentZero"],
                   "description": "Open-source general-purpose AI agent framework that runs in a Kali-based container with a built-in hacker profile and a web UI; GTIG reported threat-actor experimentation with it in 2026.",
                   "own_actor": "Agent Zero operators"},
}
ZEEK_TYPES = {"ipv4": "Intel::ADDR", "ipv6": "Intel::ADDR", "md5": "Intel::FILE_HASH", "domain": "Intel::DOMAIN", "user_agent": "Intel::SOFTWARE", "sha256": "Intel::FILE_HASH", "url": "Intel::URL"}


def load():
    with SRC.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def fw_of(r):
    return r.get("framework", "").split()


def only(rows, fw):
    return [r for r in rows if fw in fw_of(r)]


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def plain_lists(rows, folder):
    for kind, name in [("ipv4", "ipv4.txt"), ("ipv6", "ipv6.txt"), ("domain", "domains.txt"), ("user_agent", "user_agents.txt"), ("sha256", "sha256.txt"), ("md5", "md5.txt"), ("url", "urls.txt")]:
        values = sorted({r["value"] for r in rows if r["type"] == kind})
        write(folder / name, "\n".join(values) + "\n")


def table_csv(rows, path, cols):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def zeek_intel(rows, fw):
    label = FRAMEWORKS[fw]["name"]
    lines = ["#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\tmeta.url"]
    for r in rows:
        t = "Intel::SUBNET" if r["type"] == "ipv4" and "/" in r["value"] else ZEEK_TYPES.get(r["type"])
        if not t:
            continue
        desc = f"{label} {r['confidence']}: {r['context']} ({r['actor']})".replace("\t", " ")
        value = r["value"].split("://", 1)[-1] if r["type"] == "url" else r["value"]  # Zeek URLs carry no scheme
        lines.append("\t".join([value, t, f"threatdefence-{fw}", desc, r["source_url"]]))
    write(ROOT / "frameworks" / fw / "zeek" / "intel" / f"{fw}.intel", "\n".join(lines) + "\n")


def suricata_ip(rows, fw):
    meta = FRAMEWORKS[fw]
    label = meta["name"]
    by_actor = defaultdict(list)
    for r in rows:
        if r["type"] in ("ipv4", "ipv6"):
            by_actor[(r["actor"], r["context"])].append(r["value"])
    out = ["# Generated by tools/build_feeds.py from iocs/indicators.csv. Do not edit by hand.",
           f"# Reported {label} addresses. Cloud and VPS addresses are reassigned: check review_by in the CSV before blocking."]
    sid = meta["sid"]
    for (actor, ctx), ips in sorted(by_actor.items()):
        group = "[" + ",".join(sorted(set(ips))) + "]"
        msg = f"TD {label} reported address, {actor}, {ctx}".replace(";", ",").replace('"', "'")
        out.append(f'alert ip $HOME_NET any -> {group} any (msg:"{msg} (outbound)"; classtype:trojan-activity; sid:{sid}; rev:1; metadata:created_at {meta['created']}, confidence Medium;)')
        out.append(f'alert ip {group} any -> $HOME_NET any (msg:"{msg} (inbound)"; classtype:trojan-activity; sid:{sid + 1}; rev:1; metadata:created_at {meta['created']}, confidence Medium;)')
        sid += 2
    write(ROOT / "frameworks" / fw / "suricata" / f"{fw}-ip.rules", "\n".join(out) + "\n")


def sid_for(kind, value):
    return f"{kind}--{uuid.uuid5(NS, kind + ':' + value)}"


def stix_pattern(r):
    v = r["value"].replace("\\", "\\\\").replace("'", "\\'")
    return {
        "ipv4": f"[ipv4-addr:value = '{v}']",
        "domain": f"[domain-name:value = '{v}']",
        "user_agent": f"[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = '{v}']",
        "ipv6": f"[ipv6-addr:value = '{v}']",
        "sha256": f"[file:hashes.'SHA-256' = '{v}']",
        "md5": f"[file:hashes.MD5 = '{v.lower()}']",
        "file_name": f"[file:name LIKE '{v}%']",
        "file_path": f"[directory:path = '{v}']",
        "uri_string": f"[url:value LIKE '%{v}%']",
        "url": f"[url:value = '{v}']",
        "account_name": f"[user-account:account_login LIKE '%{v}%']",
    }.get(r["type"])


def stix(rows):
    identity = {"type": "identity", "spec_version": "2.1", "id": sid_for("identity", "ThreatDefence"), "created": NOW, "modified": NOW,
                "name": "ThreatDefence", "identity_class": "organization"}
    tools = {}
    for fw, meta in FRAMEWORKS.items():
        tools[fw] = {"type": "tool", "spec_version": "2.1", "id": sid_for("tool", meta["name"]), "created": NOW, "modified": NOW,
                     "name": meta["name"], "aliases": meta["aliases"], "description": meta["description"],
                     "tool_types": ["exploitation", "vulnerability-scanning"]}
    objects = [identity] + list(tools.values())
    own = tuple(m["own_actor"] for m in FRAMEWORKS.values()) + ("Related", "Unknown", "Unattributed")
    actors, uses = {}, set()
    for r in rows:
        a = r["actor"]
        if a and not a.startswith(own):
            actors.setdefault(a, {"type": "intrusion-set", "spec_version": "2.1", "id": sid_for("intrusion-set", a), "created": NOW, "modified": NOW, "name": a})
            for fw in fw_of(r):
                uses.add((a, fw))
    objects += actors.values()
    for a, fw in sorted(uses):
        name = actors[a]["name"]
        objects.append({"type": "relationship", "spec_version": "2.1", "id": sid_for("relationship", name + "-uses-" + fw),
                        "created": NOW, "modified": NOW, "relationship_type": "uses", "source_ref": actors[a]["id"], "target_ref": tools[fw]["id"]})
    for r in rows:
        pat = stix_pattern(r)
        if not pat:
            continue
        ind = {"type": "indicator", "spec_version": "2.1", "id": sid_for("indicator", r["type"] + r["value"]),
               "created": NOW, "modified": NOW, "created_by_ref": identity["id"],
               "name": f"{' and '.join(FRAMEWORKS[f]['name'] for f in fw_of(r))} {r['type']}: {r['value']}", "description": f"{r['context']}. Reported by {r['source']}.",
               "indicator_types": ["malicious-activity"] if r["confidence"] != "low" else ["anomalous-activity"],
               "pattern": pat, "pattern_type": "stix", "valid_from": f"{r['reported']}T00:00:00Z",
               "confidence": {"high": 85, "medium": 60, "low": 30}[r["confidence"]],
               "labels": fw_of(r) + [r["confidence"]],
               "external_references": [{"source_name": r["source"], "url": r["source_url"]}]}
        if r.get("review_by"):
            ind["valid_until"] = f"{r['review_by']}T00:00:00Z"
        objects.append(ind)
        targets = [actors[r["actor"]]] if r["actor"] in actors else [tools[f] for f in fw_of(r)]
        for target in targets:
            objects.append({"type": "relationship", "spec_version": "2.1", "id": sid_for("relationship", ind["id"] + target["id"]),
                            "created": NOW, "modified": NOW, "relationship_type": "indicates", "source_ref": ind["id"], "target_ref": target["id"]})
    digest = hashlib.sha256(json.dumps(objects, sort_keys=True).encode()).hexdigest()
    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid5(NS, digest)}", "objects": objects}
    write(ROOT / "feeds" / "stix2.1-bundle.json", json.dumps(bundle, indent=1, ensure_ascii=False) + "\n")
    return sum(1 for o in objects if o["type"] == "indicator")


def main():
    rows = load()
    seen = set()
    for r in rows:
        key = (r["type"], r["value"])
        if key in seen:
            raise SystemExit(f"duplicate indicator {key}")
        seen.add(key)
        if r["confidence"] not in ("high", "medium", "low"):
            raise SystemExit(f"bad confidence for {key}")
        dt.date.fromisoformat(r["reported"])
        bad = [f for f in fw_of(r) if f not in FRAMEWORKS]
        if not fw_of(r) or bad:
            raise SystemExit(f"unknown or missing framework for {key}: {r.get('framework')!r}")
    cols = ["value", "type", "confidence", "context", "actor", "source", "source_url", "reported", "review_by", "framework"]
    plain_lists(rows, ROOT / "feeds")
    table_csv(rows, ROOT / "feeds" / "sentinel-watchlist.csv", cols)
    for fw in FRAMEWORKS:
        sub = only(rows, fw)
        plain_lists(sub, ROOT / "feeds" / "by-framework" / fw)
        zeek_intel(sub, fw)
        suricata_ip(sub, fw)
    table_csv(only(rows, "artex"), ROOT / "frameworks" / "artex" / "splunk" / "lookups" / "artex_iocs.csv", cols[:-1])
    n = stix(rows)
    print(f"{len(rows)} indicators, {n} STIX indicators, feeds written")


if __name__ == "__main__":
    main()
