#!/usr/bin/env python3
"""Write tests/artex-sample.pcap: synthetic ARTEX-style traffic plus benign traffic for the Zeek and Suricata tests.

    pip install scapy && python3 tests/make_pcap.py
"""
from pathlib import Path
from scapy.all import IP, TCP, UDP, DNS, DNSQR, Ether, wrpcap

pkts = []
t = [1795000000.0]


def stamp(p):
    t[0] += 0.01
    p.time = t[0]
    return p


def session(cli, srv, sport, dport, request, response):
    e = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    er = Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
    c, s = 1000, 5000
    pkts.append(stamp(e / IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="S", seq=c)))
    pkts.append(stamp(er / IP(src=srv, dst=cli) / TCP(sport=dport, dport=sport, flags="SA", seq=s, ack=c + 1)))
    pkts.append(stamp(e / IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="A", seq=c + 1, ack=s + 1)))
    pkts.append(stamp(e / IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="PA", seq=c + 1, ack=s + 1) / request))
    c2 = c + 1 + len(request)
    pkts.append(stamp(er / IP(src=srv, dst=cli) / TCP(sport=dport, dport=sport, flags="PA", seq=s + 1, ack=c2) / response))
    s2 = s + 1 + len(response)
    pkts.append(stamp(e / IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="FA", seq=c2, ack=s2)))
    pkts.append(stamp(er / IP(src=srv, dst=cli) / TCP(sport=dport, dport=sport, flags="FA", seq=s2, ack=c2 + 1)))
    pkts.append(stamp(e / IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="A", seq=c2 + 1, ack=s2 + 1)))


def req(path, ua, extra=""):
    return (f"GET {path} HTTP/1.1\r\nHost: app.example.test\r\nUser-Agent: {ua}\r\n{extra}Accept: */*\r\n\r\n").encode()


def resp(body, ctype="text/html", status="404 Not Found", extra=""):
    b = body.encode()
    return (f"HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {len(b)}\r\n{extra}\r\n").encode() + b


ATT, WEB, CONSOLE = "203.0.113.10", "10.0.0.5", "10.0.0.9"
session(ATT, WEB, 40001, 80, req("/zzz-nonexistent-xyz123", "artex-pentest/1.0", "X-ARTX-KEY: k1\r\n"), resp("not found"))
session(ATT, WEB, 40002, 80, req("/sso/login?jwt=eyJhbGciOiJub25lIn0.eyJlbWFpbCI6InRlc3RAdGVzdC5jb20ifQ.", "python-requests/2.31.0"), resp("denied", status="401 Unauthorized"))
session(ATT, WEB, 40003, 80, req("/auth/callback?code=AAAA&state=notvalidb64!!", "Mozilla/5.0 (spa-api-recon)"), resp("bad state", status="400 Bad Request"))
session("10.0.0.20", CONSOLE, 40004, 8787, req("/", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
        resp('<html><head><title>ARTEX - Agentic Pentest</title><script src="/_next/static/chunks/main.js"></script></head></html>', status="200 OK"))
session("198.51.100.7", WEB, 40005, 80, req("/", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36"),
        resp("<html><head><title>Home</title></head></html>", status="200 OK"))
session("10.0.0.30", "172.86.84.226", 40006, 88,
        b"GET /test/winlogon.exe HTTP/1.1\r\nHost: ftp.vietnam852.com:88\r\nUser-Agent: Microsoft-WinINet\r\nAccept: */*\r\n\r\n",
        resp("MZ", ctype="application/octet-stream", status="200 OK"))
for name, sport in [("ftp.vietnam852.com", 53005), ("nginxmysql.com", 53001), ("x1.webhook.site", 53002), ("artx9f.abc.dnslog.cn", 53003), ("www.example.com", 53004)]:
    pkts.append(stamp(Ether() / IP(src=WEB, dst="10.0.0.53") / UDP(sport=sport, dport=53) / DNS(id=sport, rd=1, qd=DNSQR(qname=name))))

out = Path(__file__).with_name("artex-sample.pcap")
wrpcap(str(out), pkts)
print(f"wrote {out} ({len(pkts)} packets)")
