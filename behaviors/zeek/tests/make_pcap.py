#!/usr/bin/env python3
"""Write behaviors-sample.pcap: synthetic traffic for every check in agentic-behaviors, plus benign traffic.

    pip install scapy && python3 make_pcap.py
"""
import os
import struct
from pathlib import Path
from scapy.all import IP, TCP, UDP, DNS, DNSQR, Ether, wrpcap
from scapy.layers.kerberos import (Kerberos, KRB_AS_REQ, KRB_KDC_REQ_BODY, KRB_ERROR, PrincipalName,
                                   ASN1_GENERAL_STRING, ASN1_GENERALIZED_TIME, ASN1_INTEGER)

pkts = []
t = [1795000000.0]


def stamp(p):
    t[0] += 0.01
    p.time = t[0]
    return p


def session(cli, srv, sport, dport, request=b"", response=b""):
    e, er = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02"), Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
    c, s = 1000, 5000
    pkts.append(stamp(e / IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="S", seq=c)))
    pkts.append(stamp(er / IP(src=srv, dst=cli) / TCP(sport=dport, dport=sport, flags="SA", seq=s, ack=c + 1)))
    pkts.append(stamp(e / IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="A", seq=c + 1, ack=s + 1)))
    c2, s2 = c + 1, s + 1
    if request:
        pkts.append(stamp(e / IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="PA", seq=c2, ack=s2) / request))
        c2 += len(request)
    if response:
        pkts.append(stamp(er / IP(src=srv, dst=cli) / TCP(sport=dport, dport=sport, flags="PA", seq=s2, ack=c2) / response))
        s2 += len(response)
    pkts.append(stamp(e / IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="FA", seq=c2, ack=s2)))
    pkts.append(stamp(er / IP(src=srv, dst=cli) / TCP(sport=dport, dport=sport, flags="FA", seq=s2, ack=c2 + 1)))
    pkts.append(stamp(e / IP(src=cli, dst=srv) / TCP(sport=sport, dport=dport, flags="A", seq=c2 + 1, ack=s2 + 1)))


def req(path, ua, host="app.example.test"):
    return f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\nAccept: */*\r\n\r\n".encode()


def resp(body="x", status="404 Not Found"):
    return f"HTTP/1.1 {status}\r\nContent-Type: text/html\r\nContent-Length: {len(body)}\r\n\r\n{body}".encode()


def client_hello(sni):
    name = sni.encode()
    sni_ext = struct.pack(">HHHBH", 0, len(name) + 5, len(name) + 3, 0, len(name)) + name
    body = b"\x03\x03" + os.urandom(32) + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + struct.pack(">H", len(sni_ext)) + sni_ext
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


WEB, SRV = "10.0.0.5", "10.0.0.5"
port = [40000]


def nxt():
    port[0] += 1
    return port[0]


# 1. Model APIs from a server (Model_API_From_Server): DeepSeek, and Qwen on a DashScope subdomain
session(SRV, "198.51.100.80", nxt(), 443, client_hello("api.deepseek.com"))
session(SRV, "198.51.100.81", nxt(), 443, client_hello("coding.dashscope.aliyuncs.com"))
# 2. Qwen Code page reader plus attack traffic from one address (AI_Agent_Attacking_Site)
session("203.0.113.20", WEB, nxt(), 80, req("/products", "QwenCode/0.6.1 (linux; x64)"), resp("ok", "200 OK"))
session("203.0.113.20", WEB, nxt(), 80, req("/download?f=../../etc/passwd", "curl/8.5.0"), resp())
# A Claude Code reader alone, with no attack traffic (nothing expected)
session("203.0.113.21", WEB, nxt(), 80, req("/docs", "Claude-User (claude-code/2.1.98; +https://support.anthropic.com/)"), resp("ok", "200 OK"))
# 3. Rotating proxies: 60 addresses, two login requests each (Rotating_Proxy_Probing)
for i in range(60):
    for _ in range(2):
        session(f"198.18.{i // 200}.{i % 200 + 1}", WEB, nxt(), 80, req("/wp-login.php", "Mozilla/5.0", "shop.example.test"), resp())
# 4. Backup sweep with one file served, WSUS admin API and WSUS port (Backup_File_Served, Backup_Path_Sweep, WSUS_*)
for p in ["/.git/HEAD", "/.env.bak", "/backup.zip", "/db_backup.sql", "/dump.sql"]:
    session("203.0.113.30", WEB, nxt(), 80, req(p, "python-requests/2.31.0"), resp())
session("203.0.113.30", WEB, nxt(), 80, req("/.env", "python-requests/2.31.0"), resp("DB_PASSWORD=x", "200 OK"))
session("203.0.113.31", "10.0.0.6", nxt(), 8530, req("/ApiRemoting30/WebService.asmx", "Mozilla/5.0", "wsus.example.test"), resp())
# 5. Kerberos enumeration: 30 unknown names over UDP 88 (Kerberos_Enumeration)
for i in range(30):
    sp = nxt()
    name = PrincipalName(nameString=[ASN1_GENERAL_STRING(f"user{i:02d}")], nameType=ASN1_INTEGER(1))
    asreq = Kerberos(root=KRB_AS_REQ(reqBody=KRB_KDC_REQ_BODY(realm=ASN1_GENERAL_STRING("CORP.TEST"), cname=name,
            sname=PrincipalName(nameString=[ASN1_GENERAL_STRING("krbtgt"), ASN1_GENERAL_STRING("CORP.TEST")], nameType=ASN1_INTEGER(2)),
            till=ASN1_GENERALIZED_TIME("20370913024805Z"), nonce=ASN1_INTEGER(i + 1), etype=[ASN1_INTEGER(18)])))
    err = Kerberos(root=KRB_ERROR(errorCode=ASN1_INTEGER(6), stime=ASN1_GENERALIZED_TIME("20261121000000Z"), susec=ASN1_INTEGER(0),
            realm=ASN1_GENERAL_STRING("CORP.TEST"), cname=name, crealm=ASN1_GENERAL_STRING("CORP.TEST"),
            sname=PrincipalName(nameString=[ASN1_GENERAL_STRING("krbtgt"), ASN1_GENERAL_STRING("CORP.TEST")], nameType=ASN1_INTEGER(2))))
    pkts.append(stamp(Ether() / IP(src="10.0.0.66", dst="10.0.0.2") / UDP(sport=sp, dport=88) / asreq))
    pkts.append(stamp(Ether() / IP(src="10.0.0.2", dst="10.0.0.66") / UDP(sport=88, dport=sp) / err))
# 6. SMB fan-out to 12 hosts (SMB_WinRM_Fan_Out)
for i in range(12):
    session("10.0.0.66", f"10.0.1.{i + 10}", nxt(), 445)
# 7. Callback to the prober on a PentAGI worker port (Callback_To_Prober)
for _ in range(3):
    session("203.0.113.40", WEB, nxt(), 80, req("/", "Mozilla/5.0"), resp("ok", "200 OK"))
session(WEB, "203.0.113.40", nxt(), 28001, b"id\n")
# 8. A server looks up an interactsh name (Out_Of_Band_Lookup), a canary token (Canary_Token_Lookup), and an ordinary name
pkts.append(stamp(Ether() / IP(src=WEB, dst="10.0.0.53") / UDP(sport=nxt(), dport=53) / DNS(id=1, rd=1, qd=DNSQR(qname="c9k2xq7a1b3d.oast.fun"))))
pkts.append(stamp(Ether() / IP(src=WEB, dst="10.0.0.53") / UDP(sport=nxt(), dport=53) / DNS(id=3, rd=1, qd=DNSQR(qname="x7k2m9.canarytokens.com"))))
pkts.append(stamp(Ether() / IP(src=WEB, dst="10.0.0.53") / UDP(sport=nxt(), dport=53) / DNS(id=2, rd=1, qd=DNSQR(qname="www.example.org"))))
# Benign: an ordinary visitor and an ordinary outbound call (nothing expected)
session("198.51.100.99", WEB, nxt(), 80, req("/", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36"), resp("ok", "200 OK"))
session(WEB, "198.51.100.100", nxt(), 443, client_hello("www.example.com"))

out = Path(__file__).with_name("behaviors-sample.pcap")
wrpcap(str(out), pkts)
print(f"wrote {out} ({len(pkts)} packets)")
