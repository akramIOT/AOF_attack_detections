# Coverage

| Behavior | Data source | Sigma | Sentinel / Defender | Suricata | Zeek | YARA |
|---|---|---|---|---|---|---|
| Published PentAGI addresses and consoles | Network, DNS, proxy, sign-in, web | | N, I | N, I | I | |
| Agent command wrapper and worker containers | EDR | S | N | | | Y |
| Worker ports published in 28000 to 29999 | EDR | | N | | | |
| Update check to update.pentagi.com | DNS, proxy, EDR, TLS | S | N | N | I | |
| PentAGI console certificate, title and Swagger page | TLS, web | | | N | | |
| PentAGI console use through a proxy | Proxy | S | N | | | |
| Every page fetched twice at once | Web, WAF | | N | | | |
| Callbacks from your servers to the probing address or the worker ports | EDR, web | | N (`behaviors/`) | N | | |
| PentAGI prompts in model requests | Decrypted traffic, AI gateway | | | N | | Y |
