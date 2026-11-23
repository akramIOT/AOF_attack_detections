# Suricata

- `artex.rules`: user agents, probe artifacts, console pages and C2 domains (SIDs 9726001 to 9726199).
- `artex-ip.rules`: generated from `iocs/indicators.csv` by `tools/build_feeds.py` (SIDs from 9726500). Addresses are reassigned, so review them against the `review_by` dates in the CSV.

Tested with `suricata -T` on Suricata 7. HTTP rules need cleartext HTTP or decrypted traffic. Snort users can also use Cisco Talos coverage: ARTEX SIDs 1:67494 to 1:67496 (Snort 2) and 7:76 to 7:78 (Snort 3).
