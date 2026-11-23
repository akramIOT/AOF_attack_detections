#!/usr/bin/env bash
# Run the agentic-behaviors Zeek package against behaviors-sample.pcap and check that every notice fires.
# The pcap uses documentation ranges (198.18/15, 198.51.100/24, 203.0.113/24) as outside addresses, so private
# ranges are not treated as local here; 10.0.0.0/8 is the site.
set -euo pipefail
cd "$(dirname "$0")"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
(cd "$work" && zeek -C -r "$OLDPWD/behaviors-sample.pcap" "$OLDPWD/../agentic-behaviors" -e \
    'redef Site::private_address_space_is_local = F; redef Site::local_nets += { 10.0.0.0/8 };' >/dev/null)
fail=0
for n in Model_API_From_Server AI_Agent_Attacking_Site Rotating_Proxy_Probing Backup_File_Served Backup_Path_Sweep \
         WSUS_Admin_From_Internet WSUS_Port_From_Internet Kerberos_Enumeration SMB_WinRM_Fan_Out Callback_To_Prober Out_Of_Band_Lookup \
         Model_API_Failover Canary_Token_Lookup; do
    if grep -q "AgenticBehaviors::$n" "$work/notice.log" 2>/dev/null; then echo "notice: $n"; else echo "MISSING: $n"; fail=1; fi
done
# The benign visitor and the www.example.com call must not raise anything.
if grep -E "198\.51\.100\.(99|100)|203\.0\.113\.21|example\.org" "$work/notice.log" >/dev/null 2>&1; then echo "UNEXPECTED: benign traffic raised a notice"; fail=1; fi
# Both model API hosts must be seen, including the DashScope subdomain.
grep -q "coding.dashscope.aliyuncs.com" "$work/notice.log" || { echo "MISSING: DashScope subdomain"; fail=1; }
[ $fail -eq 0 ] && echo PASS || { echo FAIL; exit 1; }
