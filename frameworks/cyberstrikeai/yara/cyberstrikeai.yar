/*
   AOF attack detections by ThreatDefence: CyberStrikeAI
   https://github.com/ThreatDefence/AOF_attack_detections

   Experimental. Built from the CyberStrikeAI source code (AIPentest/CyberStrikeAI at af6cf750). The implant rule was
   tested against Windows, Linux and macOS implants compiled from the stock template the way the console builds them
   (go build -ldflags "-s -w -buildid=" -trimpath), and the other rules against the CyberStrikeAI source tree.
*/

rule CyberStrikeAI_Implant
{
    meta:
        description = "Go implant built by the CyberStrikeAI console from its beacon template"
        author = "ThreatDefence"
        date = "2026-11-21"
        reference = "https://securelist.com/cyberstrikeai-attacks/121715/"
        confidence = "high"
    strings:
        // Go build information: the builder compiles inside the console's own module (Kaspersky saw it on every payload)
        $path = "cyberstrike-ai/tmp/c2/payloads/build-" ascii
        $h1 = "X-Implant-Token" ascii
        $h2 = "X-Session-Token" ascii
        $p1 = "persistence installed via" ascii
        $p2 = "com.apple.systemupdate" ascii
        $p3 = "@reboot %s &" ascii
        $p4 = ") # cs" ascii
        $p5 = "SystemUpdate" ascii
        $t1 = "http_beacon" ascii
        $t2 = "tcp_beacon" ascii
    condition:
        (uint16(0) == 0x5a4d or uint32(0) == 0x464c457f or uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe)
        and filesize < 30MB
        and ($path or ($h1 and $h2 and $p1 and 1 of ($p2, $p3, $p4, $p5) and 1 of ($t*)))
}

rule CyberStrikeAI_Console
{
    meta:
        description = "CyberStrikeAI console binary or source, or a fork that keeps its strings"
        author = "ThreatDefence"
        date = "2026-11-21"
        reference = "https://github.com/AIPentest/CyberStrikeAI"
        confidence = "high"
    strings:
        $s1 = "CyberStrikeAI-WebShell/1.0" ascii
        $s2 = ":OSPROBE_%OS%:END" ascii
        $s3 = "beacon.go.tmpl" ascii
        $s4 = "CyberStrikeAI/1.7" ascii
        $s5 = "X-Implant-Token" ascii
        $s6 = "tcpBeaconMagic" ascii
        $s7 = "disguisedReject" ascii
    condition:
        filesize < 200MB and 2 of them
}

rule CyberStrikeAI_Curl_Beacon_Script
{
    meta:
        description = "CyberStrikeAI curl_beacon one-liner saved to a script, shell history or cron file"
        author = "ThreatDefence"
        date = "2026-11-21"
        reference = "https://github.com/AIPentest/CyberStrikeAI"
        confidence = "high"
    strings:
        $h = "X-Implant-Token: " ascii
        $c = "/check_in" ascii
        $t = "/tasks?session_id=" ascii
        $r = "od -An -N32 -tx1 /dev/urandom" ascii
    condition:
        filesize < 1MB and $h and $c and ($t or $r)
}

rule CyberStrikeAI_Persistence_Artifacts
{
    meta:
        description = "Persistence the CyberStrikeAI implant writes: a .bashrc line ending in # cs, or the com.apple.systemupdate LaunchAgent"
        author = "ThreatDefence"
        date = "2026-11-21"
        reference = "https://github.com/AIPentest/CyberStrikeAI"
        confidence = "medium"
    strings:
        $bashrc = /\(nohup [^\n]{1,512} &>\/dev\/null &\) # cs/ ascii
        $label = "<string>com.apple.systemupdate</string>" ascii
        $keep = "<key>KeepAlive</key><true/>" ascii
    condition:
        filesize < 1MB and ($bashrc or ($label and $keep))
}
