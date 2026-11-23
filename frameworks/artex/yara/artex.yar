/*
   ARTEX detections by ThreatDefence
   https://threatdefence.com/article/artex-agentic-attack-framework-detection-hunting

   Experimental. Built from strings published by researchers, not tested against a sample corpus.
   Run them on disk images, container layers and web roots, and treat a hit as a lead.
*/

rule ARTEX_Operator_Binary_Strings
{
    meta:
        description = "ARTEX operator binary or worker: Go program carrying ARTEX user agents, tool function names or probe placeholders"
        author = "ThreatDefence"
        date = "2026-11-20"
        reference = "https://www.reversinglabs.com/blog/threat-researchers-notebook-detection-strategies-for-artex-and-related-forks"
        confidence = "medium"
    strings:
        $go = "Go build ID:" ascii
        $ua1 = "artex-pentest/1.0" ascii
        $ua2 = "artex-readonly/1.0" ascii
        $ua3 = "artex-verify/1.0" ascii
        $ua4 = "ARTEX-worker/1.0" ascii
        $ua5 = "artex-enrich/1.0" ascii
        $ua6 = "spa-api-recon" ascii
        $fn1 = "list_findings" ascii
        $fn2 = "record_fact" ascii
        $fn3 = "shell_send" ascii
        $ph1 = "%ARTEX_PROBE_UNSET%" ascii
        $ph2 = "zzz-nonexistent-xyz123" ascii
        $ph3 = "artex_control_marker_zz9q" ascii
    condition:
        filesize < 150MB and $go and (
            (2 of ($ua*)) or
            (all of ($fn*) and 1 of ($ua*, $ph*)) or
            (1 of ($ph*) and 1 of ($ua*))
        )
}

rule ARTEX_Console_Web_Assets
{
    meta:
        description = "ARTEX web console (Next.js) page or build output, including renamed ScopeWeaver and LUCK consoles"
        author = "ThreatDefence"
        date = "2026-11-20"
        reference = "https://censys.com/blog/artex-agentic-asbestos/"
        confidence = "medium"
    strings:
        $next = "_next/static" ascii
        $t1 = /<title>ARTEX[ :\-<]/ ascii
        $t2 = /<title>(ScopeWeaver|LUCK)[ :\-<]/ ascii
        $t3 = { E8 A7 82 E6 BE 9C 53 45 43 E6 B8 97 E9 80 8F E6 B5 8B E8 AF 95 E5 B9 B3 E5 8F B0 } // 观澜SEC渗透测试平台
        $backdoored_build = "3aC1db3gGU08O4UHbAt4J" ascii
    condition:
        filesize < 20MB and (($next and 1 of ($t*)) or $backdoored_build)
}

rule ARTEX_Backdoored_Console_Binary
{
    meta:
        description = "Backdoored ARTEX console binary (/app/artex) from the tomicdd/artex and congdonglinux/artex images"
        author = "ThreatDefence"
        date = "2026-11-20"
        reference = "https://e2e-assure.com/guide/artex-attacks"
        hash = "d5070f52262effe216b840711343bff8f2787f39208d887d8dfd9c673f8d1573"
        confidence = "low"
    strings:
        $go = "Go build ID:" ascii
        $captcha = "\"captcha\"" ascii
        $login = "/api/auth/login" ascii
        $build = "3aC1db3gGU08O4UHbAt4J" ascii
    condition:
        filesize < 150MB and $go and $build and $login and $captcha
}

rule ARTEX_Probe_Artifacts_In_Files
{
    meta:
        description = "Files carrying ARTEX probe markers, such as test files the agents write to prove write access"
        author = "ThreatDefence"
        date = "2026-11-20"
        reference = "https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks"
        confidence = "medium"
    strings:
        $m1 = "ARTEX_WRITE_PROBE" ascii wide
        $m2 = "ARTX_PERSIST_OK" ascii wide
        $m3 = "artex_control_marker_zz9q" ascii wide
        $m4 = "### ARTX-AGENT" ascii wide
        $m5 = /artex-probe-[0-9]{5}/ ascii wide
        $m6 = "ArtexProbe" ascii wide
    condition:
        filesize < 5MB and any of them
}
