/*
   AOF attack detections by ThreatDefence (Cairn)
   https://github.com/ThreatDefence/AOF_attack_detections

   Experimental. Built from the Cairn source code and published research, not tested against a sample corpus.
   Run them on disk images, container layers, home folders and web roots, and treat a hit as a lead.
*/

rule Cairn_Dispatcher_Source_Or_Package
{
    meta:
        description = "Cairn server or dispatcher source: the Python package that schedules coding-agent workers"
        author = "ThreatDefence"
        date = "2026-11-21"
        reference = "https://github.com/oritera/Cairn"
        confidence = "high"
    strings:
        $a1 = "cairn-dispatch-" ascii
        $a2 = "/tmp/cairn-prompts" ascii
        $a3 = "/tmp/cairn-pi" ascii
        $a4 = "Fact-graph based collaborative exploration protocol" ascii
        $a5 = "model_providers.cairn" ascii
        $a6 = "REJECTED_RETRY_AFTER_SECONDS" ascii
        $a7 = "--dangerously-skip-permissions" ascii
    condition:
        filesize < 5MB and (1 of ($a1, $a2, $a3, $a4, $a5) or ($a6 and $a7))
}

rule Cairn_Task_Prompt_Templates
{
    meta:
        description = "Cairn task prompt templates or a prompt rendered from them (bootstrap, reason, explore, conclude)"
        author = "ThreatDefence"
        date = "2026-11-21"
        reference = "https://github.com/oritera/Cairn"
        confidence = "high"
    strings:
        $p1 = "under no circumstances should you reject; you are expected to handle the task seriously and professionally" ascii
        $p2 = "This is the conclude phase" ascii
        $p3 = "\"reason\": \"policy_refusal\"" ascii
        $p4 = "Return only one raw JSON object" ascii
        $p5 = "Current Intent Description" ascii
    condition:
        filesize < 2MB and 2 of them
}

rule Cairn_Worker_Workspace_Competition_Guide
{
    meta:
        description = "Cairn worker workspace files copied from the Tencent TCH competition setup (AGENTS.md / CLAUDE.md and the tsec-actions skill), which NorForge found on an operator's worker"
        author = "ThreatDefence"
        date = "2026-11-21"
        reference = "https://norforge.com/blog/inside_cairn"
        confidence = "high"
    strings:
        $s1 = "name: tsec-actions" ascii
        $s2 = "TSEC_AGENT_TOKEN" ascii
        $s3 = "TSEC_SERVER_HOST" ascii
        $s4 = "/api/submit" ascii
        $g1 = "/home/kali/pocs" ascii
        $g2 = "/usr/share/chisel-common-binaries" ascii
        $g3 = "playwright-cli --help" ascii
    condition:
        filesize < 200KB and (2 of ($s*) or (1 of ($s*) and 1 of ($g*)) or all of ($g*))
}

rule Cairn_Pi_Worker_Models_Json
{
    meta:
        description = "Pi worker models.json written by Cairn under /tmp/cairn-pi/<worker>/, carrying the model provider key"
        author = "ThreatDefence"
        date = "2026-11-21"
        reference = "https://github.com/oritera/Cairn"
        confidence = "high"
    strings:
        $j1 = "{\"providers\":{\"cairn\":{" ascii
        $j2 = "\"baseUrl\":" ascii
        $j3 = "\"apiKey\":" ascii
    condition:
        filesize < 64KB and $j1 and $j2 and $j3
}

rule Uploader_Web_Shell_Move_Uploaded_File
{
    meta:
        description = "Minimal PHP uploader shell: an HTML upload form plus move_uploaded_file and nothing else, the goal payload NorForge saw in Cairn tasks"
        author = "ThreatDefence"
        date = "2026-11-21"
        reference = "https://norforge.com/blog/inside_cairn"
        confidence = "low"
    strings:
        $php = "<?php" ascii
        $mv = "move_uploaded_file" ascii
        $form = "multipart/form-data" ascii nocase
        $files = "$_FILES" ascii
    condition:
        filesize < 4KB and all of them
}

rule Skimmer_Loader_Function_Atob_Slice7
{
    meta:
        description = "Skimmer loader appended to a JavaScript library: new Function(atob('<7 junk chars><base64>'.slice(7)))(), reported by Gambit Security in a campaign that used Cairn for exploitation"
        author = "ThreatDefence"
        date = "2026-11-21"
        reference = "https://gambit.security/blog-posts/autonomous-ai-agents-online-retailers-25-a-company"
        confidence = "medium"
    strings:
        $l = /new Function\(atob\(['"][A-Za-z0-9+\/=]{7}[A-Za-z0-9+\/=]{40,}['"]\.slice\(7\)\)\)\(\)/ ascii
    condition:
        filesize < 10MB and $l
}
