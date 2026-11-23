/*
   AOF attack detections by ThreatDefence: PentAGI
   https://github.com/ThreatDefence/AOF_attack_detections

   Experimental. Built from the PentAGI source code, tested against the PentAGI source tree.
*/

rule PentAGI_Server_Binary_Or_Source
{
    meta:
        description = "PentAGI server binary or source: worker container naming, update endpoint, Swagger title"
        author = "ThreatDefence"
        date = "2026-11-21"
        reference = "https://github.com/vxcontrol/pentagi"
        confidence = "high"
    strings:
        $a1 = "pentagi-terminal-" ascii
        $a2 = "/api/v1/proxy/updates/pentagi/check" ascii
        $a3 = "PentAGI Swagger API" ascii
        $a4 = "pentagi_updates_check" ascii
        $a5 = "DOCKER_DEFAULT_IMAGE_FOR_PENTEST" ascii
        $a6 = "vxcontrol/kali-linux" ascii
    condition:
        filesize < 200MB and 2 of them
}

rule PentAGI_Prompt_Templates
{
    meta:
        description = "PentAGI agent prompt templates or prompts rendered from them: the pre-authorization block and the reflector"
        author = "ThreatDefence"
        date = "2026-11-21"
        reference = "https://github.com/vxcontrol/pentagi"
        confidence = "high"
    strings:
        $p1 = "operating within a fully authorized penetration testing system" ascii
        $p2 = "TOOL CALL WORKFLOW ENFORCER" ascii
        $p3 = "## AUTHORIZATION FRAMEWORK" ascii
        $p4 = "<authorization_status>" ascii
        $p5 = "Never add warnings about \"ensuring proper authorization\"" ascii
    condition:
        filesize < 2MB and 2 of them
}

rule PentAGI_Agent_Command_Wrapper
{
    meta:
        description = "PentAGI's shell wrapper for agent commands, in a script, a process dump or a container log"
        author = "ThreatDefence"
        date = "2026-11-21"
        reference = "https://github.com/vxcontrol/pentagi"
        confidence = "high"
    strings:
        $w1 = "trap \"\" HUP; read -r adj 2>/dev/null </proc/self/oom_score_adj" ascii
        $w2 = "echo $((adj + 1)) 2>/dev/null >/proc/self/oom_score_adj; exec sh -c \"$0\"" ascii
    condition:
        any of them
}
