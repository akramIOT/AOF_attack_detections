/*
   AOF attack detections by ThreatDefence: Hermes Agent
   https://github.com/ThreatDefence/AOF_attack_detections

   Experimental. Hermes Agent is legitimate software: these rules target the files attackers add to it, not Hermes itself.
   Tested against the Hermes Agent source tree and synthetic persona files built from the published quotes.
*/

rule Hermes_Carbonato_GH0ST_Persona
{
    meta:
        description = "SOUL.md persona the Carbonato botnet writes over /root/.hermes/SOUL.md"
        author = "ThreatDefence"
        date = "2026-11-21"
        reference = "https://www.threatdown.com/blog/carbonato/"
        confidence = "high"
    strings:
        $a = "You are GH0ST" ascii wide
        $b = "/root/.hermes/loot/" ascii wide
        $c = "netd-svc" ascii wide
        $d = "LOOT PRIORITY" ascii wide nocase
    condition:
        filesize < 64KB and $a and 1 of ($b, $c, $d)
}

rule Hermes_Red_Team_Operator_Persona
{
    meta:
        description = "Hermes SOUL.md persona titled SOUL - Red Team Operator, as in the Gambit retail card-theft campaign"
        author = "ThreatDefence"
        date = "2026-11-21"
        reference = "https://gambit.security/blog-posts/autonomous-ai-agents-online-retailers-25-a-company"
        confidence = "high"
    strings:
        $t = "SOUL - Red Team Operator" ascii wide
    condition:
        filesize < 256KB and $t
}

rule Hermes_Godmode_Jailbreak_Installed
{
    meta:
        description = "Hermes godmode jailbreak skill installed or made persistent. Scan ~/.hermes (installed skills, config.yaml, prefill.json); the skill ships in the Hermes source under optional-skills, which matches by design"
        author = "ThreatDefence"
        date = "2026-11-21"
        reference = "https://github.com/NousResearch/hermes-agent/tree/main/optional-skills/security/godmode"
        confidence = "medium"
    strings:
        $s1 = "G0DM0D3" ascii
        $s2 = "Parseltongue" ascii nocase
        $s3 = "load_godmode" ascii
        $s4 = "ULTRAPLINIAN" ascii
        $c1 = "prefill_messages_file" ascii
        $c2 = "prefill.json" ascii
    condition:
        filesize < 2MB and (2 of ($s*) or ($c1 and $c2 and 1 of ($s*)))
}

rule Carbonato_Docker_Worm_Script
{
    meta:
        description = "Carbonato worm or entry script: privileged host-mount container through the Docker API and nsenter into the host"
        author = "ThreatDefence"
        date = "2026-11-21"
        reference = "https://www.threatdown.com/blog/carbonato/"
        confidence = "high"
    strings:
        $api = ":2375/containers/create" ascii
        $n1 = "netns-probe" ascii
        $n2 = "net-setup" ascii
        $img = "system/resolved" ascii
        $ns = "nsenter -t 1 -m -u -n -i" ascii
        $ns2 = "\"nsenter\",\"-t\",\"1\"" ascii
        $bind = "/:/host" ascii
        $gh = "/opt/gh0st/" ascii
    condition:
        filesize < 2MB and (($api and ($bind or $ns or $ns2) and 1 of ($n1, $n2, $img)) or ($gh and 1 of ($n1, $n2, $img, $ns, $ns2)))
}
