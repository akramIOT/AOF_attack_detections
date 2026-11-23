/*
   AOF attack detections by ThreatDefence: Strix
   https://github.com/ThreatDefence/AOF_attack_detections

   Experimental. Built from the Strix source code (usestrix/strix at a1ccf777), tested against the Strix source tree.
*/

rule Strix_Package
{
    meta:
        description = "Strix AI pentest agent package files (pip strix-agent), or a fork that keeps its strings"
        author = "ThreatDefence"
        date = "2026-11-21"
        reference = "https://github.com/usestrix/strix"
        confidence = "high"
    strings:
        $s1 = "strix.gateway.scarf.sh" ascii
        $s2 = "phc_7rO3XRuNT5sgSKAl6HDIrWdSGh1COzxw0vxVIAR6vVZ" ascii
        $s3 = "usestrix/strix-sandbox" ascii
        $s4 = "strix-run-id" ascii
        $s5 = "You are an advanced AI application security validation agent" ascii
        $s6 = "strix_runs" ascii
        $s7 = "STRIX_LLM" ascii
    condition:
        filesize < 5MB and 2 of them
}

rule Strix_Sandbox_Entrypoint
{
    meta:
        description = "Entrypoint of the Strix sandbox container: Caido proxy with guest access and system-wide proxy settings"
        author = "ThreatDefence"
        date = "2026-11-21"
        reference = "https://github.com/usestrix/strix/blob/main/containers/docker-entrypoint.sh"
        confidence = "high"
    strings:
        $c = "caido-cli --listen 0.0.0.0:${CAIDO_PORT}" ascii
        $g = "--allow-guests" ascii
        $p = "CAIDO_PORT=48080" ascii
        $s = "STRIX_HOST_UID" ascii
    condition:
        filesize < 256KB and $c and $g and ($p or $s)
}

rule Strix_Run_Record
{
    meta:
        description = "Strix run record run.json from a strix_runs/<run>/ folder (keys written by strix/report/state.py)"
        author = "ThreatDefence"
        date = "2026-11-21"
        reference = "https://github.com/usestrix/strix"
        confidence = "medium"
    strings:
        $k1 = "\"run_id\"" ascii
        $k2 = "\"run_name\"" ascii
        $k3 = "\"targets_info\"" ascii
        $k4 = "\"llm_usage\"" ascii
        $k5 = "\"auth_mode\"" ascii
    condition:
        filesize < 5MB and uint8(0) == 0x7b and all of them
}
