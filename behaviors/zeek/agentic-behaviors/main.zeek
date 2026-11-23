##! AOF attack detections by ThreatDefence: behaviors shared by agentic attack frameworks
##! https://github.com/ThreatDefence/AOF_attack_detections
##!
##! Network versions of the cross-framework hunts in behaviors/sentinel/hunting. Each script raises a notice; tune the
##! exported sets and thresholds with redef in your local.zeek. HTTP checks need cleartext HTTP, so run Zeek behind TLS
##! decryption or inside a terminating proxy for HTTPS sites. TLS, Kerberos and connection checks work as they are.
##!
##! Load with:  @load ./agentic-behaviors   (from the folder that holds this directory)

@load base/frameworks/notice

module AgenticBehaviors;

export {
    ## Internal servers, container hosts and build agents. Leave empty to treat every address in Site::local_nets as one.
    const server_nets: set[subnet] = {} &redef;

    ## Developer subnets and approved AI gateways, ignored by the model API check.
    const allowed_ai_nets: set[subnet] = {} &redef;

    ## How long to suppress repeat notices for the same source and indicator.
    const suppress_for: interval = 1hr &redef;

    ## Request URIs that carry attack payloads (same expression as the KQL hunts).
    const payload_uri: pattern =
        /(?i:union(\s|\+|%20)+select)/ | /(?i:sleep\()/ | /(?i:extractvalue)/ | /\.\.\// | /(?i:%2e%2e)/ |
        /\/etc\/passwd/ | /(?i:<script|%3cscript)/ | /\$\{/ | /\{\{/ | /\/\.git\// | /\/\.env/ |
        /(?i:wp-config)/ | /(?i:phpinfo)/ &redef;

    ## Login, admin and payment paths agents aim for.
    const sensitive_uri: pattern =
        /(?i:\/(login|signin|admin|wp-admin|wp-login|api\/auth|user\/login|account|checkout|upload))/ &redef;

    ## User agents of the attack tools agents run through their shells.
    const tool_user_agents: pattern =
        /^curl\// | /^python-requests\// | /^Python-urllib\// | /sqlmap/ | /[Nn]uclei/ | /Fuzz Faster U Fool/ |
        /Nikto/ | /dirsearch/ | /WPScan/ | /katana/ | /dalfox/ | /HeadlessChrome/ &redef;
}

## True when an address is one of your servers (server_nets, or Site::local_nets when server_nets is empty).
function is_server(a: addr): bool
    {
    if ( |server_nets| == 0 )
        return Site::is_local_addr(a);
    return a in server_nets;
    }

function raise(c: connection, note: Notice::Type, msg: string, sub: string, key: string)
    {
    NOTICE([$note=note, $msg=msg, $sub=sub, $conn=c, $identifier=key, $suppress_for=suppress_for]);
    }
