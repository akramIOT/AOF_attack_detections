##! An AI agent's page reader on your application next to attack traffic from the same address (behaviors hunt 03)
##!
##! Agent CLIs read pages with their own fetch tools and attack through curl, Python and Kali tools in their shell:
##! Qwen Code ("QwenCode/<version> (<os>; <arch>)"), Kimi CLI ("KimiCLI/<version>"), opencode
##! ("opencode/<channel>/<version>/<name>") and Claude Code ("Claude-User (claude-code/<version>; ...)", which Cairn's
##! workers run with DeepSeek behind it). A reader hit alone means little: ordinary users send the same strings. The
##! same address sending reader requests and tool traffic or payloads to one host within the window is an AI agent
##! attacking that host.

@load base/protocols/http
@load ./main

module AgenticBehaviors;

export {
    redef enum Notice::Type += {
        ## One address sent AI agent page reads and attack tool traffic or payloads to the same host.
        AI_Agent_Attacking_Site,
    };

    ## User agents of AI agent page readers and search tools.
    const agent_reader_user_agents: pattern =
        /Claude-User \(claude-code\// | /^QwenCode\// | /^KimiCLI\// | /^opencode\// &redef;

    ## How long a page read or an attack request is remembered for pairing.
    const page_reader_window: interval = 2hr &redef;
}

type ReaderState: record {
    reader: bool &default=F;
    attack: bool &default=F;
    sample: string &default="";
};

global reader_state: table[addr, string] of ReaderState &create_expire=page_reader_window;

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
    {
    if ( ! is_orig || ! c?$http )
        return;
    local ua = c$http?$user_agent ? c$http$user_agent : "";
    local host = c$http?$host ? c$http$host : cat(c$id$resp_h);
    local uri = c$http?$uri ? c$http$uri : "";
    local src = c$id$orig_h;

    if ( [src, host] !in reader_state )
        reader_state[src, host] = ReaderState();
    local st = reader_state[src, host];

    if ( agent_reader_user_agents in ua )
        st$reader = T;
    else if ( tool_user_agents in ua || payload_uri in uri )
        {
        st$attack = T;
        if ( st$sample == "" )
            st$sample = fmt("%s %s", ua, uri);
        }

    if ( st$reader && st$attack )
        raise(c, AI_Agent_Attacking_Site,
              fmt("%s read %s with an AI agent's page reader and sent attack traffic", src, host),
              st$sample, cat(src, host));
    }
