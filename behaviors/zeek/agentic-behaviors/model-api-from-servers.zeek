##! AI model API traffic from servers (behaviors hunt 02)
##!
##! Every agentic attack framework needs a model, and the ones seen in real intrusions mostly use Chinese models and
##! gateways: CyberStrikeAI ships configured for Qwen on Alibaba DashScope, CyberStrikeAI and Cairn operators ran DeepSeek,
##! and GLM, Kimi, MiniMax, Doubao, SiliconFlow and OpenRouter are all one setting away. A server, container host or build
##! agent opening TLS to one of these is an AI agent running on it, whatever the client. Seen by TLS server name, so no
##! decryption is needed. Endpoints are taken from the provider lists in Qwen Code, Kimi CLI and opencode.
##! A second notice fires when one server reaches two or more of these APIs inside failover_window: operators fail
##! over to another provider when a key is banned. Set server_nets and allowed_ai_nets (main.zeek) with redef.

@load base/protocols/ssl
@load ./main

module AgenticBehaviors;

export {
    redef enum Notice::Type += {
        ## A server opened TLS to a model API or model gateway.
        Model_API_From_Server,
        ## One server opened TLS to two or more different model APIs inside the failover window.
        Model_API_Failover,
    };

    ## Chinese model APIs. A name matches itself and any subdomain.
    const china_model_hosts: set[string] = {
        "api.deepseek.com", "dashscope.aliyuncs.com", "dashscope-intl.aliyuncs.com", "dashscope-us.aliyuncs.com",
        "open.bigmodel.cn", "api.z.ai", "api.moonshot.cn", "api.moonshot.ai", "api.kimi.com", "code.kimi.com",
        "api.kimi.ai", "api.minimax.io", "api.minimax.cn", "api.minimaxi.com", "ark.cn-beijing.volces.com",
        "api.siliconflow.cn", "api.siliconflow.com", "api.stepfun.com", "api.stepfun.ai", "tokenhub.tencentmaas.com",
        "api.lkeap.cloud.tencent.com", "api.hunyuan.cloud.tencent.com", "qianfan.baidubce.com", "api.xiaomimimo.com",
        "api-inference.modelscope.cn",
    } &redef;

    ## Model gateways that resell many providers' models behind one key.
    const gateway_hosts: set[string] = {
        "openrouter.ai", "api.novita.ai", "zenmux.ai", "api.ofox.ai", "api.together.xyz", "api.groq.com", "api.tensorx.ai",
    } &redef;

    ## Other model APIs.
    const other_model_hosts: set[string] = {
        "api.openai.com", "api.anthropic.com", "generativelanguage.googleapis.com", "api.mistral.ai", "api.x.ai",
    } &redef;

    ## How long distinct model APIs from one server are remembered before the failover count resets.
    const failover_window: interval = 30min &redef;

    ## Distinct model APIs from one server inside failover_window that raise Model_API_Failover.
    const failover_min_hosts: count = 2 &redef;
}

global model_hosts_seen: table[addr] of set[string] &create_expire=failover_window;

## The kind of model endpoint a TLS server name belongs to, or "" when it is none of them.
function model_kind(n: string): string
    {
    for ( h in china_model_hosts )
        if ( n == h || ends_with(n, "." + h) )
            return "Chinese model API";
    for ( h in gateway_hosts )
        if ( n == h || ends_with(n, "." + h) )
            return "model gateway";
    for ( h in other_model_hosts )
        if ( n == h || ends_with(n, "." + h) )
            return "model API";
    return "";
    }

event ssl_extension_server_name(c: connection, is_client: bool, names: string_vec)
    {
    if ( ! is_client || ! is_server(c$id$orig_h) )
        return;
    for ( s in allowed_ai_nets )
        if ( c$id$orig_h in s )
            return;
    for ( i in names )
        {
        local n = to_lower(names[i]);
        local kind = model_kind(n);
        if ( kind != "" )
            {
            raise(c, Model_API_From_Server, fmt("%s opened TLS to %s %s", c$id$orig_h, kind, n), n, cat(c$id$orig_h, n));
            if ( c$id$orig_h !in model_hosts_seen )
                {
                local empty: set[string];
                model_hosts_seen[c$id$orig_h] = empty;
                }
            add model_hosts_seen[c$id$orig_h][n];
            if ( |model_hosts_seen[c$id$orig_h]| == failover_min_hosts )
                raise(c, Model_API_Failover,
                      fmt("%s opened TLS to %d model APIs within %s, including %s", c$id$orig_h, failover_min_hosts, failover_window, n),
                      n, cat(c$id$orig_h, "model-failover"));
            }
        }
    }
