##! Servers resolving out-of-band testing domains (behaviors hunt 09)
##!
##! Agents confirm blind injection, SSRF and XXE by making the target look up a unique name under a callback service.
##! Strix's sandbox ships interactsh-client and its skills use *.oast.fun; nuclei uses the same interactsh servers;
##! CyberStrikeAI operators used dnslog.cn. When one of your servers looks up one of these names, a payload ran on it.

@load base/protocols/dns
@load ./main

module AgenticBehaviors;

export {
    redef enum Notice::Type += {
        ## A server looked up a name under an out-of-band testing service.
        Out_Of_Band_Lookup,
    };

    ## Callback services. A name matches when it ends with ".<service>".
    const oob_services: set[string] = {
        "oast.fun", "oast.pro", "oast.live", "oast.site", "oast.online", "oast.me", "interact.sh", "oastify.com",
        "burpcollaborator.net", "dnslog.cn", "ceye.io", "requestrepo.com",
    } &redef;
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    if ( ! is_server(c$id$orig_h) )
        return;
    local q = to_lower(query);
    for ( svc in oob_services )
        if ( ends_with(q, "." + svc) )
            {
            raise(c, Out_Of_Band_Lookup, fmt("%s looked up %s (out-of-band testing service %s)", c$id$orig_h, q, svc),
                  q, cat(c$id$orig_h, svc));
            return;
            }
    }
