##! Servers resolving canary-token domains (behaviors hunt 11)
##!
##! A canary token is a credential, URL or DNS name planted so that reading it makes the host call home. An agent that
##! searches files, environment variables and cloud logs for secrets will trip one. When one of your servers looks up a
##! name under a canary-token service, something on that server read a token.

@load base/protocols/dns
@load ./main

module AgenticBehaviors;

export {
    redef enum Notice::Type += {
        ## A server looked up a name under a canary-token service.
        Canary_Token_Lookup,
    };

    ## Canary-token services. A name matches when it ends with ".<service>".
    const canary_services: set[string] = {
        "canarytokens.com", "canarytokens.org", "canary.tools",
    } &redef;
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    if ( ! is_server(c$id$orig_h) )
        return;
    local q = to_lower(query);
    for ( svc in canary_services )
        if ( ends_with(q, "." + svc) )
            {
            raise(c, Canary_Token_Lookup, fmt("%s looked up %s (canary token service %s)", c$id$orig_h, q, svc),
                  q, cat(c$id$orig_h, svc));
            return;
            }
    }
