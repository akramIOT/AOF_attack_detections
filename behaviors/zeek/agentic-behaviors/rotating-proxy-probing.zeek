##! One site probed through hundreds of rotating proxy addresses (behaviors hunt 04)
##!
##! Agent operators send their tools through residential proxy services (IPRoyal, 711proxy and 1024proxy in Gambit's
##! case). Cyber Security Cloud saw one agent rotate through 326 addresses in about 40 minutes for more than 1,200
##! requests. Per-address thresholds miss this, so this counts distinct outside addresses per target host for requests
##! that carry payloads or hit login and admin paths. Exclude your CDN, uptime monitoring and partner integrations.

@load base/frameworks/sumstats
@load base/protocols/http
@load ./main

module AgenticBehaviors;

export {
    redef enum Notice::Type += {
        ## Many outside addresses, few requests each, sent payloads or login and admin requests to one host.
        Rotating_Proxy_Probing,
    };

    ## Distinct outside addresses per host and window before a notice.
    const proxy_min_sources: count = 50 &redef;
    ## Average requests per address at or below which the spread looks like rotation.
    const proxy_max_per_source: double = 10.0 &redef;
    const proxy_window: interval = 40min &redef;
}

event zeek_init()
    {
    local r1 = SumStats::Reducer($stream="agentic.proxy.src", $apply=set(SumStats::UNIQUE));
    local r2 = SumStats::Reducer($stream="agentic.proxy.req", $apply=set(SumStats::SUM));
    SumStats::create([$name="agentic-rotating-proxy",
                      $epoch=proxy_window,
                      $reducers=set(r1, r2),
                      $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
                          { return result["agentic.proxy.src"]$unique + 0.0; },
                      $threshold=proxy_min_sources + 0.0,
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                          {
                          local sources = result["agentic.proxy.src"]$unique;
                          local requests = result["agentic.proxy.req"]$sum;
                          if ( requests / sources > proxy_max_per_source )
                              return;
                          NOTICE([$note=Rotating_Proxy_Probing,
                                  $msg=fmt("%s probed from %d outside addresses, %.0f requests", key$str, sources, requests),
                                  $sub=key$str, $identifier=key$str, $suppress_for=suppress_for]);
                          }]);
    }

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
    {
    # Runs after the request line and headers, so the Host header is known.
    if ( ! is_orig || ! c?$http || ! c$http?$uri || Site::is_local_addr(c$id$orig_h) )
        return;
    if ( payload_uri !in c$http$uri && sensitive_uri !in c$http$uri )
        return;
    local host = c$http?$host ? c$http$host : cat(c$id$resp_h);
    SumStats::observe("agentic.proxy.src", [$str=host], [$str=cat(c$id$orig_h)]);
    SumStats::observe("agentic.proxy.req", [$str=host], [$num=1]);
    }
