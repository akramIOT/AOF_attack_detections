##! ARTEX detections by ThreatDefence
##! https://threatdefence.com/article/artex-agentic-attack-framework-detection-hunting
##!
##! Raises notices for ARTEX user agents, request headers and probe markers, the placeholder paths and
##! unsigned alg:none tokens ARTEX sends while mapping a web application, and ARTEX console pages
##! served in cleartext. Cleartext HTTP only: put it behind TLS decryption or on the inside of a
##! terminating proxy to see HTTPS traffic.
##!
##! Load with:  @load ./artex   (from the folder that holds this directory)
##! Indicators: load ../intel/artex.intel with the Intel framework (see README).

@load base/frameworks/notice
@load base/protocols/http

module ARTEX;

export {
    redef enum Notice::Type += {
        ## A request carried a user agent that names ARTEX or a renamed build.
        User_Agent,
        ## A request carried an ARTEX header or probe marker.
        Probe_Marker,
        ## A request asked for a placeholder path ARTEX uses to learn how a site answers.
        Probe_Path,
        ## A request carried an unsigned JWT with alg none.
        JWT_Alg_None,
        ## A server answered with an ARTEX console page.
        Console_Page,
    };

    ## User agents that name ARTEX, its forks and renamed builds.
    const user_agents: pattern =
        /artex-(readonly|pentest|audit|verify|spawn|enrich)\// |
        /ARTEX-worker\// | /artex-i21861-canary/ | /ARTeX/ |
        /Mozilla\/5\.0 \(ARTEX\)/ | /ArtExVerify\// | /ArtEx\/1\.0/ |
        /scopeweaver/ | /spa-api-recon/ &redef;

    ## Placeholder paths and probe values in request URIs.
    const probe_paths: pattern =
        /zzz-nonexistent-xyz123/ | /zzz_nonexistent_abc\.txt/ | /Notexist-xyz/ |
        /code=AAAA&state=notvalidb64!!/ &redef;

    ## Probe marker strings in request URIs.
    const probe_markers: pattern =
        /ARTEX_WRITE_PROBE/ | /ARTX_PERSIST_OK/ | /artex_control_marker_zz9q/ |
        /ARTEX-PROBE-/ | /artex-probe-/ &redef;

    ## Base64url headers of unsigned JWTs ({"alg":"none"} and common variants).
    const alg_none_jwt: pattern =
        /eyJhbGciOiJub25lIn0\./ | /eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0\./ |
        /eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0\./ &redef;

    ## Console page titles: ARTEX, renamed builds ScopeWeaver and LUCK.
    const console_titles: pattern =
        /<title>(ARTEX|ScopeWeaver|LUCK)[ :\-<]/ &redef;

    ## How long to suppress repeat notices for the same source and indicator.
    const suppress_for: interval = 1hr &redef;
}

function raise(c: connection, note: Notice::Type, msg: string, sub: string)
    {
    NOTICE([$note=note, $msg=msg, $sub=sub, $conn=c,
            $identifier=cat(c$id$orig_h, note, sub),
            $suppress_for=suppress_for]);
    }

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
    {
    if ( probe_paths in original_URI )
        raise(c, Probe_Path, fmt("ARTEX probe path from %s", c$id$orig_h), original_URI);

    if ( probe_markers in original_URI )
        raise(c, Probe_Marker, fmt("ARTEX probe marker in URI from %s", c$id$orig_h), original_URI);

    if ( alg_none_jwt in original_URI )
        raise(c, JWT_Alg_None, fmt("Unsigned alg:none JWT in URI from %s", c$id$orig_h), original_URI);
    }

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
    {
    if ( ! is_orig )
        return;

    for ( i in hlist )
        {
        local h = hlist[i];

        if ( h$name == "USER-AGENT" && user_agents in h$value )
            raise(c, User_Agent, fmt("ARTEX user agent from %s", c$id$orig_h), h$value);

        else if ( h$name == "X-ARTX-KEY" )
            raise(c, Probe_Marker, fmt("X-ARTX-KEY header from %s", c$id$orig_h), h$value);

        else if ( h$name == "AUTHORIZATION" && alg_none_jwt in h$value )
            raise(c, JWT_Alg_None, fmt("Unsigned alg:none JWT in Authorization from %s", c$id$orig_h), h$name);
        }
    }

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
    {
    if ( is_orig )
        return;

    if ( console_titles in data )
        raise(c, Console_Page, fmt("ARTEX console page served by %s:%s", c$id$resp_h, c$id$resp_p),
              cat(c$id$resp_h, ":", c$id$resp_p));
    }
