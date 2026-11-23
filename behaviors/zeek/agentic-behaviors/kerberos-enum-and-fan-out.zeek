##! Kerberos user enumeration and SMB or WinRM fan-out from one address (behaviors hunt 06)
##!
##! Agent workers ship kerbrute, netexec and Impacket. Kerbrute sends bare AS-REQs: unknown names fail with
##! KDC_ERR_C_PRINCIPAL_UNKNOWN (6) and its password spray fails with KDC_ERR_PREAUTH_FAILED (24). Netexec then fans out
##! over SMB (445) and WinRM (5985, 5986). Zeek sees all of it on the wire, with no domain controller auditing needed.

@load base/frameworks/sumstats
@load base/protocols/krb
@load ./main

module AgenticBehaviors;

export {
    redef enum Notice::Type += {
        ## One address asked the KDC about many accounts, most of them unknown or with bad passwords.
        Kerberos_Enumeration,
        ## One address opened SMB or WinRM to many hosts.
        SMB_WinRM_Fan_Out,
    };

    const krb_min_accounts: count = 25 &redef;
    const krb_min_failures: count = 10 &redef;
    const fan_out_min_hosts: count = 10 &redef;
    const fan_out_ports: set[port] = { 445/tcp, 5985/tcp, 5986/tcp } &redef;
    const lateral_window: interval = 10min &redef;
}

global krb_failures: table[addr] of count &default=0 &create_expire=10min;

event zeek_init()
    {
    local r1 = SumStats::Reducer($stream="agentic.krb.accounts", $apply=set(SumStats::UNIQUE));
    SumStats::create([$name="agentic-kerberos-enum",
                      $epoch=lateral_window,
                      $reducers=set(r1),
                      $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
                          {
                          # Only count toward the threshold once enough failures have been seen from this address.
                          if ( krb_failures[key$host] < krb_min_failures )
                              return 0.0;
                          return result["agentic.krb.accounts"]$unique + 0.0;
                          },
                      $threshold=krb_min_accounts + 0.0,
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                          {
                          NOTICE([$note=Kerberos_Enumeration,
                                  $msg=fmt("%s asked the KDC about %d accounts, %d failed as unknown or bad password",
                                           key$host, result["agentic.krb.accounts"]$unique, krb_failures[key$host]),
                                  $src=key$host, $identifier=cat(key$host), $suppress_for=suppress_for]);
                          }]);

    local r2 = SumStats::Reducer($stream="agentic.fanout.hosts", $apply=set(SumStats::UNIQUE));
    SumStats::create([$name="agentic-smb-winrm-fan-out",
                      $epoch=lateral_window,
                      $reducers=set(r2),
                      $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
                          { return result["agentic.fanout.hosts"]$unique + 0.0; },
                      $threshold=fan_out_min_hosts + 0.0,
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                          {
                          NOTICE([$note=SMB_WinRM_Fan_Out,
                                  $msg=fmt("%s opened SMB or WinRM to %d hosts", key$host, result["agentic.fanout.hosts"]$unique),
                                  $src=key$host, $identifier=cat(key$host), $suppress_for=suppress_for]);
                          }]);
    }

event krb_as_request(c: connection, msg: KRB::KDC_Request)
    {
    if ( msg?$client_name )
        SumStats::observe("agentic.krb.accounts", [$host=c$id$orig_h], [$str=to_lower(msg$client_name)]);
    }

event krb_error(c: connection, msg: KRB::Error_Msg)
    {
    if ( msg$error_code == 6 || msg$error_code == 24 )
        {
        ++krb_failures[c$id$orig_h];
        if ( msg?$client_name )
            SumStats::observe("agentic.krb.accounts", [$host=c$id$orig_h], [$str=to_lower(msg$client_name)]);
        }
    }

event connection_established(c: connection)
    {
    if ( c$id$resp_p in fan_out_ports )
        SumStats::observe("agentic.fanout.hosts", [$host=c$id$orig_h], [$str=cat(c$id$resp_h)]);
    }
