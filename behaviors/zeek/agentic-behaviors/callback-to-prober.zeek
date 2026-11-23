##! A server calls back to the address that was probing it (behaviors hunt 07)
##!
##! Agentic frameworks catch reverse shells and out-of-band callbacks on the machine that runs the attack. PentAGI
##! publishes two listener ports per engagement from 28000 on its host, and Cairn's guide tells its agents to call back
##! to the host's own external address. Either way, a server you own connects out to an address that was sending it
##! requests shortly before. Ordinary servers rarely connect to the addresses that browse them.

@load ./main

module AgenticBehaviors;

export {
    redef enum Notice::Type += {
        ## A server opened a connection to an outside address that had been connecting to it.
        Callback_To_Prober,
    };

    ## How long an outside address is remembered after its last inbound connection.
    const prober_memory: interval = 1day &redef;
    ## Inbound connections from an address before it counts as a prober.
    const prober_min_conns: count = 3 &redef;
    ## Outbound ports that are normal replies to visitors (mail, DNS, NTP).
    const callback_ignore_ports: set[port] = { 25/tcp, 53/udp, 53/tcp, 123/udp } &redef;
    ## PentAGI's worker listener range.
    const pentagi_ports_low: count = 28000 &redef;
    const pentagi_ports_high: count = 29999 &redef;
}

global probers: table[addr] of count &default=0 &read_expire=prober_memory;

event connection_established(c: connection)
    {
    local o = c$id$orig_h;
    local r = c$id$resp_h;

    # Inbound: an outside address connecting to one of your servers.
    if ( ! Site::is_local_addr(o) && is_server(r) )
        {
        ++probers[o];
        return;
        }

    # Outbound: one of your servers connecting to an address that had been probing it.
    if ( is_server(o) && ! Site::is_local_addr(r) && r in probers && probers[r] >= prober_min_conns
         && c$id$resp_p !in callback_ignore_ports )
        {
        local p = port_to_count(c$id$resp_p);
        local note = (p >= pentagi_ports_low && p <= pentagi_ports_high) ? " (PentAGI worker port range)" : "";
        raise(c, Callback_To_Prober,
              fmt("%s connected to %s:%s after %d inbound connections from it%s", o, r, c$id$resp_p, probers[r], note),
              cat(c$id$resp_p), cat(o, r, c$id$resp_p));
        }
    }
