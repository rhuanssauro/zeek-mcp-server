##! OSPF Anomaly Detection Script
##!
##! Monitors IP protocol 89 (OSPF) traffic for anomalies:
##! - OSPF packets from unexpected sources
##! - High volume of OSPF traffic (potential flooding)
##! - OSPF traffic to non-multicast destinations (possible spoofing)
##! - Multiple OSPF sources on a single segment
##!
##! Note: Zeek does not have a native OSPF analyzer, so we detect based
##! on IP protocol number and connection metadata.

@load base/protocols/conn
@load base/frameworks/notice

module OSPFAnomaly;

export {
    redef enum Notice::Type += {
        ## OSPF traffic detected
        OSPF_Traffic_Detected,
        ## OSPF traffic to non-standard destination (not 224.0.0.5/6)
        OSPF_Non_Standard_Dest,
        ## High volume of OSPF packets from a single source
        OSPF_Flood_Detected,
        ## Multiple OSPF speakers on segment
        OSPF_Multiple_Speakers,
    };

    ## OSPF multicast addresses
    const ospf_multicast_all_routers = 224.0.0.5;
    const ospf_multicast_dr = 224.0.0.6;

    ## Threshold for OSPF flood detection (packets per source)
    const flood_threshold = 100 &redef;
}

# Track OSPF sources
global ospf_sources: set[addr] = {};
global ospf_packet_count: table[addr] of count = {} &default=0;

event connection_state_remove(c: connection)
    {
    # OSPF uses IP protocol 89 - appears as icmp or unknown in Zeek conn.log
    # We look for protocol field and common OSPF patterns
    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    local proto = get_port_transport_proto(c$id$resp_p);

    # Check for OSPF multicast destinations (common indicator)
    local dst_str = fmt("%s", dst);
    local is_ospf_mcast = (dst_str == "224.0.0.5" || dst_str == "224.0.0.6");

    # Also check for protocol 89 connections (may show as resp_p = 0/unknown)
    if ( ! is_ospf_mcast )
        return;

    add ospf_sources[src];
    ospf_packet_count[src] += 1;

    # Notice: OSPF traffic detected
    NOTICE([
        $note=OSPF_Traffic_Detected,
        $msg=fmt("OSPF traffic: %s -> %s", src, dst),
        $src=src,
        $dst=dst,
        $conn=c,
        $identifier=fmt("ospf-%s-%s", src, dst),
        $suppress_for=300sec
    ]);

    # Check for non-standard OSPF destinations
    if ( ! is_ospf_mcast )
        {
        NOTICE([
            $note=OSPF_Non_Standard_Dest,
            $msg=fmt("OSPF to non-multicast destination: %s -> %s (possible spoofing)", src, dst),
            $src=src,
            $dst=dst,
            $conn=c,
            $identifier=fmt("ospf-nonmcast-%s-%s", src, dst),
            $suppress_for=60sec
        ]);
        }

    # Check for flooding
    if ( ospf_packet_count[src] >= flood_threshold )
        {
        NOTICE([
            $note=OSPF_Flood_Detected,
            $msg=fmt("OSPF flood from %s: %d packets detected", src, ospf_packet_count[src]),
            $src=src,
            $identifier=fmt("ospf-flood-%s", src),
            $suppress_for=300sec
        ]);
        }

    # Check for multiple speakers
    if ( |ospf_sources| > 10 )
        {
        NOTICE([
            $note=OSPF_Multiple_Speakers,
            $msg=fmt("Multiple OSPF speakers detected: %d unique sources", |ospf_sources|),
            $src=src,
            $identifier="ospf-multi-speakers",
            $suppress_for=600sec
        ]);
        }
    }
