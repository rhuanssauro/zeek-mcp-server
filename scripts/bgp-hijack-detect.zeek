##! BGP Hijack Detection Script
##!
##! Monitors TCP port 179 (BGP) for anomalies in BGP sessions:
##! - New BGP peers not seen before
##! - BGP sessions from unexpected source IPs
##! - Short-lived BGP sessions (possible prefix hijack attempts)
##! - Multiple BGP connections from the same source in rapid succession
##!
##! Generates notices for each detected anomaly.

@load base/protocols/conn
@load base/frameworks/notice

module BGPHijackDetect;

export {
    redef enum Notice::Type += {
        ## A new BGP session was detected on TCP/179
        BGP_New_Session,
        ## A BGP session was very short-lived (possible hijack attempt)
        BGP_Short_Session,
        ## Multiple BGP connections from the same source in a short window
        BGP_Rapid_Connections,
        ## BGP traffic detected on non-standard port
        BGP_Non_Standard_Port,
    };

    ## Minimum session duration to not trigger short-session alert
    const short_session_threshold = 5sec &redef;

    ## Maximum connections from one source in the tracking window
    const rapid_conn_threshold = 5 &redef;

    ## Time window for tracking rapid connections
    const rapid_conn_window = 60sec &redef;
}

# Track BGP connection counts per source
global bgp_conn_count: table[addr] of count = {} &default=0;
global bgp_conn_start: table[addr] of time = {};

event connection_state_remove(c: connection)
    {
    local resp_port = c$id$resp_p;
    local orig_port = c$id$orig_p;

    # Detect BGP on standard port 179
    local is_bgp = (resp_port == 179/tcp || orig_port == 179/tcp);

    if ( ! is_bgp )
        return;

    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    # Notice: New BGP session detected
    NOTICE([
        $note=BGP_New_Session,
        $msg=fmt("BGP session detected: %s -> %s:%s (duration: %s)",
                 src, dst, resp_port, c$duration),
        $src=src,
        $dst=dst,
        $conn=c,
        $identifier=fmt("%s-%s", src, dst),
        $suppress_for=300sec
    ]);

    # Check for short-lived sessions
    if ( c$duration < short_session_threshold )
        {
        NOTICE([
            $note=BGP_Short_Session,
            $msg=fmt("Short BGP session: %s -> %s (%s) - possible hijack probe",
                     src, dst, c$duration),
            $src=src,
            $dst=dst,
            $conn=c,
            $identifier=fmt("short-%s-%s", src, dst),
            $suppress_for=60sec
        ]);
        }

    # Track rapid connections
    bgp_conn_count[src] += 1;

    if ( src !in bgp_conn_start )
        bgp_conn_start[src] = network_time();

    local elapsed = network_time() - bgp_conn_start[src];

    if ( elapsed <= rapid_conn_window )
        {
        if ( bgp_conn_count[src] >= rapid_conn_threshold )
            {
            NOTICE([
                $note=BGP_Rapid_Connections,
                $msg=fmt("Rapid BGP connections from %s: %d sessions in %s",
                         src, bgp_conn_count[src], elapsed),
                $src=src,
                $identifier=fmt("rapid-%s", src),
                $suppress_for=300sec
            ]);
            }
        }
    else
        {
        # Reset window
        bgp_conn_count[src] = 1;
        bgp_conn_start[src] = network_time();
        }
    }
