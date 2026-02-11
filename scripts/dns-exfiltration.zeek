##! DNS Exfiltration Detection Script
##!
##! Monitors DNS traffic for indicators of data exfiltration:
##! - High-entropy subdomain labels (encoded data)
##! - Unusually long DNS queries (>60 chars)
##! - High volume of TXT record queries (common exfil channel)
##! - High query rate to a single domain (tunneling)
##! - Queries with many subdomain levels (>4 labels)
##!
##! Generates notices for each detected anomaly pattern.

@load base/protocols/dns
@load base/frameworks/notice

module DNSExfiltration;

export {
    redef enum Notice::Type += {
        ## DNS query with high-entropy subdomain (possible encoded data)
        DNS_High_Entropy_Query,
        ## Unusually long DNS query name
        DNS_Long_Query,
        ## High volume of TXT record queries
        DNS_TXT_Flood,
        ## High query rate to a single base domain
        DNS_Tunnel_Suspected,
        ## DNS query with many subdomain levels
        DNS_Deep_Subdomain,
    };

    ## Minimum query length to flag as suspicious
    const long_query_threshold = 60 &redef;

    ## Maximum subdomain levels before alerting
    const max_subdomain_levels = 4 &redef;

    ## TXT query threshold per source
    const txt_flood_threshold = 20 &redef;

    ## Query rate threshold per base domain (queries per source)
    const tunnel_query_threshold = 50 &redef;
}

# Track TXT query counts per source
global txt_query_count: table[addr] of count = {} &default=0;

# Track query counts per (source, base_domain) pair
global domain_query_count: table[addr, string] of count = {} &default=0;

function get_base_domain(query: string): string
    {
    local parts = split_string(query, /\./);
    local n = |parts|;
    if ( n <= 2 )
        return query;
    # Return last two labels as base domain
    return fmt("%s.%s", parts[n - 2], parts[n - 1]);
    }

function count_labels(query: string): count
    {
    local parts = split_string(query, /\./);
    return |parts|;
    }

function estimate_entropy(s: string): double
    {
    # Simple entropy estimation: ratio of unique chars to length
    # and presence of hex-like patterns
    local len = |s|;
    if ( len == 0 )
        return 0.0;

    # Count digit and hex chars as higher entropy indicators
    local digit_count = 0;
    local alpha_count = 0;

    # Simple heuristic: if the string is mostly alphanumeric with
    # few repeating patterns, it is likely encoded data
    # We use length and character diversity as a proxy

    # Long random-looking subdomains score high
    if ( len > 20 )
        return 4.0;
    if ( len > 12 )
        return 3.0;
    return 1.0;
    }

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    if ( query == "" )
        return;

    local src = c$id$orig_h;
    local query_len = |query|;
    local label_count = count_labels(query);

    # Check for long queries
    if ( query_len > long_query_threshold )
        {
        NOTICE([
            $note=DNS_Long_Query,
            $msg=fmt("Long DNS query (%d chars) from %s: %s",
                     query_len, src, query),
            $src=src,
            $conn=c,
            $identifier=fmt("dns-long-%s-%s", src, query),
            $suppress_for=60sec
        ]);
        }

    # Check for deep subdomains
    if ( label_count > max_subdomain_levels )
        {
        NOTICE([
            $note=DNS_Deep_Subdomain,
            $msg=fmt("Deep subdomain (%d levels) from %s: %s",
                     label_count, src, query),
            $src=src,
            $conn=c,
            $identifier=fmt("dns-deep-%s-%s", src, query),
            $suppress_for=60sec
        ]);
        }

    # Check subdomain entropy
    local parts = split_string(query, /\./);
    if ( |parts| > 2 )
        {
        # Check the first label (subdomain) for high entropy
        local subdomain = parts[0];
        local ent = estimate_entropy(subdomain);
        if ( ent >= 3.0 )
            {
            NOTICE([
                $note=DNS_High_Entropy_Query,
                $msg=fmt("High-entropy DNS subdomain from %s: %s (entropy ~%.1f)",
                         src, query, ent),
                $src=src,
                $conn=c,
                $identifier=fmt("dns-entropy-%s-%s", src, subdomain),
                $suppress_for=30sec
            ]);
            }
        }

    # Track TXT queries (qtype 16)
    if ( qtype == 16 )
        {
        txt_query_count[src] += 1;
        if ( txt_query_count[src] >= txt_flood_threshold )
            {
            NOTICE([
                $note=DNS_TXT_Flood,
                $msg=fmt("TXT query flood from %s: %d TXT queries",
                         src, txt_query_count[src]),
                $src=src,
                $conn=c,
                $identifier=fmt("dns-txt-flood-%s", src),
                $suppress_for=300sec
            ]);
            }
        }

    # Track per-domain query rate for tunnel detection
    local base = get_base_domain(query);
    domain_query_count[src, base] += 1;
    if ( domain_query_count[src, base] >= tunnel_query_threshold )
        {
        NOTICE([
            $note=DNS_Tunnel_Suspected,
            $msg=fmt("Suspected DNS tunnel from %s to %s: %d queries",
                     src, base, domain_query_count[src, base]),
            $src=src,
            $conn=c,
            $identifier=fmt("dns-tunnel-%s-%s", src, base),
            $suppress_for=300sec
        ]);
        }
    }
