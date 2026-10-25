#!/bin/sh
# bufferbloat_probe.sh — active latency-under-load probe for OpenWrt + VictoriaMetrics
#
# Every run:
#   1. Measures idle RTT (TCP connect to 1.1.1.1)
#   2. Saturates download for ~14s with MULTIPLE parallel connections while
#      sampling TCP-connect RTT
#   3. Saturates upload   for ~14s with MULTIPLE parallel connections while
#      sampling TCP-connect RTT
#   4. Computes bufferbloat grade (Waveform scale) and pushes metrics to VM
#
# Why TCP connect, not ping: under load the ISP's PPP term proxy-answers
# ICMP echo requests for arbitrary destination IPs (replies at ~0.6 ms,
# generated in front of the shaper), so ping deltas under-report
# bufferbloat and can even go negative. A SYN->SYN-ACK must be completed by
# the real host, past the shaper where the queue delay actually lives.
#
# Why parallel connections: CAKE shares bandwidth fairly per flow, so a single
# curl only gets a slice of the shaper (~150-260 Mbps of a 415 Mbit shaper)
# and never loads the line — which makes latency grades look better than
# reality. Several concurrent flows are needed to actually saturate.
#
# A burst is only reported as a bloat measurement if it moved real data
# (>= MIN_BURST_BPS); a failed CDN fetch is logged and skipped rather than
# pushing nonsense. The dashboard separately hedges the grade when the burst
# never reached the shaped rate.
#
# Metrics land in VictoriaMetrics via /api/v1/import/prometheus.
# Add to crontab:  */15 * * * * /opt/monitoring/scripts/bufferbloat_probe.sh

VM_URL="${VM_URL:-http://127.0.0.1:8428}"
# INET target for the TCP-connect RTT probe. NOT 1.1.1.1: this ISP
# intercepts it (ICMP echo gets proxy-answered by the interceptor in front
# of the shaper, TCP 443 gets refused), which made every latency-under-load
# reading bogus. 8.8.8.8 answers honestly.
INET_TARGET="${INET_TARGET:-8.8.8.8}"
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 openwrt-view-bufferbloat-probe/1.5"
BURST_TIMEOUT=20           # curl max time per individual transfer (s)
DUR=14                     # seconds of sustained load per direction
DOWN_WORKERS=12
UP_WORKERS=4
UP_PAYLOAD_MB=90           # __up accepts ~100MB POSTs; 90 is safe
MIN_BURST_BPS=10000000     # 10 Mbit/s: below this the burst didn't really load the line
TMP=/opt/monitoring/tmp

# Shaped rates from the SQM config (kbit/s) — logged so runs can be judged
# against what the shaper should allow.
SQM_DOWN_KBIT=$(uci -q get sqm.@queue[0].download 2>/dev/null)
SQM_UP_KBIT=$(uci -q get sqm.@queue[0].upload 2>/dev/null)

# Download sources: Cloudflare 403s curl from this network, and several CDNs
# (proof.ovh, Hetzner) rate-limit concurrent connections (HTTP 429). So the
# probe checks which sources are alive, then round-robins its workers across
# all of them — each worker skips a source that rejects it and only HTTP 200
# bytes count toward the measured speed.
DOWN_URLS="\
https://speed.cloudflare.com/__down?bytes=200000000
https://proof.ovh.net/files/1Gb.dat
http://speedtest.tele2.net/1GB.zip
https://nbg1-speed.hetzner.com/1GB.bin
https://hel1-speed.hetzner.com/1GB.bin
https://ash-speed.hetzner.com/1GB.bin
https://fsn1-speed.hetzner.com/1GB.bin
https://mirrors.kernel.org/archlinux/iso/latest/archlinux-x86_64.iso"
UP_URL="https://speed.cloudflare.com/__up"

WORKDIR=/tmp/bufferbloat-probe
mkdir -p "$WORKDIR" && cd "$WORKDIR" || exit 1

# Daytime only: skip runs outside 07:00-22:30 (cron still fires every 15 min;
# the script just exits quietly at night — nothing to monitor while asleep).
H=$(date +%H%M)
if [ "$H" -lt 0700 ] || [ "$H" -gt 2230 ]; then
    exit 0
fi

log() { logger -t bufferbloat-probe "$*"; }

# --- helpers -----------------------------------------------------------

grade_for() {  # $1 = bloat ms -> letter grade
    local b=$1
    if   [ -z "$b" ] || [ "$b" = "0" ]; then echo "n/a"
    elif awk "BEGIN{exit !($b <= 5)}"   2>/dev/null; then echo "A+"
    elif awk "BEGIN{exit !($b <= 10)}"  2>/dev/null; then echo "A"
    elif awk "BEGIN{exit !($b <= 30)}"  2>/dev/null; then echo "B"
    elif awk "BEGIN{exit !($b <= 60)}"  2>/dev/null; then echo "C"
    elif awk "BEGIN{exit !($b <= 200)}" 2>/dev/null; then echo "D"
    elif awk "BEGIN{exit !($b <= 400)}" 2>/dev/null; then echo "E"
    else echo "F"
    fi
}

# human_mbps <bits_per_s> -> "###.# Mbps"
human_mbps() {
    awk "BEGIN{v=$1/1e6; if (v>=100) printf \"%.0f Mbps\", v; else printf \"%.1f Mbps\", v}"
}

# Keep pulling until the deadline; append "bytes code" lines per transfer
 # (only 200s are counted later). Pinned to one source: a long-lived
# connection per worker avoids re-handshakes and stays under each server's
# concurrent-connection limit.
down_worker() {  # $1=url
    local end=$(( $(date +%s) + DUR )) out
    while [ "$(date +%s)" -lt "$end" ]; do
        out=$(curl -sSL -A "$UA" -o /dev/null -m "$BURST_TIMEOUT" \
            -w '%{size_download} %{http_code}' "$1" 2>>down.err)
        echo "$out" >> down.parts
        case "$out" in
            *" 200") : ;;
            *) sleep 1 ;;  # rate-limited or failed: back off, retry
        esac
    done
}

up_worker() {
    local end=$(( $(date +%s) + DUR ))
    while [ "$(date +%s)" -lt "$end" ]; do
        curl -sS -A "$UA" -o /dev/null -m "$BURST_TIMEOUT" \
            -w '%{size_upload} %{http_code}\n' \
            -H "Content-Type: application/octet-stream" \
            --data-binary @"$TMP/payload.bin" "$UP_URL" >> up.parts 2>>up.err
    done
}

# burst_down <unused> -> echoes "connect_rtt_ms speed_bps" (rtt 0 if burst failed)
burst_down() {
    local url probe_out total elapsed start med SRCS=""
    # Find sources that actually serve data (short single-stream checks).
    for url in $DOWN_URLS; do
        probe_out=$(curl -sSL -A "$UA" -o /dev/null -m 4 \
            -w '%{size_download} %{http_code}' "$url" 2>/dev/null)
        log "source check $url -> $probe_out"
        case "$probe_out" in
            *" 200") SRCS="$SRCS $url" ;;
        esac
    done
    [ -n "$SRCS" ] || { log "no download source reachable"; echo "0 0"; return; }
    log "using sources:$SRCS"

    : > down.parts
    : > conn.rtt
    start=$(date +%s)
    connect_sampler $((DUR + 2)) conn.rtt &
    local CONN_PID=$!
    local i=1 src
    # Pin each worker to one alive source (cyclically) so concurrent
    # connections spread evenly across servers.
    set -- $SRCS
    while [ "$i" -le "$DOWN_WORKERS" ]; do
        src=$(eval "echo \${$(( (i - 1) % $# + 1 ))}")
        down_worker "$src" &
        i=$((i + 1))
    done
    wait "$CONN_PID" 2>/dev/null
    wait
    elapsed=$(( $(date +%s) - start )); [ "$elapsed" -ge 1 ] || elapsed=1
    total=$(awk '$2==200{s+=$1} END{print s+0}' down.parts)
    med=$(median_ms conn.rtt)
    # push bits/s (metric name is probe_burst_speed_bps)
    echo "${med:-0} $(awk "BEGIN{printf \"%.0f\", $total*8/$elapsed}")"
}

# burst_up -> echoes "connect_rtt_ms speed_bps" (rtt 0 if burst failed)
burst_up() {
    local total elapsed start med
    mkdir -p "$TMP"
    [ -f "$TMP/payload.bin" ] || \
        dd if=/dev/urandom of="$TMP/payload.bin" bs=1M count="$UP_PAYLOAD_MB" 2>/dev/null
    [ -f "$TMP/payload.bin" ] || { log "cannot create upload payload"; echo "0 0"; return; }

    : > up.parts
    : > conn.rtt
    start=$(date +%s)
    connect_sampler $((DUR + 2)) conn.rtt &
    local CONN_PID=$!
    local i=1
    while [ "$i" -le "$UP_WORKERS" ]; do
        up_worker &
        i=$((i + 1))
    done
    wait "$CONN_PID" 2>/dev/null
    wait
    elapsed=$(( $(date +%s) - start )); [ "$elapsed" -ge 1 ] || elapsed=1
    total=$(awk '$2==200{s+=$1} END{print s+0}' up.parts)
    med=$(median_ms conn.rtt)
    # push bits/s (metric name is probe_burst_speed_bps)
    echo "${med:-0} $(awk "BEGIN{printf \"%.0f\", $total*8/$elapsed}")"
}

# connect_rtt <count> -> median TCP-connect RTT (ms) to the probe target.
# TCP, not ICMP: under load the ISP's PPP term proxy-answers echo requests
# for arbitrary destination IPs (replies at ~0.6 ms, from in front of the
# shaper), so ping deltas under-report bufferbloat and can even go
# negative. A SYN->SYN-ACK has to be completed by the real host, past the
# shaper where the queue delay actually lives. curl's time_connect is one
# RTT (plus negligible server processing); the median of several samples
# is the load reading.
connect_rtt() {
    local i=0 n="$1" t
    while [ "$i" -lt "$n" ]; do
        t=$(curl -k -sS -o /dev/null --connect-timeout 3 \
            -w '%{time_connect}\n' "https://$INET_TARGET/" 2>/dev/null)
        [ -n "$t" ] && [ "$t" != "0.000000" ] && echo "$t"
        i=$((i + 1))
        sleep 1
    done | awk '{a[NR]=$1} END{if (NR==0) print 0; else if (NR%2) printf "%.3f\n", a[(NR+1)/2]*1000; else printf "%.3f\n", (a[NR/2]+a[NR/2+1])/2*1000}'
}

# connect_sampler <duration_s> <outfile> -> appends connect RTTs (s) for
# duration seconds; run in the background alongside the burst workers.
connect_sampler() {
    local end=$(( $(date +%s) + $1 )) t
    while [ "$(date +%s)" -lt "$end" ]; do
        t=$(curl -k -sS -o /dev/null --connect-timeout 3 \
            -w '%{time_connect}\n' "https://$INET_TARGET/" 2>/dev/null)
        [ -n "$t" ] && [ "$t" != "0.000000" ] && echo "$t" >>"$2"
        sleep 1
    done
}

# median_ms <file of seconds> -> median in ms
median_ms() {
    awk '{a[NR]=$1} END{if (NR==0) print 0; else if (NR%2) printf "%.3f\n", a[(NR+1)/2]*1000; else printf "%.3f\n", (a[NR/2]+a[NR/2+1])/2*1000}' "$1" 2>/dev/null
}


# Idle RTT via TCP connect (see connect_rtt for why not ping).
IDLE_INET_AVG=$(connect_rtt 5)
IDLE_INET_LOSS=0
[ -z "$IDLE_INET_AVG" ] && IDLE_INET_AVG=0

# --- phase 2/3: bursts + loaded RTT --------------------------------------

DOWN_INET=$(burst_down)
UP_INET=$(burst_up)

DOWN_INET_AVG=$(echo "$DOWN_INET" | cut -d' ' -f1)
DOWN_SPEED=$(echo "$DOWN_INET" | cut -d' ' -f2)
UP_INET_AVG=$(echo "$UP_INET" | cut -d' ' -f1)
UP_SPEED=$(echo "$UP_INET" | cut -d' ' -f2)

DOWN_OK=0; UP_OK=0
DOWN_BLOAT=0; UP_BLOAT=0
DOWN_GRADE="n/a"; UP_GRADE="n/a"

if [ "$DOWN_SPEED" -ge "$MIN_BURST_BPS" ] 2>/dev/null && [ -n "$DOWN_INET_AVG" ] && [ "$DOWN_INET_AVG" != "0" ]; then
    DOWN_OK=1
    DOWN_BLOAT=$(awk "BEGIN{print $DOWN_INET_AVG-$IDLE_INET_AVG}")
    DOWN_GRADE=$(grade_for "$DOWN_BLOAT")
fi
if [ "$UP_SPEED" -ge "$MIN_BURST_BPS" ] 2>/dev/null && [ -n "$UP_INET_AVG" ] && [ "$UP_INET_AVG" != "0" ]; then
    UP_OK=1
    UP_BLOAT=$(awk "BEGIN{print $UP_INET_AVG-$IDLE_INET_AVG}")
    UP_GRADE=$(grade_for "$UP_BLOAT")
fi

# --- push to VictoriaMetrics ---------------------------------------------

TS=$(date +%s)000
M="probe_idle_rtt_ms{target=\"$INET_TARGET\"} $IDLE_INET_AVG $TS
probe_idle_loss_percent{target=\"$INET_TARGET\"} $IDLE_INET_LOSS $TS
probe_burst_speed_bps{direction=\"down\"} ${DOWN_SPEED:-0} $TS
probe_burst_speed_bps{direction=\"up\"} ${UP_SPEED:-0} $TS
probe_burst_ok{direction=\"down\"} $DOWN_OK $TS
probe_burst_ok{direction=\"up\"} $UP_OK $TS"

if [ "$DOWN_OK" = "1" ]; then
    M="$M
probe_loaded_rtt_ms{direction=\"down\",target=\"$INET_TARGET\"} $DOWN_INET_AVG $TS
probe_bloat_ms{direction=\"down\"} $DOWN_BLOAT $TS
probe_bloat_grade{direction=\"down\",grade=\"$DOWN_GRADE\"} 1 $TS"
fi
if [ "$UP_OK" = "1" ]; then
    M="$M
probe_loaded_rtt_ms{direction=\"up\",target=\"$INET_TARGET\"} $UP_INET_AVG $TS
probe_bloat_ms{direction=\"up\"} $UP_BLOAT $TS
probe_bloat_grade{direction=\"up\",grade=\"$UP_GRADE\"} 1 $TS"
fi

printf '%s\n' "$M" > probe.prom
if curl -sS -A "$UA" -m 10 -X POST --data-binary @probe.prom "$VM_URL/api/v1/import/prometheus" >/dev/null 2>&1; then
    log "pushed (shaper ${SQM_DOWN_KBIT:-?}k/${SQM_UP_KBIT:-?}k): idle=${IDLE_INET_AVG}ms down=$(human_mbps "$DOWN_SPEED")/$([ "$DOWN_OK" = 1 ] && echo "+${DOWN_BLOAT}ms $DOWN_GRADE" || echo FAILED) up=$(human_mbps "$UP_SPEED")/$([ "$UP_OK" = 1 ] && echo "+${UP_BLOAT}ms $UP_GRADE" || echo FAILED)"
else
    log "ERROR pushing to $VM_URL"
    exit 1
fi
