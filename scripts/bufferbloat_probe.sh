#!/bin/sh
# bufferbloat_probe.sh — active latency-under-load probe for OpenWrt + VictoriaMetrics
#
# Every run:
#   1. Measures idle RTT (gateway + 1.1.1.1)
#   2. Saturates download for ~14s with MULTIPLE parallel connections while pinging
#   3. Saturates upload   for ~14s with MULTIPLE parallel connections while pinging
#   4. Computes bufferbloat grade (Waveform scale) and pushes metrics to VM
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
INET_TARGET="${INET_TARGET:-1.1.1.1}"
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 openwrt-view-bufferbloat-probe/1.5"
BURST_TIMEOUT=20           # curl max time per individual transfer (s)
DUR=14                     # seconds of sustained load per direction
DOWN_WORKERS=12
UP_WORKERS=4
UP_PAYLOAD_MB=90           # __up accepts ~100MB POSTs; 90 is safe
PING_COUNT=12              # samples per phase (1/s)
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

ping_stats() {  # $1=host -> echoes "avg loss"
    local out
    out=$(ping -c "$PING_COUNT" -W 2 -q "$1" 2>/dev/null | tail -2)
    local loss avg
    loss=$(echo "$out" | grep -o '[0-9.]*% packet loss' | grep -o '^[0-9.]*')
    avg=$(echo "$out" | sed -n 's/.*min\/avg\/max[^=]*= [0-9.]*\/\([0-9.]*\)\/.*/\1/p')
    [ -z "$avg" ] && { echo "0 100"; return; }
    echo "$avg ${loss:-0}"
}

current_gateway() {
    ip route show default 2>/dev/null | awk '{print $3; exit}'
}

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

# avg_rtt_from <ping output file> -> avg or 0
avg_rtt_from() {
    sed -n 's/.*min\/avg\/max[^=]*= [0-9.]*\/\([0-9.]*\)\/.*/\1/p' "$1" 2>/dev/null
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

# burst_down <ping_target> -> echoes "avg_rtt speed_bps" (avg 0 if burst failed)
burst_down() {
    local ptarget="$1" url probe_out total elapsed start avg SRCS=""
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
    start=$(date +%s)
    ping -c "$PING_COUNT" -W 3 -q "$ptarget" > ping.down 2>/dev/null &
    local PING_PID=$!
    local i=1 src
    # Pin each worker to one alive source (cyclically) so concurrent
    # connections spread evenly across servers.
    set -- $SRCS
    while [ "$i" -le "$DOWN_WORKERS" ]; do
        src=$(eval "echo \${$(( (i - 1) % $# + 1 ))}")
        down_worker "$src" &
        i=$((i + 1))
    done
    wait "$PING_PID" 2>/dev/null
    wait
    elapsed=$(( $(date +%s) - start )); [ "$elapsed" -ge 1 ] || elapsed=1
    total=$(awk '$2==200{s+=$1} END{print s+0}' down.parts)
    avg=$(avg_rtt_from ping.down)
    # push bits/s (metric name is probe_burst_speed_bps)
    echo "${avg:-0} $(awk "BEGIN{printf \"%.0f\", $total*8/$elapsed}")"
}

# burst_up <ping_target> -> echoes "avg_rtt speed_bps" (avg 0 if burst failed)
burst_up() {
    local ptarget="$1" total elapsed start avg
    mkdir -p "$TMP"
    [ -f "$TMP/payload.bin" ] || \
        dd if=/dev/urandom of="$TMP/payload.bin" bs=1M count="$UP_PAYLOAD_MB" 2>/dev/null
    [ -f "$TMP/payload.bin" ] || { log "cannot create upload payload"; echo "0 0"; return; }

    : > up.parts
    start=$(date +%s)
    ping -c "$PING_COUNT" -W 3 -q "$ptarget" > ping.up 2>/dev/null &
    local PING_PID=$!
    local i=1
    while [ "$i" -le "$UP_WORKERS" ]; do
        up_worker &
        i=$((i + 1))
    done
    wait "$PING_PID" 2>/dev/null
    wait
    elapsed=$(( $(date +%s) - start )); [ "$elapsed" -ge 1 ] || elapsed=1
    total=$(awk '$2==200{s+=$1} END{print s+0}' up.parts)
    avg=$(avg_rtt_from ping.up)
    # push bits/s (metric name is probe_burst_speed_bps)
    echo "${avg:-0} $(awk "BEGIN{printf \"%.0f\", $total*8/$elapsed}")"
}

# --- phase 1: idle RTT ---------------------------------------------------

GW=$(current_gateway)
IDLE_GW=$(ping_stats "$GW" 2>/dev/null)
IDLE_INET=$(ping_stats "$INET_TARGET")

IDLE_GW_AVG=$(echo "$IDLE_GW" | cut -d' ' -f1)
IDLE_INET_AVG=$(echo "$IDLE_INET" | cut -d' ' -f1)
IDLE_INET_LOSS=$(echo "$IDLE_INET" | cut -d' ' -f2)
[ -z "$IDLE_INET_AVG" ] && IDLE_INET_AVG=0

# --- phase 2/3: bursts + loaded RTT --------------------------------------

DOWN_INET=$(burst_down "$INET_TARGET")
UP_INET=$(burst_up "$INET_TARGET")

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
probe_idle_rtt_ms{target=\"gateway\"} $IDLE_GW_AVG $TS
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
