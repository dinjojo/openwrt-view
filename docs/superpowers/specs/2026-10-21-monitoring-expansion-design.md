# Monitoring Expansion — Buffering Incidents, Latency Quality, Tunnel & Connection Health

**Date:** 2026-10-21
**Status:** Implemented in v2.2.0 (conntrack check, tunnel card, latency percentiles, buffering episodes) — DNS/DHCP follow-ups noted below
**Scope:** openwrt-view v2.x single binary (Go + embedded UI) on NanoPi R6C / OpenWrt 25.12.4, VictoriaMetrics on-router

## Intent and why

The user's overall aim: **find out if there is buffering, why it is happening, and how many times it has happened** — plus honest latency quality numbers (p50/p95) and the tunnel/firewall/connection-health coverage discussed in-thread. The dashboard must give a clear signal when something is wrong, in plain language, without raw-data interpretation burden. Everything runs on the router; no Grafana; the UI is viewed from another machine's browser.

## Goals

1. **Buffering incident detection and counting** — "this happened N times, here is when, here is why it likely happened."
2. **Latency quality with percentiles** — p50/p95 for WAN RTT and loaded latency, computed from VictoriaMetrics history.
3. **WARP tunnel detail** — state, handshake freshness, transfer counters and rates, reconnect history (surface what the poller already collects).
4. **Connection & security health** — conntrack utilization and exhaustion events, WAN unsolicited-traffic trend, router config-change events, DHCP sanity.

## Non-goals / anti-goals

- No per-IP firewall labels or packet-level logging (high cardinality, storage, privacy).
- No DNS query-log dashboard — AdGuard Home's own UI already covers queries/blocks; duplicating it adds storage and a privacy surface. Take only a service-health signal.
- No new external dependencies; single static binary; all storage on the router's NVMe.
- No panel overload: new signals fold into the existing tabs (Overview + System), reusing card/panel patterns.

## What exists today (verified)

- **WARP:** `pkg/sysmon` WarpPoller reads `wg show wg0 dump` every 30 s (handshake, rx/tx totals, rates); `evalWarp` health check; events on tunnel down/up. UI shows only "exit: via WARP" in the Overview Internet footer.
- **Firewall:** FWPoller reads aggregate end-of-chain nft counters (`openwrt-view: unsolicited inbound/forward` in `input_wan`/`forward_wan`) every 30 s with a 240-sample rolling median; `evalWANRejects` is baseline-aware (warn at 10× median, crit at 50×).
- **Conntrack:** `collectd_conntrack` + `collectd_conntrack_percent` already scraped into VM and charted in System history; **no max/utilization check, no insert-failure detection**.
- **Probe:** `/opt/monitoring/scripts/bufferbloat_probe.sh` hourly (11:00–20:00) pushes `probe_bloat_ms{direction=down|up}`, `probe_burst_speed_bps`, `probe_idle_rtt_ms`, `probe_loaded_rtt_ms`, `probe_idle_loss_percent` to VM. Verified flowing (latest 09:30 today, bloat −1.7 ms).
- **RTT:** `collectd_ping` to 1.1.1.1 and 8.8.8.8 continuously; `collectd_ping_ping_droprate` for loss.
- **Events ring:** persistent (200 events, `/opt/monitoring/openwrt-view-events.json`), kinds wan/warp/reboot/probe/monitor; surfaced in Overview Events panel.

## Design

### 1. Buffering incidents (the headline)

**"Buffering" here means bufferbloat** — queueing delay when the line saturates — which is the thread's whole premise (SQM, latency under load, probe grades). Stream stalls can also come from WARP throughput, Wi-Fi, CDN or DNS; those show up via the exit-tunnel card, health checks and AdGuard, not the incident list. Known blind spot, documented: the passive RTT detector probes the **direct WAN path**, so a WARP-path-only stall is invisible to it — the WARP card's handshake/transfer signals cover that path instead.

Two detectors, one incident list:

- **Active (probe):** a probe run whose `probe_bloat_ms` for either direction exceeds **+30 ms** is an incident sample. Consecutive above-threshold samples collapse into one *episode* (start, end, peak, direction).
- **Passive (24/7, between probes):** `collectd_ping` RTT sampled while WAN utilization (from `collectd_interface_if_octets_*` on the WAN iface, derived against the 415 Mbit shaper) exceeds ~70% and RTT exceeds the rolling idle baseline by **+30 ms** for **≥ 2 consecutive samples**. This catches bufferbloat during real usage (e.g. a big download at 3 AM) that the daytime-only probe never sees.
- Episodes are queried from VM on demand (`/api/incidents?range=24h|7d|30d`), so nothing new must be stored — VM already holds the raw series. Response: count, per-episode start/duration/direction/peak-ms, and a one-line plain-language cause hint ("download at 95% of shaper when it started").
- Range/resolution policy: **passive** episodes offered at 24 h and 7 d (ping samples are ~10 s native; at 30 d VM range-step would average neighbours and defeat the ≥2-consecutive rule). **Active-probe** episodes (15 min raw) are fine at 24 h / 7 d / 30 d.
- The events ring grows 200 → **1000 entries** (still ~100 KB on NVMe), and **probe events become conditional**: only a below-expected grade or bloat above threshold is an event — clean runs stay off the timeline, otherwise probe spam drowns real events at ~62/day.
- Overview gets a **"Buffering" card**: incidents in last 24 h, worst episode, and grade; clicking drills into the incident list with a timeline chart (VM-backed).
- New events kind `bloat` in the events ring when an episode is detected (checked on the existing 15 s event watcher — cheap VM instant queries).

**Threshold (+30 ms, ≥2 samples) is my call** — sane default; make it configurable via flags later. Note in UI that the probe grade is a ceiling (probe burst reaches ~87% of shaper).

### 2. Latency quality (p50/p95)

- Server-side `/api/percentiles?range=24h|7d` computing from VM range data:
  - `collectd_ping` p50/p95 **per target** (1.1.1.1, 8.8.8.8) — "your line's resting latency".
  - `probe_loaded_rtt_ms` p95 vs `probe_idle_rtt_ms` median — "latency under load".
  - `collectd_ping_ping_droprate` mean p95 — packet loss.
- Computed in Go (sort the sampled values; no quantile approximation needed at these sizes).
- Placement: a compact "Latency quality" strip in the System tab — four numbers with plain-language captions ("half your pings were faster than 4.1 ms").
- **DNS p50/p95 is not possible** from AdGuard Home — it exports only an average processing time. Documented as a limitation; the dashboard shows DNS via AdGuard's own dashboard link and we keep no copy of query data.

### 3. WARP tunnel panel

- Extend the System tab with an "Exit tunnel (WARP)" card fed by the existing WarpState snapshot (expose it via the SSE stats payload — poller already runs):
  - state: fresh handshake age ("handshake 12 s ago — healthy" / stale warning at >3 min), endpoint, transfer totals + current rx/tx rates.
  - reconnect count in the last 24 h / 7 d from the events ring (warp kinds).
  - CPU of encryption workloads is not separately measurable here (in-kernel); CPU load card already covers router-wide load — documented as such.

### 4. Connection & security health

- **Conntrack:** new small poller reading `/proc/sys/net/netfilter/nf_conntrack_count` and `..._max` (cheap, every 30 s) plus `/proc/net/stat/nf_conntrack` per-CPU counters. **Counter semantics (corrected during builder review):** a full table shows up as `drop`/`early_drop` — sustained rate above zero is a **crit** ("the router ran out of connection tracking — new connections were refused"). `insert_failed` also counts benign NAT/UDP clash races on healthy routers, so it is a **warn** only when it arrives as a burst (edge-triggered, never latched). Utilization: warn ≥70%, crit ≥90%. Utilization joins the System tab Gateway card gauge row; exhaustion events go to the events ring.
- **WAN unsolicited traffic:** chart the existing FWPoller rolling rate (per min) in System — already baseline-aware in health; now visible as a sparkline so "normal" vs "scanning" is obvious.
- **Config changes:** poller hashes `/etc/config/*` every 5 min; on change, add an event listing which file changed. Router config drift becomes visible in the timeline.
- **DHCP sanity:** count active leases (dnsmasq lease file) vs pool size; warn only when pool usage >90%. Low priority, cheap to add.
- **Rejected with reasons:** top source IPs of rejected WAN traffic (cardinality/privacy — aggregate counters suffice for a home network); per-rule firewall counters (rule churn on upgrade, no actionable signal); new-connections-per-second precise rate (no cheap kernel source via collectd/node-exporter; conntrack-utilization spikes catch the same failure mode); UPnP (miniupnpd not installed — leftover UCI config only).

## Constraints

- Router CPU/arm64, 4 GB RAM; VM retention on NVMe; dropbear SSH for deploys (`scp -O`).
- All polling must be trivially cheap: /proc reads, existing pollers, VM queries — no new daemons.
- UI patterns reuse the existing card/gauge/panel system and theme tokens (slate dark, porcelain light, Fira Sans/Fira Code).

## Left to the builder

- Exact UI placement and panel composition within the stated tabs.
- Episode-grouping implementation details; flag names for thresholds.
- Whether the incident cause-hint logic lives server- or client-side.
