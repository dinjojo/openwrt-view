# openwrt-view — PRODUCT.md

## Users
The user, the household's network operator. Checks the dashboard several times a day
from a phone (PWA, added to home screen) and a laptop, most often in the evening in the
living room. Occasional deeper debugging sessions when something feels slow.

## Product Purpose
Single-binary monitoring panel for an OpenWrt NanoPi R6C router with a Netgear Orbi mesh.
Answers in one glance: is anything wrong (WAN, Wi-Fi mesh, SQM latency, satellites)?
Then supports drilling into which device, which band, and since when. It shows live
throughput, per-client Wi-Fi signal, SQM/CAKE queue health, buffering episodes, 7-day
reports, and per-device usage history.

## Accessibility & Inclusion
State must be readable at a glance and at arm's length: indicator semantics never rely
on colour alone (label + state text always present). Body text ≥4.5:1 contrast. Tables
and readouts use tabular numerals so columns hold still. Touch targets work on a phone.

## Product Truth (fixed, do not redesign away)
- Tabs: Overview / Diagnostics / SQM / Clients / System. All data is real, from the
  router's own counters, a VictoriaMetrics store, and hourly latency probes. No demo data.
- Plain-language verdicts are the product's voice: "quiet air", "no buffering in 24h".
  Controls name their action. No marketing copy anywhere.
- Everything runs offline on the LAN; no external font hosts or CDNs at runtime.
