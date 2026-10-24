# openwrt-view: design system

This file describes the system that ships in `pkg/server/index.html`. It was
written from the built page. When the page and this file disagree, the page
is right, so fix this file.

**World: "Machined instrument".** The dashboard looks like one control unit
milled from warm aluminum. Engraved rules separate the regions, so there are
no floating cards. Colour shows state through indicator lamps, and every lamp
has state text beside it. Live measurements are set in a mono face with
tabular figures. Mode: Operate. Colour strategy: Restrained, meaning warm
neutrals, one signal-amber accent, and the lamp hues.

## Tokens

All tokens are CSS custom properties on `:root` (light) and
`html[data-theme="dark"]`. The theme toggle sets `data-theme` and
reloads the page, so canvas charts pick up the new colours.

| Role | Token | Evening (dark, default) | Daylight (light) |
|---|---|---|---|
| Surround behind the unit | `--ground` | `#121110` | `#d6d1c6` |
| Aluminum face | `--panel` | `#1f1e1b` | `#e8e5de` |
| Recessed well (rail, meters, table heads, inputs) | `--well` | `#181715` | `#dedad1` |
| Chart paper (tape bed) | `--tape` | `#161513` | `#f2efe7` |
| Engraved line, shadow side | `--groove` | `#0b0a09` | `#b3ac9f` |
| Engraved line, lit side | `--ridge` | `#33312c` | `#f8f6f1` |
| Row separators, chart grid | `--hair` | `#2b2a26` | `#d2cdc2` |
| Enamel ink | `--ink` | `#ece9e2` (13.8:1) | `#1d1b17` (13.7:1) |
| Secondary ink | `--ink-2` | `#bdb7ab` (8.4:1) | `#4a463e` (7.5:1) |
| Tertiary ink | `--ink-3` | `#959084` (5.2:1) | `#645f55` (5.0:1) |
| Signal amber: selection, live data, active controls | `--accent` | `#e0a458` | `#824e0e` (text-safe) |
| Chart ink for the accent | `--accent-ink` | `#e0a458` | `#b06a1c` |
| Text on accent | `--on-accent` | `#1c1b19` | `#fbf7ef` |
| Download series | `--dl` | = `--accent-ink` | = `--accent-ink` |
| Upload series (blued steel) | `--ul` | `#a9b8c4` | `#5d6f7d` |
| State text | `--ok` `--warn` `--crit` | `#8fbe78` `#f0c35a` `#ef7a6e` | `#2f6a27` `#765200` `#b0322a` |
| Lamp lenses | `--lamp-ok` `--lamp-warn` `--lamp-crit` `--lamp-off` | `#7fb069` `#f2b632` `#e5534b` `#3d3b36` | `#5f9a45` `#e0a81e` `#d2443a` `#bdb7ab` |
| Modal scrim | `--scrim` | `rgba(6,5,4,.66)` | `rgba(40,36,30,.45)` |
| Lifted surface (tooltip, dialog) | `--lift` | offset and soft blur, never a zero-blur shadow | same |

Contrast ratios are measured against `--panel`. Every text token, including
`--warn` on `--well`, clears 4.5:1 in both themes.

**Legacy aliases.** The scripts read some colours through older names:
`--green` → `--ok`, `--amber` → `--warn`, `--red` → `--crit`,
`--muted` → `--ink-2`, `--faint` → `--ink-3`, `--text` → `--ink`,
`--panel2` → `--well`, `--line` → `--groove`, `--bg` → `--ground`. Keep the
aliases until every script reference has moved to the semantic name.

**Browser surfaces.** The browser's own parts are themed from the same
palette:
- `::selection` is the accent at 38% opacity.
- `caret-color` is the accent.
- `:focus-visible` draws a 2px accent outline with a 2px offset.
- Scrollbars use a `--ridge` thumb on a `--well` track, set with both
  `scrollbar-color` and the `::-webkit-scrollbar` rules.

## Type

The two families ship as OFL woff2 files in `web/fonts/`. They are embedded as
`data:` URIs in `@font-face`, because the binary serves only this HTML file.
No font host is contacted at runtime.

- **Bitter** (variable, 100–900; contemporary slab serif drawn for screens)
  sets all UI text. Its slab serifs give the panel an engraved-equipment-label
  voice that grotesque dashboards don't have. Headings use weight 600 with
  tracking of -0.01em; body stays at 400.
- **Azeret Mono** (variable, 100–900) sets measurements, tables of
  numbers, chart axes and range controls. It is always tabular (`.num`, or
  `--f-num` set directly). Mono is used only for data, never as decoration.

The scale uses a ratio of about 1.125 on a 14px body. The tokens are fixed rem
values:

| Token | Size | Use |
|---|---|---|
| `--t-2xs` | 11px | phone tab labels, tier group names |
| `--t-xs` | 12px | meter sub-lines, chart legends, axis numerals (11px canvas) |
| `--t-sm` | 13px | secondary text, table cells, lamp state |
| `--t-base` | 14px | body |
| `--t-md` | 16px | section headings (`.h2`) |
| `--t-lg` | 18px | wordmark |
| `--t-xl` | 22px | meter values |
| `--t-display` | 32px (28px on phones) | throughput readout, the largest type on the surface |

There are no eyebrows, kickers, or uppercase tracked labels. A heading carries
its own weight, and a quieter qualifier can follow it inline
(`<h2>Top clients <span class="sub">this billing period</span></h2>`).

## Spacing and shape

- **Spacing** follows a 4px rhythm: `--s1` 4, `--s2` 8, `--s3` 12, `--s4` 16,
  `--s5` 24, `--s6` 32. Sections pad by `--s5` on desktop and `--s4` on
  phones, held in `--pad`. Meters, lists and table rows are packed tight;
  sections get generous space between them.
- **Radii** are small and used sparingly: `--r-sm` 4px for controls, wells and
  tape, `--r-md` 6px for tooltips, and `--r-lg` 8px for the unit and dialogs.
- **Elevation** is declared once. Inside the unit there are no shadows. Only
  the lamp tooltip and the dialogs lift, using `--lift`.

## Component vocabulary

- **Unit (`.unit`).** The single panel, at most 1480px wide, centred on
  `--ground` with a 1px groove border. On phones it runs edge to edge.
- **Engraved section (`.sect`).** Each section has a `--ridge` top edge and a
  `--groove` bottom edge. Stacked sections therefore read as one cut line:
  dark then light. Side-by-side regions use `.split > .cell` with the same
  pair running vertically. At 900px and below the cells stack.
- **Lamp (`.lamp[data-state]`).** A 10px incandescent lens: a flat fill with a
  darker rim of the same hue. There is no glow. States are
  `ok`/`warn`/`crit`/`info`/`unknown` (unlit). Sizes are `.sm` 8px and
  `.lg` 14px. A lamp always sits beside a label or a state word. Built with
  `lamp(state, size)` in the script.
- **Lamp bank (`#lamp-bank`).** A seamed grid of `.lampcell` buttons across
  the top of every tab:
  - The lamps are WAN, Exit path, Wi-Fi, SQM, Router, and one per mesh
    satellite. Each reads `Name · state text`.
  - The summary cell (`#health-summary`) ends the row.
  - Clicking a lamp opens the tab that owns that subsystem.
  - Hovering or focusing a lamp shows `.lc-tip`, the last event of that
    lamp's kind from `/api/events` (wan/reboot, warp, orbi, probe,
    satellite). The Router lamp has no event source, so it has no tooltip.
  - On phones the bank becomes two columns.
- **The one motion.** When a lamp changes state it flares once (`.flare`,
  220ms, `cubic-bezier(.16,1,.3,1)`, scaling from 1.7× with a brightness
  lift). Nothing else animates except the 160ms chevron on disclosure rows.
  `prefers-reduced-motion` turns both off.
- **Bezel rail (`.bezel`, `.tab-btn`).** Tabs cut into a recessed rail. The
  active tab takes the panel colour and joins the content below it, with its
  icon in accent. The rail is sticky on desktop. On phones it becomes a fixed
  bottom bar with an icon over each label, and an accent top edge marks the
  active tab.
- **Throughput instrument (`.instrument`).**
  - The readout (`.ro`) shows current download in accent and upload in ink,
    as 32px mono with a unit label, updated on every SSE sample. Below it sit
    the WAN state line, the WARP line, and a link to line diagnostics.
  - The paper tape (`#ov-tape`) is a uPlot strip chart on `--tape` with hair
    grid lines, mono axis numerals, an amber download trace with a 9% fill,
    and a steel upload trace.
  - A `5M` / `3H` / `24H` segmented control picks the span. `5M` is the live
    SSE ring and advances every second. `3H` and `24H` use the 5-minute
    system history.
  - Below 1100px the readout sits above the tape.
- **Meters (`.meters > .meter`).** A seamed cluster of readings inside one
  recessed well. Each cell has a label (`.m-lab`), a mono value (`.m-val`), a
  sub-line (`.m-sub`), and optionally a thin `.bar` or an `.m-spark` trace.
  Unfilled slots stay the well colour. Used for SQM per-interface rows,
  exit paths, latency quality, the router-health strip, the clients summary
  and the radio environment.
- **Rows (`.rows > .lrow`, `.ev`, `.check`).** Lists separated by `--hair`
  lines:
  - `.lrow` is a general list row.
  - `.ev` is an event row with a lamp, a mono time and the message.
  - `.check` is a problem row with a lamp, name, state word, value and plain
    detail.
- **Keys (`.key`).** Small machined buttons, each with a lamp, a label and a
  value. They are the healthy health-check groups, and each jumps to its tab.
- **Segmented control (`.seg`).** A recessed track holding mono buttons. The
  active button (`.on`, `aria-pressed`) is an accent block with
  `--on-accent` text. All range pickers use it.
- **Table (`.tbl`).**
  - Rows are dense, with a `--well` header and hair row lines.
  - Numeric columns (`.r`) are right-aligned and mono.
  - Group rows (`.grp`) carry an icon and a label over a groove underline. No
    coloured side borders.
  - Clickable rows (`tr[data-mac]`) highlight to `--well` and can be focused
    with the keyboard.
  - On phones, tables scroll inside `.overflow-x-auto` while the page itself
    stays at 390px.
  - The SQM per-tin table (`.tier`) has a sticky field column.
- **Chart (`makeChart`).** uPlot with an `.chart-title`, hair grid lines, mono
  11px axes and a custom `.chart-legend`. Clicking a client series opens that
  client's drill-down; it never hides the series.
- **Dialog (`.modal > .dialog`).** A panel-coloured sheet on `--scrim`, with no
  blur. The head holds the title, a segmented range control and an icon close
  button. On phones the dialog goes full screen.

## Icons

The icons are authored inline SVG, 24px viewBox, 2px stroke with round caps
and joins, in `currentColor`. Direction in text uses the ↓ and ↑ arrows, which
are in the Bitter latin subset. No emoji, and no Unicode glyphs as icons.

## Offline

Everything the page needs is inside `index.html`:
- uPlot 1.6.31 (MIT), its CSS and JS inlined.
- The two fonts, as data URIs.

At runtime the page requests only same-origin `/api/*`, `/events`,
`/manifest.webmanifest` and `/icon-512.png`.
