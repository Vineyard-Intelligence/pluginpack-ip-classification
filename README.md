# IP Classification

A Vineyard plugin pack. Answers **why** an address showed up — internet-wide scanner, C2
infrastructure, crawler, anonymizer, or space that should never be routed. One plugin, **IP Classification**,
which runs on the selected IP Address nodes: select one or many and every field below is filled in.

Address data is not embedded. The plugin reads one /8 shard per address from
[ip-observation-history](https://github.com/Vineyard-Intelligence/ip-observation-history), which
collects the published lists: [OpenFilters/internet-scanners](https://github.com/OpenFilters/internet-scanners),
[HL-SOC/C2-Tracker](https://github.com/HL-SOC/C2-Tracker), FireHOL, Team Cymru, and vendors that publish
their own crawler or VPN ranges.

## Fields

| Field | Values |
|---|---|
| `ip_scope` | `private`, `loopback`, `cgnat`, `link_local`, `multicast`, `reserved`, `documentation`, `benchmark`, `unallocated` — omitted for ordinary public addresses, which have nothing to report |
| `scanner` | `shodan` `censys` `tenable` `binaryedge` … (22) |
| `crawler` | `googlebot` `bingbot` `applebot` `gptbot` `claudebot` … |
| `anonymizer` | `nordvpn_entry` `mullvad_entry` … `tor_exit_node` `socks_proxy` `icloud_private_relay` |
| `c2_family` | `cobalt_strike` `sliver` `remcos` … (36) |
| `tags` | `scanner` `c2` `crawler` `anonymizer` `bogon` |
| `scanner_source`, `crawler_source`, `anonymizer_source`, `c2_source` | the feed each value came from, pinned to the commit it was read at |
| `scanner_` / `crawler_` / `anonymizer_` / `c2_` + `first_seen`, `last_seen` | when the feed first and last listed the address (ISO 8601) |

Every value is `snake_case`. VPN providers publish their **connection endpoints**, not their egress
addresses, so those values carry `_entry`. A C2 hit creates a Tool or Malware node and links it with a
`used as C2` edge.

## Build

```bash
npm run update-data   # refresh the source metadata the bundle embeds
npm run build         # bundle + manifest
npm run test          # 19 tests
npm run sources       # refresh the source table in ip-observation-history
npm run serve         # dev server on 8787
```

The bundle is 19 KiB — source lists are not embedded, only the C2 family metadata. A run reads
`index.json` (12 KiB, once) plus one shard per distinct /8 (about 2 KiB). **IPv4 only.**
