// Single source of truth for where the snapshot comes from.
//
// `remote: true` means the Vineyard web sandbox can fetch it directly, so the data ships FRESH on
// every run. That is not a preference — it is the CORS measurement (2026-10-24, Origin:
// https://app.vineyard.run):
//
//   raw.githubusercontent.com  access-control-allow-origin: *   → remote
//   openai.com                 access-control-allow-origin: *   → remote
//   airvpn.org                 access-control-allow-origin: *   → remote
//   developers.google.com / bing.com / search.developer.apple.com / claude.com /
//   perplexity.com / team-cymru.org / api.mullvad.net / api.nordvpn.com /
//   privadovpn.com / api.surfshark.com / api.ivpn.net           → no CORS header → bundled
//
// Surfshark and IVPN are bundled for a second reason: their APIs return hostnames, and a browser
// cannot resolve DNS, so those addresses only exist if the build resolves them. VyprVPN and
// TorGuard publish .ovpn archives that have to be unpacked at build time.
import { execFileSync } from "node:child_process";

export const OPENFILTERS = "https://raw.githubusercontent.com/OpenFilters/internet-scanners/main/cidr";
export const C2TRACKER = "https://raw.githubusercontent.com/HL-SOC/C2-Tracker/main/data";
export const BOGON_URL = "https://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt";
// Tor exit list. The Tor Project's own endpoints (check.torproject.org/torbulkexitlist,
// onionoo.torproject.org) either omit CORS or cost ~190 KB uncompressed per run, which dominates the
// whole pack. FireHOL republishes the same TorDNSEL data (source: check.torproject.org/exit-addresses)
// as an ipset on GitHub raw: `access-control-allow-origin: *`, ~5 KB gzipped, regenerated every five
// minutes, and 96.8% identical to Onionoo's current exit set (measured 2026-10-24).
// Fallback if this ever stops: https://onionoo.torproject.org/details?type=relay&flag=Exit&fields=exit_addresses
export const TOR_URL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/tor_exits.ipset";

// FireHOL republishes several operator lists on GitHub raw (CORS `*`, ipset format). Only the ones
// that are both current and small are used; each was checked for its own "This File Date":
//   socks_proxy.ipset  302 entries, 10-min refresh  → adopted
//   sslproxies.ipset   102 entries, 10-min refresh  → adopted
//   cidr_report_bogons.netset  stale since 2024-12  → not used (Team Cymru stays)
//   maltrail_scanners.ipset    16,854 entries but last built 2026-03-30 → not used
//   c2_tracker.ipset           2,470 entries, mirrors the archived tracker, no family names → not used
//   firehol_anonymous.netset   8.1 MB gzipped → far too large for a per-run fetch
// FireHOL ships four variants of every list and they mean different things:
//   socks_proxy.ipset      Aggregation: none    → active RIGHT NOW        (302)
//   socks_proxy_1d.ipset   Aggregation: 1 day   → union over 1 day        (1,469)
//   socks_proxy_7d.ipset   Aggregation: 7 days  → union over 7 days       (2,592)
//   socks_proxy_30d.ipset  Aggregation: 30 days → union over 30 days      (4,340)
// Only the base file is used: the field answers "is this address a proxy now", and an address that
// was a proxy three weeks ago is usually an ordinary user's by now. The _Nd variants are history,
// which is exactly what would make the label wrong.
export const PROXY_URLS = [
  ["SOCKS proxy", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/socks_proxy.ipset"],
  ["SSL proxy", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/sslproxies.ipset"],
];
export const RELAY_URL = "https://raw.githubusercontent.com/hroost/icloud-private-relay-iplist/main/ipv4/ipv4-ranges.txt";

// Churn decides delivery for scanners. Measured with scripts/churn.mjs (git history, 180 days):
// the six below changed 3+ times; the other sixteen changed 0-1 times in the same window, so paying
// a request per run for them buys nothing. `remote` follows that measurement, not taste.
/**
 * Machine-readable value for a source: lowercase snake_case. Names carry spaces, hyphens and
 * parentheses ("palo alto expanse", "brute ratel c4", "group-ib"), none of which belong in a value a
 * filter or a GROUP BY has to touch.
 */
const toSnake = (name) => name.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");

const DYNAMIC_SCANNERS = new Set(["hunter", "fofa", "strechoid", "quake", "binaryedge", "groupib"]);

// [slug, display name]
export const SCANNERS = [
  ["shodan", "Shodan"],
  ["censys", "Censys"],
  ["tenableasm", "Tenable"],
  ["binaryedge", "BinaryEdge"],
  ["strechoid", "Stretchoid"],
  ["hunter", "Hunter"],
  ["quake", "Quake"],
  ["fofa", "FOFA"],
  ["zoomeye", "ZoomEye"],
  ["leakix", "LeakIX"],
  ["netlas", "Netlas"],
  ["onyphe", "ONYPHE"],
  ["criminalip", "Criminal IP"],
  ["bitsight", "Bitsight"],
  ["paloaltonetworks", "Palo Alto Expanse"],
  ["recordedfuture", "Recorded Future"],
  ["mandiantasm", "Mandiant"],
  ["groupib", "Group-IB"],
  ["virustotal", "VirusTotal"],
  ["intrinsec", "Intrinsec"],
  ["shadowserver", "Shadowserver"],
  ["rapid7", "Rapid7"],
];

// [file stem, display name, node kind, node type value]
export const C2 = [
  ["Cobalt Strike C2", "Cobalt Strike", "tool", "c2"],
  ["Sliver C2", "Sliver", "tool", "c2"],
  ["Metasploit Framework C2", "Metasploit", "tool", "c2"],
  ["Mythic C2", "Mythic", "tool", "c2"],
  ["Havoc C2", "Havoc", "tool", "c2"],
  ["Brute Ratel C4", "Brute Ratel C4", "tool", "c2"],
  ["Covenant C2", "Covenant", "tool", "c2"],
  ["Empire C2", "Empire", "tool", "c2"],
  ["Posh C2", "Posh", "tool", "c2"],
  ["Caldera C2", "Caldera", "tool", "c2"],
  ["Deimos C2", "Deimos", "tool", "c2"],
  ["NimPlant C2", "NimPlant", "tool", "c2"],
  ["Viper C2", "Viper", "tool", "c2"],
  ["Villain C2", "Villain", "tool", "c2"],
  ["Supershell C2", "Supershell", "tool", "c2"],
  ["RedGuard C2", "RedGuard", "tool", "c2"],
  ["PANDA C2", "PANDA", "tool", "c2"],
  ["Hak5 Cloud C2", "Hak5 Cloud C2", "tool", "c2"],
  ["Unam Web Panel", "Unam Web Panel", "tool", "c2"],
  ["Sectop RAT", "Sectop", "malware", "rat"],
  ["Quasar RAT", "Quasar", "malware", "rat"],
  ["Remcos RAT", "Remcos", "malware", "rat"],
  ["njRAT Trojan", "njRAT", "malware", "rat"],
  ["NanoCore RAT Trojan", "NanoCore", "malware", "rat"],
  ["DcRAT", "DcRAT", "malware", "rat"],
  ["AsyncRAT", "AsyncRAT", "malware", "rat"],
  ["Gh0st RAT Trojan", "Gh0st", "malware", "rat"],
  ["XtremeRAT Trojan", "XtremeRAT", "malware", "rat"],
  ["DarkComet Trojan", "DarkComet", "malware", "rat"],
  ["NetBus Trojan", "NetBus", "malware", "rat"],
  ["Hookbot", "Hookbot", "malware", "rat"],
  ["ShadowPad", "ShadowPad", "malware", "backdoor"],
  ["GoPhish", "GoPhish", "tool", "utility"],
  ["XMRig Monero Cryptominer", "XMRig", "tool", "utility"],
  ["BurpSuite", "BurpSuite", "tool", "utility"],
  ["MobSF", "MobSF", "tool", "recon"],
];

// [display name, url, kind, remote]
// kind tells the runtime parser how to read the payload; "prefixes" is the Google/OpenAI style JSON.
export const BOTS = [
  ["Googlebot", "https://developers.google.com/static/search/apis/ipranges/googlebot.json", "prefixes", false],
  ["Google Special Crawlers", "https://developers.google.com/static/search/apis/ipranges/special-crawlers.json", "prefixes", false],
  ["Google User-Triggered", "https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers.json", "prefixes", false],
  ["Bingbot", "https://www.bing.com/toolbox/bingbot.json", "prefixes", false],
  ["Applebot", "https://search.developer.apple.com/applebot.json", "prefixes", false],
  ["GPTBot", "https://openai.com/gptbot.json", "prefixes", true],
  ["OAI-SearchBot", "https://openai.com/searchbot.json", "prefixes", true],
  ["ChatGPT-User", "https://openai.com/chatgpt-user.json", "prefixes", true],
  ["ClaudeBot", "https://claude.com/crawling/bots.json", "prefixes", false],
  ["PerplexityBot", "https://www.perplexity.com/perplexitybot.json", "prefixes", false],
];

/** Remote endpoints that publish `.ovpn` archives; the build unpacks them. */
export function ovpnRemotes(zipPath) {
  let text = "";
  try {
    text = execFileSync("unzip", ["-p", zipPath, "*.ovpn"], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  } catch {
    return [];
  }
  return text
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.startsWith("remote "))
    .map((l) => l.split(/\s+/)[1])
    .filter(Boolean);
}

// VPN providers. `extract` turns the payload into endpoints (addresses or hostnames);
// `resolve` marks payloads whose endpoints are hostnames that only the build can resolve.
export const VPN = [
  {
    name: "NordVPN",
    label: "nordvpn_entry",
    url: "https://api.nordvpn.com/v2/servers?limit=0",
    remote: false,
    kind: "json",
    extract: (d) => (d.servers ?? []).map((s) => s?.station),
  },
  {
    name: "Mullvad",
    label: "mullvad_entry",
    url: "https://api.mullvad.net/www/relays/all/",
    remote: false,
    kind: "json",
    extract: (d) => (Array.isArray(d) ? d : []).map((r) => r?.ipv4_addr_in),
  },
  {
    // Bundled on purpose: the payload is ~215 KB of server metadata for ~1,000 addresses, and it was
    // 70% of the per-run transfer. Flip this to true to trade freshness for 210 KiB per run.
    name: "AirVPN",
    label: "airvpn_entry",
    url: "https://airvpn.org/api/status/",
    remote: false,
    kind: "airvpn",
    extract: (d) => (d.servers ?? []).flatMap((s) => [s?.ip_v4_in1, s?.ip_v4_in2, s?.ip_v4_in3, s?.ip_v4_in4]),
  },
  {
    name: "Privado",
    label: "privado_entry",
    url: "https://privadovpn.com/apps/servers_export.json",
    remote: false,
    kind: "json",
    extract: (d) => (d.servers ?? []).map((s) => s?.ip),
  },
  {
    name: "Surfshark",
    label: "surfshark_entry",
    url: "https://api.surfshark.com/v4/server/clusters/generic",
    remote: false,
    resolve: true,
    kind: "json",
    extract: (d) => (Array.isArray(d) ? d : []).map((c) => c?.connectionName),
  },
  {
    name: "IVPN",
    label: "ivpn_entry",
    url: "https://api.ivpn.net/v4/servers/stats",
    remote: false,
    resolve: true,
    kind: "json",
    extract: (d) => (d.servers ?? []).flatMap((s) => Object.values(s?.hostnames ?? {})),
  },
  {
    name: "VyprVPN",
    label: "vyprvpn_entry",
    url: "https://support.vyprvpn.com/hc/article_attachments/46761120489229",
    remote: false,
    kind: "ovpnzip",
    resolve: true,
  },
  {
    name: "TorGuard",
    label: "torguard_entry",
    url: "https://torguard.net/downloads/OpenVPN-TCP-Linux.zip",
    remote: false,
    kind: "ovpnzip",
  },
];

/** Every download the snapshot needs, tagged with the bucket it feeds and whether it ships remote. */
export function sources() {
  const jobs = [];
  for (const [slug, name] of SCANNERS) {
    jobs.push({
      bucket: "scanners",
      name,
      label: toSnake(name),
      kind: "cidr",
      remote: DYNAMIC_SCANNERS.has(slug),
      url: `${OPENFILTERS}/${slug}_v4.txt`,
    });
  }
  for (const [stem, name, nodeKind, nodeType] of C2) {
    jobs.push({
      bucket: "c2",
      name,
      label: toSnake(name),
      kind: "ips",
      remote: true,
      nodeKind,
      nodeType,
      url: `${C2TRACKER}/${encodeURIComponent(`${stem} IPs`)}.txt`,
    });
  }
  for (const [name, url, kind, remote] of BOTS) {
    jobs.push({ bucket: "bots", name, label: toSnake(name), kind, remote, url });
  }
  // VPN providers, Tor exits and iCloud Private Relay are one concept to an analyst: the address is
  // not the person. They share one bucket and one field; the provider name keeps the detail.
  for (const vpn of VPN) {
    jobs.push({
      bucket: "anonymizer",
      name: vpn.name,
      label: vpn.label,
      kind: vpn.kind,
      remote: vpn.remote,
      url: vpn.url,
      vpn,
    });
  }
  jobs.push({
    bucket: "anonymizer",
    name: "iCloud Private Relay",
    label: "icloud_private_relay",
    kind: "cidr",
    remote: true,
    url: RELAY_URL,
  });
  jobs.push({
    bucket: "anonymizer",
    name: "Tor exit node",
    label: "tor_exit_node",
    kind: "cidr",
    remote: true,
    url: TOR_URL,
  });
  for (const [name, url] of PROXY_URLS) {
    jobs.push({ bucket: "anonymizer", name, label: toSnake(name), kind: "cidr", remote: true, url });
  }
  jobs.push({
    bucket: "bogon",
    name: "Unallocated / bogon",
    label: "unallocated_bogon",
    kind: "cidr",
    remote: false,
    url: BOGON_URL,
  });
  return jobs;
}
