// Vineyard plugin pack — IP classification.
//
// Answers why an address shows up in a log: it is an internet-wide scanner, a C2 or malware family,
// a crawler or AI bot, a VPN or iCloud Private Relay exit, or simply not routable space.
//
// DATA
//   Address data lives in the observation index, not in this file: index.json plus one /8 shard per
//   address, both served from ip-observation-history. Only the C2 family metadata is embedded.
//
// SDK note: definePlugin / definePluginPack are identity helpers, reproduced here so the pack
// builds as one dependency-free ESM file.

const definePlugin = (p) => p;
const definePluginPack = (p) => p;

const DATASET = /*__DATA__*/ null;

// Address data is not embedded. It is read from the observation index, one /8 shard per address:
//
//   https://raw.githubusercontent.com/Vineyard-Intelligence/ip-observation-history/main
//
// Only the C2 family metadata (which Tool/Malware node a family maps to) ships in the bundle — it is
// static knowledge about families, not address data.

// jsDelivr rather than raw.githubusercontent.com: raw pins a 5-minute CDN cache but serves whatever
// build it saw first, while jsDelivr revalidates the branch and sends a week-long cache header. Shards
// are requested with ?v=<built_at> so each build gets its own cache entry instead of a stale one.
// raw, not jsDelivr: jsDelivr keys its cache by content-encoding, so the gzip variant of a shard
// can keep serving bytes from a previous build while the identity variant is already fresh. raw
// has one variant and a five-minute TTL, which a twice-daily dataset can live with.
const SHARD_BASE = "https://raw.githubusercontent.com/Vineyard-Intelligence/ip-observation-history/main";
const SNAPSHOT = DATASET?.generated_at ?? "unknown";
// c2_family holds the lowercase label; the Tool/Malware node keeps the proper name.
const FAMILY_BY_LABEL = new Map((DATASET?.c2Families ?? []).map((f) => [f.label ?? f.name, f]));

// ---------------------------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------------------------

/** "1.2.3.0/24" or a bare "1.2.3.4" → [start, end] integers, or null. */
function cidrToRange(cidr) {
  const [addr, bitsRaw] = String(cidr).trim().split("/");
  const bits = bitsRaw === undefined || bitsRaw === "" ? 32 : Number(bitsRaw);
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return null;
  const octets = addr.split(".").map(Number);
  if (octets.length !== 4) return null;
  if (octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) return null;
  const start = ((octets[0] << 24) >>> 0) + (octets[1] << 16) + (octets[2] << 8) + octets[3];
  return [start, start + 2 ** (32 - bits) - 1];
}

/** Turn a fetched payload into a list of addresses/CIDRs, by source kind. */
function parsePayload(kind, text) {
  if (kind === "cidr") {
    return text
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith("#") && !l.startsWith(";"));
  }
  if (kind === "ips") {
    return text
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith("#"));
  }
  if (kind === "prefixes") {
    const doc = JSON.parse(text);
    return (doc.prefixes ?? []).map((p) => p.ipv4Prefix).filter(Boolean);
  }
  if (kind === "airvpn") {
    const doc = JSON.parse(text);
    return (doc.servers ?? []).flatMap((s) => [s?.ip_v4_in1, s?.ip_v4_in2, s?.ip_v4_in3, s?.ip_v4_in4]).filter(Boolean);
  }
  return [];
}

/** Decode one bundled source: "<gap>.<len>" base 36 triples, gap from the previous start. */
function decodePacked(packed) {
  if (!packed) return [];
  const parts = packed.split(" ");
  const out = new Array(parts.length);
  let prev = 0;
  for (let i = 0; i < parts.length; i++) {
    const dot = parts[i].indexOf(".");
    prev += parseInt(parts[i].slice(0, dot), 36);
    out[i] = [prev, prev + parseInt(parts[i].slice(dot + 1), 36)];
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// Range index
// ---------------------------------------------------------------------------------------------

function buildIndex(names, triples) {
  triples.sort((a, b) => a[0] - b[0]);
  const n = triples.length;
  const starts = new Uint32Array(n);
  const ends = new Uint32Array(n);
  const ids = new Uint8Array(n);
  const lasts = new Uint32Array(n);
  const firsts = new Uint32Array(n);
  const prefMax = new Uint32Array(n);
  const refs = new Array(n);
  let max = 0;
  for (let i = 0; i < n; i++) {
    const [s, e, id, ref, last, first] = triples[i];
    starts[i] = s;
    ends[i] = e;
    ids[i] = id;
    refs[i] = ref ?? null;
    lasts[i] = last ?? 0;
    firsts[i] = first ?? 0;
    if (e > max) max = e;
    prefMax[i] = max;
  }
  return { starts, ends, ids, refs, lasts, firsts, prefMax, names };
}

/** All entries whose range contains the given IPv4 integer. */
function matchInt(index, ip) {
  if (!index || !index.starts.length) return [];
  const { starts, ends, ids, prefMax } = index;
  let lo = 0;
  let hi = starts.length - 1;
  let pos = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (starts[mid] <= ip) {
      pos = mid;
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  const hits = [];
  for (let i = pos; i >= 0 && prefMax[i] >= ip; i--) {
    if (ends[i] >= ip) hits.push(i);
  }
  return hits;
}

// One load per run, cached on the ctx.net identity so a second call in the same worker (or the same
// run) does not re-download. A new worker gets a new ctx.net and therefore fresh data.
const loaded = new WeakMap();

async function loadState(ctx) {
  const key = ctx.net;
  if (key && loaded.has(key)) return loaded.get(key);
  const pending = loadStateUncached(ctx);
  if (key) loaded.set(key, pending);
  return pending;
}

async function loadStateUncached(ctx) {
  const state = { index: null, shards: new Map(), fetched: 0, failed: 0 };
  if (!ctx.net?.fetch) return state;
  try {
    const res = await ctx.net.fetch(`${SHARD_BASE}/index.json`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    state.index = await res.json();
  } catch {
    state.index = null;
  }
  return state;
}

/** "146.70.163.90" or "104.28.28.0/26" → [start, end]. */
function keyToRange(key) {
  const [addr, bitsRaw] = key.split("/");
  const start = ipv4ToInt(addr);
  if (start === null) return null;
  const bits = bitsRaw === undefined ? 32 : Number(bitsRaw);
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return null;
  return [start, start + 2 ** (32 - bits) - 1];
}

/** The shard holding this address, as a matchInt-shaped index over its source tags. */
async function shardFor(ctx, state, ip) {
  if (!state.index) return null;
  const o1 = ip >>> 24;
  const name = String(o1).padStart(3, "0");
  if (!state.shards.has(name)) {
    state.shards.set(
      name,
      (async () => {
        try {
          const v = state.index?.built_at ?? 0;
          const res = await ctx.net.fetch(`${SHARD_BASE}/shards/${name}.json?v=${v}`);
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          const obj = await res.json();
          const names = [];
          const idOf = new Map();
          const triples = [];
          for (const [key, records] of Object.entries(obj)) {
            const range = keyToRange(key);
            if (!range) continue;
            for (const record of records) {
              const [tag, , refLast, , firstSeen, lastSeen] = record;
              if (!idOf.has(tag)) {
                idOf.set(tag, names.length);
                names.push(tag);
              }
              triples.push([range[0], range[1], idOf.get(tag), refLast ?? null, lastSeen ?? 0, firstSeen ?? 0]);
            }
          }
          state.fetched++;
          return buildIndex(names, triples);
        } catch {
          state.failed++;
          return null;
        }
      })(),
    );
  }
  return state.shards.get(name);
}

// ---------------------------------------------------------------------------------------------
// Attribution
// ---------------------------------------------------------------------------------------------

const SPECIAL = [
  ["0.0.0.0/8", "reserved"],
  ["10.0.0.0/8", "private"],
  ["100.64.0.0/10", "cgnat"],
  ["127.0.0.0/8", "loopback"],
  ["169.254.0.0/16", "link_local"],
  ["172.16.0.0/12", "private"],
  ["192.0.0.0/24", "reserved"],
  ["192.0.2.0/24", "documentation"],
  ["192.88.99.0/24", "reserved"],
  ["192.168.0.0/16", "private"],
  ["198.18.0.0/15", "benchmark"],
  ["198.51.100.0/24", "documentation"],
  ["203.0.113.0/24", "documentation"],
  ["224.0.0.0/4", "multicast"],
  ["240.0.0.0/4", "reserved"],
].map(([cidr, scope]) => [...cidrToRange(cidr), scope]);

/** Strict dotted-quad → integer, or null. Rejects CIDR notation: this is about one address. */
function ipv4ToInt(value) {
  if (typeof value !== "string") return null;
  const parts = value.trim().split(".");
  if (parts.length !== 4) return null;
  let out = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const n = Number(p);
    if (n > 255) return null;
    out = out * 256 + n;
  }
  return out >>> 0;
}

function scopeOf(ip) {
  for (const [s, e, scope] of SPECIAL) if (ip >= s && ip <= e) return scope;
  return "public";
}

const IP_TYPE = "infrastructure.ip_address";
const nodeIp = (node) => (typeof node?.data?.ip_address === "string" ? node.data.ip_address.trim() : "");

/** C2 families for this IP: creates a Tool/Malware node per family and links it "used as C2". */
async function attributeC2(ctx, node, names, url, windows) {
  if (!names.length) return { count: 0, names: [] };

  await ctx.graph.updateNode(node.id, {
    c2_family: names.join(", "),
    c2_source: url,
  });

  for (const name of names) {
    const family = FAMILY_BY_LABEL.get(name) ?? { name, kind: "malware", type: "unknown" };
    const isTool = family.kind === "tool";
    const created = await ctx.graph.createNode({
      type: isTool ? "threat.tool" : "threat.malware",
      data: isTool
        ? {
            name: family.name,
            tool_type: family.type,
            description: `C2 framework seen on captured C2 infrastructure (snapshot ${SNAPSHOT}).`,
            ...(windows?.[name] ?? {}),
          }
        : { name: family.name, malware_type: family.type, is_family: true, ...(windows?.[name] ?? {}) },
    });
    await ctx.graph.createEdge({
      from: node.id,
      to: created.id,
      label: "used as C2",
      data: { source: url, snapshot: SNAPSHOT },
    });
  }
  return { count: names.length, names };
}

/** Every attribution this pack knows, applied to one IP Address node. */
async function attributeIp(ctx, node, ip) {
  const state = await loadState(ctx);
  const scope = scopeOf(ip);
  // A special-use range is answered from RFC 6890 alone — no point asking for a shard.
  const shard = scope === "public" ? await shardFor(ctx, state, ip) : null;

  const patch = {};

  // `tags` carries the category axes only; the specific source stays in the field beside it
  // (scanner=shodan, anonymizer=nordvpn_entry). Both are written in the same call.
  const tags = [];
  const buckets = new Map();
  // tag -> { ref, last }: the commit this address came from and when it was last listed there.
  // One tag can match several ranges; the freshest evidence wins.
  const matched = new Map();
  if (shard) {
    for (const pos of matchInt(shard, ip)) {
      const tag = shard.names[shard.ids[pos]];
      const bucket = state.index?.sources?.[tag]?.bucket;
      if (!bucket) continue;
      const prev = matched.get(tag);
      if (!prev || shard.lasts[pos] >= prev.last) {
        matched.set(tag, {
          ref: shard.refs[pos],
          first: shard.firsts[pos],
          last: shard.lasts[pos],
        });
      }
      if (!buckets.has(bucket)) buckets.set(bucket, []);
      const list = buckets.get(bucket);
      if (!list.includes(tag)) list.push(tag);
    }
  }

  /**
   * The upstream file, pinned to the commit the value was read from. A branch url ("…/main/…")
   * answers "where is this list today"; the value came from a specific commit, and an analyst
   * checking it months later needs that commit. Sources that are APIs (no repo) have no ref and
   * keep their url unchanged.
   */
  const pin = (url, ref) => {
    if (!ref || typeof url !== "string") return url;
    // raw.githubusercontent.com/<org>/<repo>/<branch>/<path> — the branch segment is what a reader
    // would see drift, so it is the segment the commit replaces. Works for main and master alike.
    const m = url.match(/^(https:\/\/raw\.githubusercontent\.com\/[^/]+\/[^/]+\/)([^/]+)(\/.*)$/);
    return m ? `${m[1]}${ref}${m[3]}` : url;
  };
  const feeds = (bucket) =>
    (buckets.get(bucket) ?? [])
      .map((name) => pin(state.index?.sources?.[name]?.source, matched.get(name)?.ref))
      .filter(Boolean)
      .join(", ");

  const iso = (sec) => (sec ? new Date(sec * 1000).toISOString() : null);
  /**
   * Record a window without narrowing one already on the node. Two runs (or two plugins writing the
   * same address) can see different spans: the one that saw it longer is the truth, so first_seen
   * only moves EARLIER and last_seen only moves LATER. Without this, whichever ran last would win and
   * a 2023 sighting would be replaced by today's.
   */
  const writeWindow = (prefix, w) => {
    const first = iso(w.first);
    const last = iso(w.last);
    const prevFirst = Date.parse(node.data?.[`${prefix}_first_seen`] ?? "");
    const prevLast = Date.parse(node.data?.[`${prefix}_last_seen`] ?? "");
    if (first && !(prevFirst && prevFirst <= Date.parse(first))) patch[`${prefix}_first_seen`] = first;
    if (last && !(prevLast && prevLast >= Date.parse(last))) patch[`${prefix}_last_seen`] = last;
  };
  /** Earliest first_seen and latest last_seen across the tags of one category. */
  const span = (bucket) => {
    let first = 0;
    let last = 0;
    for (const name of buckets.get(bucket) ?? []) {
      const m = matched.get(name);
      if (!m) continue;
      if (m.first && (!first || m.first < first)) first = m.first;
      if (m.last > last) last = m.last;
    }
    return { first, last };
  };

  // "public" is not a finding, it is the absence of one: a globally routable address that no list
  // names. Writing it made the data lopsided — every plain address carried `ip_scope: public` +
  // `is_bogon: false`, so a node's shape said "classified" when nothing had been found. The scope
  // is only recorded when it says something: special-use space, or an unallocated block.
  const scopeLabel = buckets.get("bogon") ? "unallocated" : scope;
  if (scopeLabel !== "public") patch.ip_scope = scopeLabel;
  if (buckets.get("scanners")) {
    patch.scanner = buckets.get("scanners").join(", ");
    patch.scanner_source = feeds("scanners");
    writeWindow("scanner", span("scanners"));
    if (!node.data?.organization) patch.organization = buckets.get("scanners")[0];
    tags.push("scanner");
  }
  if (buckets.get("bots")) {
    patch.crawler = buckets.get("bots").join(", ");
    patch.crawler_source = feeds("bots");
    writeWindow("crawler", span("bots"));
    tags.push("crawler");
  }
  if (buckets.get("anonymizer")) {
    patch.anonymizer = buckets.get("anonymizer").join(", ");
    patch.anonymizer_source = feeds("anonymizer");
    writeWindow("anonymizer", span("anonymizer"));
    tags.push("anonymizer");
  }
  if (buckets.get("c2")) {
    tags.push("c2");
    writeWindow("c2", span("c2"));
  }
  if (patch.ip_scope) tags.push("bogon");
  if (tags.length) patch.tags = tags;

  // Nothing found and nothing to say about the address: leave the node untouched rather than
  // stamping it with an empty verdict.
  if (!Object.keys(patch).length) return { patch: {}, count: 0, wrote: false };
  await ctx.graph.updateNode(node.id, patch);

  const c2Names = buckets.get("c2") ?? [];
  const c2Windows = {};
  for (const name of c2Names) {
    const m = matched.get(name);
    if (!m) continue;
    const w = {};
    if (iso(m.first)) w.first_seen = iso(m.first);
    if (iso(m.last)) w.last_seen = iso(m.last);
    c2Windows[name] = w;
  }
  const c2 = await attributeC2(ctx, node, c2Names, feeds("c2"), c2Windows);
  if (c2.count) patch.c2_family = c2.names.join(", ");

  // `wrote` is set only where the update actually happened: the early return above leaves the node
  // alone, and the summary counts what changed, not what was looked at.
  return { patch, wrote: true, ...c2 };
}

/** One line per address, for the task summary. */
function describe(address, result) {
  const { patch, ...c2 } = result;
  const parts = [
    patch.ip_scope && `scope=${patch.ip_scope}`,
    patch.scanner && `scanner=${patch.scanner}`,
    patch.crawler && `crawler=${patch.crawler}`,
    patch.anonymizer && `anonymizer=${patch.anonymizer}`,
  ].filter(Boolean);
  const suffix = c2.count ? ` · c2=${c2.names.join(", ")} (${c2.count} node(s) linked)` : "";
  if (!parts.length && !c2.count) return `${address}: public, no list names it`;
  return `${address}: ${parts.join(" · ")}${suffix}`;
}

function liveNote(state) {
  // Nothing about shards: how the data is fetched is not the analyst's concern. Only a real
  // problem — no data at all, or a lookup that failed — is worth saying out loud.
  if (!state.index) return " · address data unavailable (no network access?)";
  return state.failed ? " · some address data could not be read" : "";
}

// ---------------------------------------------------------------------------------------------
// The plugin
// ---------------------------------------------------------------------------------------------

const lookupPlugin = definePlugin({
  manifest: {
    identifier: "run.vineyard.plugins.ip_classification",
    content_type: "vineyard:plugin",
    name: "IP Classification",
    version: "1.2.0",
    description:
      "Classifies an IPv4 address by role: internet-wide scanner, C2 or malware family (creating a linked Tool or Malware node), crawler or AI bot, anonymizer (VPN, Tor exit, iCloud Private Relay), or non-routable space. Type an address into the form or select IP Address nodes. No API key.",
    icon: "fingerprint",
    io: {
      // A declared seed type is what tells the run dialog this plugin operates on a selection:
      // with an empty list it is filed as whole-graph and handed every node in the project.
      consumes: [
        {
          typepack: "run.vineyard.typepacks.infrastructure",
          category: "infrastructure",
          name: "ip_address",
        },
      ],
      produces: [
        { typepack: "run.vineyard.typepacks.threat", category: "threat", name: "tool" },
        { typepack: "run.vineyard.typepacks.threat", category: "threat", name: "malware" },
      ],
    },
    scopes: {
      graph: ["node:read", "node:update", "node:create", "edge:create"],
      network: [
        {
          endpoint: "https://raw.githubusercontent.com/Vineyard-Intelligence/ip-observation-history/main",
          methods: ["GET"],
          purpose: "observation index and /8 shards",
        },
      ],
    },
    platforms: { primary: "web", web: { runtime: "sandbox-js", entry: "dist/pack.mjs" } },
    lifecycle: { persistence: "ephemeral", controls: ["progress", "cancel"] },
  },

  async run(ctx) {
    if (!ctx.graph?.updateNode || !ctx.graph?.createNode || !ctx.graph?.createEdge) {
      return { summary: "Needs node:read, node:update, node:create and edge:create scopes." };
    }

    const selection = ctx.input?.selection ?? [];
    if (!selection.length) {
      return { summary: "Select one or more IP Address nodes to classify." };
    }

    ctx.progress?.set?.({ percent: 0, message: "loading address data" });
    const state = await loadState(ctx);
    let attributed = 0;
    let untouched = 0;
    let families = 0;
    const skipped = [];
    let single = null;

    for (const id of selection) {
      if (ctx.signal?.aborted) break;
      const node = await ctx.graph.get(id);
      if (!node) continue;
      if (node.type !== IP_TYPE) {
        skipped.push("not an IP Address");
        continue;
      }
      const ip = ipv4ToInt(nodeIp(node));
      if (ip === null) {
        skipped.push(`${nodeIp(node) || "(blank)"}: only IPv4 is supported`);
        continue;
      }
      const result = await attributeIp(ctx, node, ip);
      if (result.wrote) attributed++;
      else untouched++;
      families += result.count;
      single = describe(nodeIp(node), result);
      ctx.progress?.set?.({
        percent: Math.round(((attributed + skipped.length) / selection.length) * 100),
        message: `${attributed} of ${selection.length} classified`,
      });
    }

    const quiet = untouched ? `${untouched} public and not in any list` : "";
    const reasons = [quiet, skipped.length ? `skipped ${skipped.length}: ${[...new Set(skipped)].join("; ")}` : ""].filter(Boolean);
    const note = reasons.length ? ` (${reasons.join("; ")})` : "";
    // One address gets the same line the form used to print; a batch gets the counts.
    // One address reads better as a sentence, whether or not anything was found for it.
    const head =
      selection.length === 1 && single ? single : `${attributed}/${selection.length} IP(s) attributed`;
    return {
      summary: `${head}${attributed > 1 && families ? ` · ${families} C2 match(es)` : ""}${note}${liveNote(state)}`,
      counts: { attributed, c2_families: families },
    };
  },
});
export default definePluginPack({
  identifier: "run.vineyard.pluginpacks.ip_classification",
  content_type: "vineyard:pluginpack",
  name: "IP Classification (under test)",
  version: "1.2.0",
  description:
    "Classifies IP addresses as scanners, C2 and malware families, crawlers, anonymizers and non-routable space.",
  author: { name: "VINEYARD", url: "https://github.com/Vineyard-Intelligence" },
  license: "Apache-2.0",
  icon: "fingerprint",
  platforms: { primary: "web", web: { runtime: "sandbox-js", entry: "dist/pack.mjs" } },
  plugins: [lookupPlugin],
});
