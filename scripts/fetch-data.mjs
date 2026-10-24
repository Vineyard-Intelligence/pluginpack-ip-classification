// Build-time data fetcher. Network access happens HERE, never in the plugin.
//
//   node scripts/fetch-data.mjs
//
// Writes data/generated.json. Every bucket keeps three parallel arrays — names, ranges and meta — so
// scripts/build.mjs can split each source into "ships in the bundle" or "fetched at runtime".
// Source URLs and the remote/bundled decision live in scripts/sources.mjs.
import { writeFileSync, mkdirSync, unlinkSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { promises as dns } from "node:dns";
import { sources, ovpnRemotes } from "./sources.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = `${HERE}/../data/generated.json`;
const BUCKETS = ["scanners", "c2", "bots", "anonymizer", "bogon"];

async function get(url, tries = 4) {
  for (let i = 0; i < tries; i++) {
    try {
      const r = await fetch(url, { headers: { "user-agent": "vineyard-ip-classification-build/1.0" } });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return r;
    } catch (e) {
      if (i === tries - 1) throw new Error(`${url}: ${e.message}`);
      await new Promise((res) => setTimeout(res, 800 * (i + 1)));
    }
  }
}

function toRange(cidr) {
  const [addr, bitsRaw] = cidr.trim().split("/");
  // A bare address (no "/prefix") is a single host. The iCloud Private Relay list mixes both forms,
  // and treating a missing prefix as NaN silently dropped 514 of its 3,488 entries.
  const bits = bitsRaw === undefined || bitsRaw === "" ? 32 : Number(bitsRaw);
  const octets = addr.split(".").map(Number);
  if (octets.length !== 4 || octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) return null;
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return null;
  const start = ((octets[0] << 24) >>> 0) + (octets[1] << 16) + (octets[2] << 8) + octets[3];
  return [start, start + 2 ** (32 - bits) - 1];
}

function addSource(bucket, job) {
  const idx = bucket.names.length;
  bucket.names.push(job.name);
  bucket.meta.push({
    name: job.name,
    label: job.label ?? job.name.toLowerCase(),
    url: job.url,
    kind: job.kind,
    remote: !!job.remote,
    updated: job.updated ?? "",
  });
  return idx;
}

function addRanges(bucket, idx, cidrs) {
  let added = 0;
  for (const c of cidrs) {
    const r = toRange(c);
    if (!r) continue;
    bucket.ranges.push([r[0], r[1], idx]);
    added++;
  }
  return added;
}

const cidrLines = (text) =>
  text
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#") && !l.startsWith(";"));

/** Resolve hostnames to A records, bounded so we do not hammer a resolver. */
async function resolveAll(hostnames, concurrency = 8) {
  const out = new Set();
  const queue = [...new Set(hostnames)];
  async function worker() {
    while (queue.length) {
      const host = queue.shift();
      try {
        for (const ip of await dns.resolve4(host)) out.add(ip);
      } catch {
        // a dead hostname is not a build failure
      }
    }
  }
  await Promise.all(Array.from({ length: concurrency }, worker));
  return [...out];
}

const isIpv4 = (s) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s);


/** Last push date for a GitHub repo, so hosted feeds can report how fresh they are. */
async function repoUpdated(repo) {
  try {
    const r = await fetch(`https://api.github.com/repos/${repo}`, {
      headers: { "user-agent": "vineyard-ip-classification-build/1.0" },
    });
    if (!r.ok) return "";
    return String((await r.json()).pushed_at ?? "").slice(0, 10);
  } catch {
    return "";
  }
}

/** Pull a freshness marker out of the payload itself when the source publishes one. */
function updatedFrom(kind, text, doc) {
  const header = text.slice(0, 600);
  // Team Cymru stamps an epoch: "# last updated 1792803301 (Sat Oct 24 ...)"
  const epoch = header.match(/#\s*last updated\s+(\d{9,})/i);
  if (epoch) return new Date(Number(epoch[1]) * 1000).toISOString();
  const m =
    header.match(/#\s*Last updated:\s*([0-9-]{10})/i) || header.match(/Last-Modified:\s*([0-9-]{10})/i);
  if (m) return m[1].slice(0, 10);
  if (doc && typeof doc.creationTime === "string") return new Date(doc.creationTime).toISOString();
  return "";
}

async function main() {
  const out = { generated_at: new Date().toISOString().slice(0, 10) };
  const [openfiltersDate, c2Date, relayDate] = await Promise.all([
    repoUpdated("OpenFilters/internet-scanners"),
    repoUpdated("HL-SOC/C2-Tracker"),
    repoUpdated("hroost/icloud-private-relay-iplist"),
  ]);
  for (const k of BUCKETS) out[k] = { names: [], ranges: [], meta: [] };
  out.c2.families = [];

  for (const job of sources()) {
    try {
      const startedAt = Date.now();
      const res = await get(job.url);
      const lastModified = res.headers.get("last-modified");
      // Dynamic APIs stamp Last-Modified with the current second; anything under an hour old is
      // "generated now", not "changed then", and would misreport freshness.
      const httpUpdated =
        lastModified && (job.updatedFromHeader || startedAt - Date.parse(lastModified) > 3_600_000)
          ? new Date(lastModified).toISOString()
          : "";
      const bucket = out[job.bucket];
      let addresses = [];
      let updated = "";

      if (job.kind === "cidr") {
        const text = await res.text();
        addresses = cidrLines(text);
        updated = updatedFrom(job.kind, text);
      } else if (job.kind === "ips") {
        const text = await res.text();
        addresses = cidrLines(text).map((ip) => `${ip}/32`);
        updated = updatedFrom(job.kind, text);
      } else if (job.kind === "prefixes") {
        const doc = await res.json();
        addresses = (doc.prefixes ?? []).map((p) => p.ipv4Prefix).filter(Boolean);
        updated = updatedFrom(job.kind, "", doc);
      } else if (job.kind === "json") {
        const candidates = job.vpn.extract(await res.json()).filter(Boolean);
        addresses = job.vpn.resolve ? await resolveAll(candidates) : candidates;
      } else if (job.kind === "airvpn") {
        addresses = job.vpn.extract(await res.json()).filter(Boolean);
      } else if (job.kind === "ovpnzip") {
        const zipPath = join(tmpdir(), `vpnsrc-${process.pid}-${Math.random().toString(36).slice(2)}.zip`);
        writeFileSync(zipPath, Buffer.from(await res.arrayBuffer()));
        try {
          const remotes = ovpnRemotes(zipPath);
          addresses = job.vpn?.resolve ? await resolveAll(remotes.filter((r) => !isIpv4(r))) : remotes.filter(isIpv4);
        } finally {
          try {
            unlinkSync(zipPath);
          } catch {
            /* temp file already gone */
          }
        }
      }

      // GitHub-hosted feeds carry no date of their own; the repo's last push is the best proxy.
      if (!updated && job.url.includes("OpenFilters/")) updated = openfiltersDate;
      if (!updated && job.url.includes("HL-SOC/")) updated = c2Date;
      if (!updated && job.url.includes("hroost/")) updated = relayDate;

      const idx = addSource(bucket, { ...job, updated: updated || httpUpdated });
      const n = addRanges(bucket, idx, addresses);
      if (job.bucket === "c2") {
        bucket.families.push({
          name: job.name,
          label: job.label ?? job.name.toLowerCase(),
          kind: job.nodeKind,
          type: job.nodeType,
        });
      }
      const tag = job.remote ? "remote" : "bundle";
      console.log(`${tag} ${job.bucket.padEnd(8)} ${job.name.padEnd(20)} ${n}`);
    } catch (e) {
      console.warn(`SKIP ${job.bucket} ${job.name}: ${e.message}`);
    }
  }

  for (const k of BUCKETS) out[k].ranges.sort((a, b) => a[0] - b[0]);
  mkdirSync(dirname(OUT), { recursive: true });
  writeFileSync(OUT, JSON.stringify(out));
  const total = BUCKETS.reduce((n, k) => n + out[k].ranges.length, 0);
  const remote = BUCKETS.reduce((n, k) => n + out[k].meta.filter((m) => m.remote).length, 0);
  console.log(
    `\nwrote ${OUT} — ${total} ranges, ${remote} remote source(s), ${(JSON.stringify(out).length / 1024).toFixed(0)} KiB`,
  );
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
