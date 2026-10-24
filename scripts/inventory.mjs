// Rewrites the "Data sources" table inside the history repository's README.md, between the sources
// markers. The plugin pack itself only points at that table — it does not repeat it.
//
//   node scripts/churn.mjs   # refresh data/churn.json (git history)
//   node scripts/sources.mjs  # npm run sources
//
// Transfer sizes are cached in data/transfer.json so the table can be regenerated without
// re-downloading.
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

const DATA = JSON.parse(readFileSync(new URL("../data/generated.json", import.meta.url), "utf8"));
const CHURN = existsSync(new URL("../data/churn.json", import.meta.url))
  ? JSON.parse(readFileSync(new URL("../data/churn.json", import.meta.url), "utf8"))
  : {};
const README = fileURLToPath(new URL("../../ip-observation-history/README.md", import.meta.url));
const START = "<!-- sources:start -->";
const END = "<!-- sources:end -->";
const CACHE_PATH = fileURLToPath(new URL("../data/transfer.json", import.meta.url));

const BUCKETS = [
  ["scanners", "Scanners"],
  ["c2", "C2 / malware"],
  ["bots", "Crawlers / AI bots"],
  ["anonymizer", "Anonymizers (VPN / Tor / iCloud Relay)"],
  ["bogon", "Non-routable"],
];


const originOf = (url) => new URL(url).host;

function sourceLabel(url) {
  return `<${url}>`;
}

function delivery(meta) {
  if (meta.remote) return "**fetch**";
  if (meta.kind === "ovpnzip") return "번들(zip)";
  if (/surfshark|ivpn/i.test(meta.name)) return "번들(DNS)";
  return "번들";
}


const cache = existsSync(CACHE_PATH) ? JSON.parse(readFileSync(CACHE_PATH, "utf8")) : {};

function measure(url) {
  if (cache[url]) return cache[url];
  const raw = Number(
    execFileSync("curl", ["-sL", "-m", "60", "-o", "/dev/null", "-w", "%{size_download}", url], { encoding: "utf8" }),
  );
  let gz = raw;
  try {
    gz = Number(
      execFileSync(
        "curl",
        ["-sL", "-m", "60", "-H", "Accept-Encoding: gzip", "--raw", "-o", "/dev/null", "-w", "%{size_download}", url],
        { encoding: "utf8" },
      ),
    );
  } catch {
    gz = raw;
  }
  cache[url] = { raw, gz };
  return cache[url];
}

const rows = [];
for (const [bucket, label] of BUCKETS) {
  DATA[bucket].meta.forEach((m, idx) => {
    rows.push({
      bucket,
      label,
      ...m,
      ranges: DATA[bucket].ranges.filter((r) => r[2] === idx).length,
    });
  });
}

for (const r of rows) if (r.remote) Object.assign(r, measure(r.url));
writeFileSync(CACHE_PATH, JSON.stringify(cache));

const kib = (n) => (n / 1024).toFixed(0);
const total = (list, key) => list.reduce((n, r) => n + (r[key] ?? 0), 0);
const remoteRows = rows.filter((r) => r.remote);
const bundledRows = rows.filter((r) => !r.remote);
const bundleBytes = readFileSync(new URL("../dist/pack.mjs", import.meta.url)).length;

// Measured by flipping `remote` and rebuilding (2026-10-24).
const MEASURED = { allScannersFetch: 94 * 1024, airvpnFetch: 90 * 1024, allBundled: 199 * 1024 };
const airvpnGz = 210 * 1024;
const scannerGz = total(remoteRows.filter((r) => r.bucket === "scanners"), "gz");

const churnCell = (name) => {
  const c = CHURN[name];
  return c ? `${c.changes_180d}일` : "—";
};
/** "2026-10-24 04:59 UTC" — precise enough to compare feeds, short enough for a table cell. */
const when = (iso) => {
  if (!iso) return null;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? null : `${d.toISOString().slice(0, 16).replace("T", " ")} UTC`;
};

const lastCell = (r) => {
  const c = CHURN[r.name];
  if (c?.last_change_iso) return `${when(c.last_change_iso)} (${c.age_days === 0 ? "today" : `${c.age_days}d ago`})`;
  if (r.updated) return when(r.updated) ?? "—";
  return "—";
};

const c2 = Object.values(CHURN).filter((c) => c.bucket === "c2");
const c2Median = c2.length ? c2.map((c) => c.changes_180d).sort((a, b) => a - b)[Math.floor(c2.length / 2)] : 0;

let md = `${START}
| | Sources | Ranges | Per run |
|---|---:|---:|---:|
| fetched every run | ${remoteRows.length} | ${total(remoteRows, "ranges").toLocaleString()} | **${kib(total(remoteRows, "gz"))} KiB** |
| bundled snapshot | ${bundledRows.length} | ${total(bundledRows, "ranges").toLocaleString()} | 0 (inside the ${kib(bundleBytes)} KiB bundle) |
| **total** | **${rows.length}** | **${total(rows, "ranges").toLocaleString()}** | |

Sources whose content changes often are fetched on every run; the rest ship inside the bundle.
Sizes are gzip bytes. Regenerate with npm run sources.

`;

for (const [bucket, label] of BUCKETS) {
  const list = rows.filter((r) => r.bucket === bucket);
  if (!list.length) continue;
  list.sort((a, b) => b.ranges - a.ranges || a.name.localeCompare(b.name));
  md += `### ${label}\n\n`;
  md += `| Name | Value | Source | Ranges | gzip | Last update |\n`;
  md += `|---|---|---|---:|---:|---|\n`;
  for (const r of list) {
    const gz = r.remote ? (r.gz < 1024 ? `${r.gz} B` : `${kib(r.gz)} KiB`) : "—";
    md += `| ${r.name} | \`${r.label ?? r.name.toLowerCase()}\` | ${sourceLabel(r.url)} | ${r.ranges.toLocaleString()} | ${gz} | ${lastCell(r)} |\n`;
  }
  md += `\n`;
}

md += END;

const readme = readFileSync(README, "utf8");
const a = readme.indexOf(START);
const b = readme.indexOf(END);
if (a < 0 || b < 0) {
  console.error(`README.md is missing the ${START} / ${END} markers`);
  process.exit(1);
}
const next = readme.slice(0, a) + md + readme.slice(b + END.length);
writeFileSync(README, next);
console.log(`updated ${README} between markers`);
console.log(`fetch ${remoteRows.length} / ${kib(total(remoteRows, "gz"))} KiB per run, bundle ${kib(bundleBytes)} KiB`);
