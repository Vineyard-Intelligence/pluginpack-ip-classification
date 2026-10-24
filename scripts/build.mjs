// Assembles dist/pack.mjs from src/template.mjs + data/generated.json.
//
//   node scripts/fetch-data.mjs   # refresh the snapshot (network)
//   node scripts/build.mjs        # inline it into the bundle
//   node scripts/gen-manifest.mjs # mirror the manifests into plugins/
//
// The split is the whole point: sources the browser can fetch (CORS-verified) ship as a remote
// descriptor list and are pulled fresh on every run; everything else is packed into the bundle.
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = `${HERE}/..`;

const BUCKETS = ["scanners", "c2", "bots", "anonymizer", "bogon"];

/** "<gap>.<len>" base 36, gap measured from the previous range's start within this source. */
function pack(ranges) {
  const sorted = ranges.slice().sort((a, b) => a[0] - b[0]);
  let prev = 0;
  const out = new Array(sorted.length);
  for (let i = 0; i < sorted.length; i++) {
    const [start, end] = sorted[i];
    out[i] = `${(start - prev).toString(36)}.${(end - start).toString(36)}`;
    prev = start;
  }
  return out.join(" ");
}

const raw = JSON.parse(readFileSync(`${ROOT}/data/generated.json`, "utf8"));

const local = [];
const remote = [];
for (const bucket of BUCKETS) {
  const { ranges, meta } = raw[bucket];
  meta.forEach((m, idx) => {
    if (m.remote) {
      remote.push({ bucket, name: m.label ?? m.name, url: m.url, kind: m.kind });
    } else {
      const mine = ranges.filter((r) => r[2] === idx).map((r) => [r[0], r[1]]);
      local.push({ bucket, name: m.label ?? m.name, packed: pack(mine) });
    }
  });
}

// Address ranges are no longer embedded — the plugin reads them from the observation index. Only the
// family metadata ships, because a C2 tag alone does not say whether it is a tool or a malware family.
const dataset = {
  generated_at: raw.generated_at,
  c2Families: raw.c2.families,
};

const template = readFileSync(`${ROOT}/src/template.mjs`, "utf8");
const marker = "const DATASET = /*__DATA__*/ null;";
if (!template.includes(marker)) {
  console.error(`marker not found in src/template.mjs: ${marker}`);
  process.exit(1);
}

const bundle = template.replace(marker, `const DATASET = ${JSON.stringify(dataset)};`);
mkdirSync(`${ROOT}/dist`, { recursive: true });
writeFileSync(`${ROOT}/dist/pack.mjs`, bundle);

const localRanges = local.reduce((n, s) => n + (s.packed ? s.packed.split(" ").length : 0), 0);
console.log(
  `wrote dist/pack.mjs — ${(bundle.length / 1024).toFixed(0)} KiB\n` +
    `  bundled: ${local.length} source(s), ${localRanges} ranges\n` +
    `  remote : ${remote.length} source(s), fetched per run`,
);
