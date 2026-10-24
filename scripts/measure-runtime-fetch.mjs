// What the hybrid design actually costs over the wire.
//
//   node scripts/measure-runtime-fetch.mjs
//
// The pack ships two kinds of source: `remote` ones the browser fetches on every run, and `bundled`
// ones that ride along inside dist/pack.mjs. This reports both sides as measured, so the split can
// be argued with numbers instead of intuition. gzip is the figure a browser really receives.
import { execFileSync } from "node:child_process";
import { readFileSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";

const DATA = JSON.parse(readFileSync(new URL("../data/generated.json", import.meta.url), "utf8"));
const BUCKETS = ["scanners", "c2", "bots", "anonymizer", "bogon"];

function measure(url) {
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
  return { raw, gz };
}

const remote = [];
for (const bucket of BUCKETS) {
  DATA[bucket].meta.forEach((m) => {
    if (m.remote) remote.push({ bucket, ...m });
  });
}

const rows = [];
for (const src of remote) rows.push({ ...src, ...measure(src.url) });

const mb = (n) => (n / 1024 / 1024).toFixed(2);
const kib = (n) => (n / 1024).toFixed(0);

const byBucket = new Map();
for (const r of rows) {
  const b = byBucket.get(r.bucket) ?? { files: 0, raw: 0, gz: 0 };
  b.files++;
  b.raw += r.raw;
  b.gz += r.gz;
  byBucket.set(r.bucket, b);
}

console.log("런타임 fetch (매 실행)");
console.log("bucket      files      raw       전송(실측)");
for (const [name, b] of byBucket) {
  console.log(`${name.padEnd(10)} ${String(b.files).padStart(5)}  ${mb(b.raw).padStart(8)} MiB  ${kib(b.gz).padStart(6)} KiB`);
}

const totalRaw = rows.reduce((n, r) => n + r.raw, 0);
const totalGz = rows.reduce((n, r) => n + r.gz, 0);
console.log(`\n합계 ${rows.length}개 파일 — raw ${mb(totalRaw)} MiB / gzip ${kib(totalGz)} KiB (${totalGz.toLocaleString()} B)`);

const bundlePath = fileURLToPath(new URL("../dist/pack.mjs", import.meta.url));
console.log(`번들 ${kib(statSync(bundlePath).size)} KiB (1회 다운로드, 실행마다 재사용)`);

console.log("\n가장 큰 원격 파일 5개");
for (const r of rows.slice().sort((a, b) => b.gz - a.gz).slice(0, 5)) {
  console.log(`  ${kib(r.gz).padStart(6)} KiB gzip  ${r.bucket}/${r.name}`);
}

console.log("\n번들에 남은 소스 (전송 없음)");
for (const bucket of BUCKETS) {
  const local = DATA[bucket].meta.filter((m) => !m.remote);
  if (!local.length) continue;
  const ranges = DATA[bucket].ranges.filter((r) => !DATA[bucket].meta[r[2]].remote).length;
  console.log(`  ${bucket.padEnd(9)} ${local.length} source(s), ${ranges} ranges — ${local.map((m) => m.name).join(", ")}`);
}
