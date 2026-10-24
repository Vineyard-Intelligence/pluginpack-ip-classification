// Measures how often each hosted feed actually changes, from git history.
//
//   node scripts/churn.mjs
//
// Writes data/churn.json. Scanner, C2 and relay feeds are GitHub-hosted, so the commits that touched
// a file are the ground truth for "how often does this list move" — a weekly mirror of an unchanged
// file is not churn.
//
// Needs `git` and network. Clones are shallow-filtered (--filter=blob:none) because only commit
// metadata is read, and they are reused between runs.
import { execFileSync } from "node:child_process";
import { writeFileSync, existsSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { sources } from "./sources.mjs";

const DAY = 86_400_000;
const today = Date.now();

const REPOS = {
  "raw.githubusercontent.com/OpenFilters/internet-scanners": { url: "https://github.com/OpenFilters/internet-scanners", dir: "churn-openfilters" },
  "raw.githubusercontent.com/HL-SOC/C2-Tracker": { url: "https://github.com/HL-SOC/C2-Tracker", dir: "churn-c2tracker" },
  "raw.githubusercontent.com/hroost/icloud-private-relay-iplist": { url: "https://github.com/hroost/icloud-private-relay-iplist", dir: "churn-icloudrelay" },
};

function clone(dir, url) {
  const path = join(tmpdir(), dir);
  if (existsSync(join(path, ".git"))) {
    try {
      execFileSync("git", ["-C", path, "fetch", "--quiet", "--depth", "400", "origin"], { stdio: "ignore" });
      return path;
    } catch {
      rmSync(path, { recursive: true, force: true });
    }
  }
  execFileSync("git", ["clone", "--quiet", "--filter=blob:none", "--no-checkout", url, path], { stdio: "ignore" });
  return path;
}

function gitLogDates(repoPath, file) {
  // Author date, not committer date: a fork that re-imports history rewrites committer dates to the
  // import day, which would report the whole corpus as "changed today".
  const out = execFileSync("git", ["-C", repoPath, "log", "--format=%aI", "--", file], {
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
  });
  return [...new Set(out.split("\n").map((l) => l.trim()).filter(Boolean))];
}

function stats(stamps) {
  // Stamps are author dates in ISO 8601. Counting is per DAY: a job that commits three times on one
  // day changed the list once that day. The reported last change keeps the exact time.
  const empty = {
    changes_180d: 0,
    changes_365d: 0,
    last_change: null,
    last_change_iso: null,
    age_days: null,
    median_gap_days: null,
  };
  if (!stamps.length) return empty;

  const ts = stamps.map((d) => new Date(d).getTime()).sort((a, b) => a - b);
  const days = [...new Set(stamps.map((d) => new Date(d).toISOString().slice(0, 10)))]
    .map((d) => new Date(`${d}T00:00:00Z`).getTime())
    .sort((a, b) => a - b);
  const within = (n) => days.filter((t) => today - t <= n * DAY).length;
  const gaps = days.slice(1).map((t, i) => (t - days[i]) / DAY).sort((a, b) => a - b);
  const last = ts[ts.length - 1];

  return {
    changes_180d: within(180),
    changes_365d: within(365),
    last_change: new Date(last).toISOString().slice(0, 10),
    last_change_iso: new Date(last).toISOString(),
    age_days: Math.round((today - last) / DAY),
    median_gap_days: gaps.length ? Math.round(gaps[Math.floor(gaps.length / 2)] * 10) / 10 : null,
  };
}

/** Repo-relative path of the file a source URL serves. */
function pathOf(url) {
  const u = new URL(url);
  if (u.host !== "raw.githubusercontent.com") return null;
  const parts = u.pathname.split("/").filter(Boolean); // owner, repo, ref, ...rest
  return parts.slice(3).map(decodeURIComponent).join("/");
}

const repos = {};
const out = {};
for (const src of sources()) {
  // Measured for every GitHub-hosted feed, bundled or not: the bundled ones are bundled *because*
  const repo = REPOS[`${new URL(src.url).host}/${new URL(src.url).pathname.split("/").slice(1, 3).join("/")}`];
  if (!repo) continue;
  repos[repo.dir] ??= clone(repo.dir, repo.url);
  const file = pathOf(src.url);
  if (!file) continue;
  try {
    out[src.name] = { bucket: src.bucket, ...stats(gitLogDates(repos[repo.dir], file)) };
  } catch (e) {
    console.warn(`skip ${src.name}: ${e.message}`);
  }
}

writeFileSync(new URL("../data/churn.json", import.meta.url), JSON.stringify(out, null, 2) + "\n");

const rows = Object.entries(out).sort((a, b) => (a[1].median_gap_days ?? 1e9) - (b[1].median_gap_days ?? 1e9));
console.log(`${Object.keys(out).length} sources measured → data/churn.json\n`);
console.log("명칭".padEnd(24), "변경(180일)", "마지막", "경과", "중앙 간격");
for (const [name, s] of rows.slice(0, 20)) {
  console.log(
    name.padEnd(24),
    String(s.changes_180d).padStart(6),
    String(s.last_change).padStart(12),
    `${s.age_days}일`.padStart(6),
    `${s.median_gap_days ?? "-"}일`.padStart(9),
  );
}
