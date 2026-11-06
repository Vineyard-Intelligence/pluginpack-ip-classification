// Assembles dist/pack.mjs from src/template.mjs + src/dataset.json. There is no bundler and no
// dependency here: the bundle IS the template with one line filled in, so anyone can check the
// published file against this source:
//
//   node build.mjs && git diff --exit-code dist/pack.mjs
//
// src/dataset.json is committed, unlike data/, because a bundle that needs the network to rebuild
// cannot be checked: `generated_at` alone would differ on every run. `npm run update-data` rewrites
// it; commit the result with the bundle.
//
// Usage: node build.mjs && node scripts/gen-manifest.mjs
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

// Key order matters: it is the order written into the bundle.
const dataset = JSON.parse(readFileSync(join(here, "src", "dataset.json"), "utf8"));

const template = readFileSync(join(here, "src", "template.mjs"), "utf8");
const marker = "const DATASET = /*__DATA__*/ null;";
if (!template.includes(marker)) {
  console.error(`marker not found in src/template.mjs: ${marker}`);
  process.exit(1);
}

const bundle = template.replace(marker, `const DATASET = ${JSON.stringify(dataset)};`);
mkdirSync(join(here, "dist"), { recursive: true });
writeFileSync(join(here, "dist", "pack.mjs"), bundle);

console.log(`wrote dist/pack.mjs — ${(bundle.length / 1024).toFixed(0)} KiB`);
