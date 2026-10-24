// Regenerates plugins/ip-classification.manifest.json from dist/pack.mjs.
//
// The bundle is authoritative (it is what runs); the catalog reads the JSON. Run after any manifest
// edit: node scripts/gen-manifest.mjs
import { writeFileSync } from "node:fs";
import pack from "../dist/pack.mjs";

const { plugins, ...meta } = pack;
const doc = { ...meta, plugins: plugins.map((p) => p.manifest) };
const out = new URL("../plugins/ip-classification.manifest.json", import.meta.url);
writeFileSync(out, JSON.stringify(doc, null, 2) + "\n");
console.log(`wrote plugins/ip-classification.manifest.json — ${doc.plugins.length} plugins`);
