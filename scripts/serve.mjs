// Minimal static server for the dev loader.
//
//   node scripts/serve.mjs [port]
//
// The Vineyard dev loader fetches the manifest and then imports the bundle from another origin, so
// the responses need `Access-Control-Allow-Origin` and `.mjs` needs a JavaScript MIME type.
// `python3 -m http.server` does neither, and the import fails with an opaque error.
import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { extname, join, normalize, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const ROOT_PREFIX = ROOT.endsWith(sep) ? ROOT : ROOT + sep;
const PORT = Number(process.argv[2] ?? 8787);

const TYPES = {
  ".json": "application/json; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".md": "text/markdown; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
  ".map": "application/json; charset=utf-8",
};

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
  let rel = decodeURIComponent(url.pathname);

  // The dev loader resolves a relative `platforms.web.entry` against the MANIFEST's directory
  // (frontend/.../plugins/remote.ts — a documented shipped bug), so the published
  // `dist/pack.mjs` becomes `/plugins/dist/pack.mjs`. Two ways out, both here:
  //   1. /dev/manifest.json serves the same manifest with an ABSOLUTE entry, which remote.ts
  //      leaves untouched — this is the correct way to test locally.
  //   2. anything under /plugins/dist/ is mapped to /dist/, so the mis-resolved URL still works.
  if (rel === "/dev/manifest.json" || rel === "/dev/manifest") {
    const doc = JSON.parse(await readFile(join(ROOT, "plugins/ip-classification.manifest.json"), "utf8"));
    const origin = `http://${req.headers.host ?? `127.0.0.1:${PORT}`}`;
    doc.platforms.web.entry = `${origin}/dist/pack.mjs`;
    res.writeHead(200, {
      "access-control-allow-origin": "*",
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    });
    res.end(JSON.stringify(doc, null, 2));
    return;
  }

  if (rel.startsWith("/plugins/dist/")) rel = rel.replace("/plugins", "");

  const target = normalize(join(ROOT, rel));

  // Never serve outside the pack directory. Compare against "ROOT/" so a sibling such as
  // /tmp/pack-evil does not pass a plain startsWith(ROOT) check.
  if (target !== ROOT && !target.startsWith(ROOT_PREFIX)) {
    res.writeHead(403, { "access-control-allow-origin": "*" }).end("forbidden");
    return;
  }

  const headers = {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET, HEAD, OPTIONS",
    "access-control-allow-headers": "*",
    "cache-control": "no-store",
  };

  if (req.method === "OPTIONS") {
    res.writeHead(204, headers).end();
    return;
  }

  try {
    const info = await stat(target);
    if (info.isDirectory()) {
      // Directory listing, so /data/ etc. is browsable while testing.
      const { readdir } = await import("node:fs/promises");
      const entries = await readdir(target, { withFileTypes: true });
      const rows = entries
        .map((e) => `<li><a href="${join(rel, e.name)}${e.isDirectory() ? "/" : ""}">${e.name}</a></li>`)
        .join("");
      res.writeHead(200, { ...headers, "content-type": "text/html; charset=utf-8" }).end(`<ul>${rows}</ul>`);
      return;
    }
    const body = await readFile(target);
    const type = TYPES[extname(target)] ?? "application/octet-stream";
    res.writeHead(200, { ...headers, "content-type": type, "content-length": body.length });
    res.end(req.method === "HEAD" ? undefined : body);
  } catch {
    res.writeHead(404, { ...headers, "content-type": "text/plain" }).end(`not found: ${rel}`);
  }
});

server.listen(PORT, "127.0.0.1", () => {
  console.log(`serving ${ROOT}`);
  console.log(`dev       http://127.0.0.1:${PORT}/dev/manifest.json   ← use this in the dev loader`);
  console.log(`published http://127.0.0.1:${PORT}/plugins/ip-classification.manifest.json`);
  console.log(`bundle    http://127.0.0.1:${PORT}/dist/pack.mjs`);
});
