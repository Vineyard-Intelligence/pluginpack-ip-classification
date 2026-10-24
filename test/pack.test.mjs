// Unit tests for the IP Classification pack. Run with: node --test test/pack.test.mjs
//
// The bundle needs no app and no SDK build: the mock context reproduces the SDK's documented
// semantics (per-verb presence, merged updates, created-node lookup). `ctx.net.fetch` is served from
// a fixture shaped like the observation index (index.json + one /8 shard), so the lookup path is
// exercised without touching the network.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import pack from "../dist/pack.mjs";

const plugin = pack.plugins[0];
const BASE = "https://raw.githubusercontent.com/Vineyard-Intelligence/ip-observation-history/main";

const SOURCES = {
  shodan: { source: "https://example.test/shodan_v4.txt", bucket: "scanners" },
  cobalt_strike: { source: "https://example.test/Cobalt Strike C2 IPs.txt", bucket: "c2" },
  remcos: { source: "https://example.test/Remcos IPs.txt", bucket: "c2" },
  googlebot: { source: "https://example.test/googlebot.json", bucket: "bots" },
  nordvpn_entry: { source: "https://example.test/servers", bucket: "anonymizer" },
  unallocated_bogon: { source: "https://example.test/fullbogons.txt", bucket: "bogon" },
};

const OBSERVED = 1792800000;

// [tag, ref_first, ref_last, first_observed_at, first_seen_at, last_seen_at]
const SHARDS = {
  "002": {
    "2.59.22.234": [["shodan", null, null, OBSERVED, null, OBSERVED]],
    "2.56.190.2": [["nordvpn_entry", null, null, OBSERVED, null, OBSERVED]],
    "2.56.190.3": [
      ["nordvpn_entry", null, null, OBSERVED, null, OBSERVED],
      ["shodan", null, null, OBSERVED, null, OBSERVED],
    ],
  },
  "001": {
    "1.15.76.39": [["cobalt_strike", "fdf4f8b2", "a1b2c3d4", null, 1784505600, 1784505600]],
  },
  "008": {
    "8.0.1.1": [["remcos", "aaaa1111", "bbbb2222", null, 1784505600, 1784505600]],
  },
  "034": {
    "34.22.85.0/24": [["googlebot", null, null, OBSERVED, null, OBSERVED]],
  },
  "223": {
    "223.0.0.0/8": [["unallocated_bogon", null, null, OBSERVED, null, OBSERVED]],
  },
};

const INDEX = { built_at: OBSERVED, sources: SOURCES, shards: {}, empty_bitmap: "" };

/** ctx.net.fetch stand-in serving index.json and the shards above. */
function makeNet({ fail = [], calls } = {}) {
  return async (url) => {
    calls?.push(url);
    if (fail.some((f) => url.includes(f))) return { ok: false, status: 500, text: async () => "", json: async () => ({}) };
    if (url.endsWith("/index.json")) {
      return { ok: true, status: 200, text: async () => JSON.stringify(INDEX), json: async () => INDEX };
    }
    const name = url.match(/shards\/(\d{3})\.json(?:\?|$)/)?.[1];
    if (name && SHARDS[name]) {
      const body = SHARDS[name];
      return { ok: true, status: 200, text: async () => JSON.stringify(body), json: async () => body };
    }
    return { ok: false, status: 404, text: async () => "", json: async () => ({}) };
  };
}

function makeCtx({ nodes = [], granted = {}, params = {}, selection, net, fail, calls } = {}) {
  const createdNodes = [];
  const progress = [];
  const createdEdges = [];
  const updates = new Map();
  const find = (id) => nodes.find((n) => n.id === id) ?? createdNodes.find((n) => n.id === id);

  const graph = {};
  if (granted.graph?.includes("node:read")) {
    graph.get = async (id) => find(id) ?? null;
    graph.list = async () => ({ nodes });
  }
  if (granted.graph?.includes("node:update")) {
    graph.updateNode = async (id, data) => {
      const node = find(id);
      updates.set(id, { ...(updates.get(id) ?? {}), ...data });
      if (node) node.data = { ...node.data, ...data };
    };
  }
  if (granted.graph?.includes("node:create")) {
    graph.createNode = async (draft) => {
      const node = { id: `new-${createdNodes.length + 1}`, type: draft.type, data: { ...draft.data } };
      createdNodes.push(node);
      return node;
    };
  }
  if (granted.graph?.includes("edge:create")) {
    graph.createEdge = async (edge) => createdEdges.push(edge);
  }

  return {
    run: { runId: "test", projectId: "p", pluginId: "x", grantedScopes: granted, platform: "web" },
    input: { selection: selection ?? nodes.map((n) => n.id) },
    params,
    progress: { set(p) { progress.push(p); } },
    signal: new AbortController().signal,
    graph: Object.keys(graph).length ? graph : undefined,
    net: net === false ? undefined : { fetch: net ?? makeNet({ fail, calls }) },
    mock: { createdNodes, createdEdges, updates, progress },
  };
}

const ipNode = (id, ip) => ({ id, type: "infrastructure.ip_address", data: { ip_address: ip } });
const allGraph = { graph: ["node:read", "node:update", "node:create", "edge:create"] };
const patched = (ctx) => ctx.mock.updates.get("a");

/** Progress events a run emitted, in order. */
function progressOf(ctx) {
  return ctx.mock.progress.map((p) => p.message);
}

test("progress: a run reports what it is doing, and never mentions shards", async () => {
  const nodes = [ipNode("a", "2.59.22.234"), ipNode("b", "1.15.76.39")];
  const ctx = makeCtx({ granted: allGraph, nodes });
  const res = await plugin.run(ctx);
  const messages = progressOf(ctx);
  assert.ok(messages.length >= 3, `expected progress events, got ${JSON.stringify(messages)}`);
  assert.equal(messages[0], "loading address data");
  assert.ok(messages.some((m) => /classified/.test(m)), messages.join(" | "));
  assert.equal(messages.some((m) => /shard/i.test(m)), false, messages.join(" | "));
  assert.equal(/shard/i.test(res.summary), false, res.summary);
});

test("windows merge monotonically: a later run cannot narrow what an earlier one saw", async () => {
  const seen = "2026-07-20T00:00:00.000Z";
  // The node already carries a wider window than this run will find.
  const node = {
    id: "a",
    type: "infrastructure.ip_address",
    data: { ip_address: "1.15.76.39", c2_first_seen: "2026-01-01T00:00:00.000Z", c2_last_seen: "2026-12-31T00:00:00.000Z" },
  };
  const ctx = makeCtx({ granted: allGraph, nodes: [node] });
  await plugin.run(ctx);
  const patch = patched(ctx);
  assert.equal(patch.c2_first_seen, undefined, "an earlier first_seen must not be pushed later");
  assert.equal(patch.c2_last_seen, undefined, "a later last_seen must not be pulled earlier");

  // A node whose stored window is narrower than this run's is widened.
  const narrow = {
    id: "a",
    type: "infrastructure.ip_address",
    data: { ip_address: "1.15.76.39", c2_first_seen: seen, c2_last_seen: seen },
  };
  const run = makeCtx({ granted: allGraph, nodes: [narrow] });
  await plugin.run(run);
  assert.equal(patched(run).c2_first_seen, undefined, "same instant is not an update");
  assert.equal(patched(run).c2_last_seen, undefined, "same instant is not an update");

  const older = {
    id: "a",
    type: "infrastructure.ip_address",
    data: { ip_address: "1.15.76.39", c2_first_seen: "2026-09-01T00:00:00.000Z", c2_last_seen: "2026-09-02T00:00:00.000Z" },
  };
  const widen = makeCtx({ granted: allGraph, nodes: [older] });
  await plugin.run(widen);
  assert.equal(patched(widen).c2_first_seen, seen, "an earlier first_seen replaces a later one");
  // The fixture's last sighting (2026-07-20) predates what the node already stores (2026-09-02).
  assert.equal(patched(widen).c2_last_seen, undefined, "a later stored last_seen survives");
});

test("every URL the run fetches is covered by the declared network scope", async () => {
  // The scope is an allowlist matched on origin + path-segment prefix. Reading the data from raw
  // while the manifest still named jsDelivr is exactly how a live run ends with "address data
  // unavailable": the fetch is refused, not slow.
  const [scope] = plugin.manifest.scopes.network;
  const fetched = [];
  const ctx = makeCtx({ granted: allGraph, nodes: [ipNode("a", "1.15.76.39")] });
  const inner = ctx.net.fetch;
  ctx.net.fetch = async (u) => { fetched.push(String(u)); return inner(u); };
  await plugin.run(ctx);
  assert.ok(fetched.length >= 2, `expected index + shard, got ${JSON.stringify(fetched)}`);
  for (const u of fetched) {
    const target = new URL(u);
    const allowed = new URL(scope.endpoint);
    assert.equal(target.origin, allowed.origin, `${u} leaves the declared origin`);
    assert.ok(
      target.pathname === allowed.pathname || target.pathname.startsWith(`${allowed.pathname}/`),
      `${u} leaves the declared path`,
    );
  }
});

test("the plugin identifier and title use the same words", async () => {
  assert.equal(plugin.manifest.name, "IP Classification");
  assert.equal(plugin.manifest.identifier, "run.vineyard.plugins.ip_classification");
});

test("scope carries no source field", async () => {
  // A scanner or C2 value is a claim by a list, so it names the list. A scope is a fact about the
  // address (RFC 6890, the bogon feed) and needs no provenance field beside it.
  const ctx = makeCtx({ granted: allGraph, nodes: [ipNode("a", "223.1.2.3")] });
  await plugin.run(ctx);
  assert.equal(patched(ctx).ip_scope, "unallocated");
  assert.equal("ip_scope_source" in patched(ctx), false);
});

test("selection: a public address no list names is left untouched", async () => {
  // "public" is the absence of a finding, not a finding. Writing ip_scope=public + is_bogon=false
  // on every plain address made a node look classified when nothing had been found.
  const ctx = makeCtx({ granted: allGraph, nodes: [ipNode("a", "8.8.8.8")] });
  const res = await plugin.run(ctx);
  assert.equal(ctx.mock.updates.size, 0, "no write for an address with nothing to say");
  assert.match(res.summary, /public, no list names it/);
  assert.equal(res.summary.includes("shard"), false, "shards are internal");
});

test("selection: a public address in a list carries no scope", async () => {
  const ctx = makeCtx({ granted: allGraph, nodes: [ipNode("a", "2.59.22.234")] });
  await plugin.run(ctx);
  const patch = patched(ctx);
  assert.equal("ip_scope" in patch, false);
  assert.equal("is_bogon" in patch, false);
  assert.equal(patch.scanner, "shodan");
});

test("selection: RFC 6890 ranges resolve without reading a shard", async () => {
  for (const [ip, scope] of [
    ["10.1.2.3", "private"],
    ["100.64.0.1", "cgnat"],
    ["198.18.0.5", "benchmark"],
  ]) {
    const calls = [];
    const ctx = makeCtx({ granted: allGraph, nodes: [ipNode("a", ip)], calls });
    await plugin.run(ctx);
    assert.equal(patched(ctx).ip_scope, scope, ip);
    assert.equal(calls.length, 1, `${ip} should only read index.json`);
  }
});

test("selection: a scanner range sets the field, the tag and the source url", async () => {
  const ctx = makeCtx({ granted: allGraph, nodes: [ipNode("a", "2.59.22.234")] });
  const res = await plugin.run(ctx);
  assert.equal(patched(ctx).scanner, "shodan");
  assert.equal(patched(ctx).scanner_source, SOURCES.shodan.source);
  assert.deepEqual(patched(ctx).tags, ["scanner"]);
  assert.match(res.summary, /scanner=shodan/);
});

test("selection: a C2 address creates a Tool node and a 'used as C2' edge", async () => {
  const ctx = makeCtx({ granted: allGraph, nodes: [ipNode("a", "1.15.76.39")] });
  const res = await plugin.run(ctx);
  const tool = ctx.mock.createdNodes.find((n) => n.type === "threat.tool");
  assert.equal(tool.data.name, "Cobalt Strike");
  assert.equal(tool.data.tool_type, "c2");
  assert.equal(ctx.mock.createdEdges.length, 1);
  assert.equal(ctx.mock.createdEdges[0].label, "used as C2");
  assert.equal(patched(ctx).c2_family, "cobalt_strike");
  assert.equal(patched(ctx).c2_source, SOURCES.cobalt_strike.source);
  assert.deepEqual(patched(ctx).tags, ["c2"]);
  assert.match(res.summary, /c2=cobalt_strike \(1 node\(s\) linked\)/);
});

test("selection: a RAT family becomes a Malware node, not a Tool", async () => {
  const ctx = makeCtx({ granted: allGraph, nodes: [ipNode("a", "8.0.1.1")] });
  await plugin.run(ctx);
  const malware = ctx.mock.createdNodes.find((n) => n.type === "threat.malware");
  assert.equal(malware.data.name, "Remcos");
  assert.equal(malware.data.is_family, true);
  assert.equal(ctx.mock.createdNodes.some((n) => n.type === "threat.tool"), false);
});

test("selection: crawler and anonymizer land in their own fields", async () => {
  const crawler = makeCtx({ granted: allGraph, nodes: [ipNode("a", "34.22.85.9")] });
  await plugin.run(crawler);
  assert.equal(patched(crawler).crawler, "googlebot");
  assert.equal(patched(crawler).crawler_source, SOURCES.googlebot.source);
  assert.deepEqual(patched(crawler).tags, ["crawler"]);

  const anon = makeCtx({ granted: allGraph, nodes: [ipNode("a", "2.56.190.2")] });
  await plugin.run(anon);
  assert.equal(patched(anon).anonymizer, "nordvpn_entry");
  assert.equal(patched(anon).anonymizer_source, SOURCES.nordvpn_entry.source);
  assert.deepEqual(patched(anon).tags, ["anonymizer"]);
});

test("selection: one address can carry several tags", async () => {
  const ctx = makeCtx({ granted: allGraph, nodes: [ipNode("a", "2.56.190.3")] });
  await plugin.run(ctx);
  assert.equal(patched(ctx).anonymizer, "nordvpn_entry");
  assert.equal(patched(ctx).scanner, "shodan");
  assert.equal(patched(ctx).anonymizer_source, SOURCES.nordvpn_entry.source);
  assert.equal(patched(ctx).scanner_source, SOURCES.shodan.source);
  assert.deepEqual(patched(ctx).tags, ["scanner", "anonymizer"]);
});

test("selection: a bogon range reports unallocated and tags bogon", async () => {
  const ctx = makeCtx({ granted: allGraph, nodes: [ipNode("a", "223.1.2.3")] });
  await plugin.run(ctx);
  assert.equal(patched(ctx).ip_scope, "unallocated");
  assert.equal("is_bogon" in patched(ctx), false);
  assert.deepEqual(patched(ctx).tags, ["bogon"]);
});

test("selection: a node whose value is not IPv4 is skipped, not guessed", async () => {
  for (const ip of ["nope", "1.2.3", "1.2.3.4.5", "999.1.1.1", "1.2.3.4/24"]) {
    const ctx = makeCtx({ granted: allGraph, nodes: [ipNode("a", ip)] });
    const res = await plugin.run(ctx);
    assert.match(res.summary, /skipped 1/, ip);
    assert.equal(ctx.mock.updates.size, 0, ip);
  }
});

test("network absent: the run still resolves the RFC 6890 scope", async () => {
  const ctx = makeCtx({ granted: allGraph, nodes: [ipNode("a", "10.9.9.9")], net: false });
  const res = await plugin.run(ctx);
  assert.equal(patched(ctx).ip_scope, "private");
  assert.match(res.summary, /address data unavailable/);
});

test("a failing shard is reported, not fatal", async () => {
  const ctx = makeCtx({ granted: allGraph, nodes: [ipNode("a", "2.59.22.234")], fail: ["shards/002"] });
  const res = await plugin.run(ctx);
  // The shard failed, so nothing matched — and a failed lookup is not a "public" verdict either.
  assert.equal(ctx.mock.updates.size, 0);
  assert.match(res.summary, /some address data could not be read/);
});

test("caching: a 3-IP selection reads index.json once and one shard per /8", async () => {
  const calls = [];
  const nodes = [ipNode("a", "2.59.22.234"), ipNode("b", "2.56.190.2"), ipNode("c", "34.22.85.9")];
  const ctx = makeCtx({ granted: allGraph, nodes, calls });
  await plugin.run(ctx);
  assert.equal(calls.filter((u) => u.endsWith("/index.json")).length, 1);
  assert.equal(calls.filter((u) => u.includes("/shards/")).length, 2, "002 is shared by two addresses");
});

test("selection: attributes existing nodes without creating an IP node", async () => {
  const nodes = [ipNode("a", "1.15.76.39")];
  const ctx = makeCtx({ granted: allGraph, nodes });
  const res = await plugin.run(ctx);
  assert.equal(ctx.mock.createdNodes.filter((n) => n.type === "infrastructure.ip_address").length, 0);
  assert.equal(ctx.mock.updates.get("a").c2_family, "cobalt_strike");
  assert.match(res.summary, /^1\.15\.76\.39: .*c2=cobalt_strike/);
});

test("selection: non-IP nodes are skipped and reported", async () => {
  const nodes = [ipNode("a", "2.59.22.234"), { id: "b", type: "infrastructure.domain", data: { domain: "x.test" } }];
  const ctx = makeCtx({ granted: allGraph, nodes });
  const res = await plugin.run(ctx);
  assert.match(res.summary, /skipped 1/);
});

test("selection: IPv6 is skipped rather than guessed", async () => {
  const nodes = [ipNode("a", "2001:db8::1")];
  const ctx = makeCtx({ granted: allGraph, nodes });
  const res = await plugin.run(ctx);
  assert.match(res.summary, /skipped 1/);
  assert.equal(ctx.mock.updates.size, 0);
});

test("nothing selected explains itself", async () => {
  const ctx = makeCtx({ granted: allGraph, selection: [] });
  const res = await plugin.run(ctx);
  assert.match(res.summary, /Select one or more IP Address nodes/);
});

test("scope boundary: without graph scopes nothing throws", async () => {
  const ctx = makeCtx({ granted: {}, nodes: [ipNode("a", "1.2.3.4")] });
  const res = await plugin.run(ctx);
  assert.match(res.summary, /Needs node:read/);
});

test("the manifest declares the seed type the run dialog filters on", async () => {
  const manifest = JSON.parse(readFileSync(new URL("../plugins/ip-classification.manifest.json", import.meta.url), "utf8"));
  const consumes = manifest.plugins[0].io.consumes;
  // An empty list means "whole graph" in RunPluginsDialog: it would be handed every node.
  assert.equal(consumes.length, 1);
  assert.equal(consumes[0].typepack, "run.vineyard.typepacks.infrastructure");
  assert.equal(consumes[0].name, "ip_address");
});

test("the catalog manifest matches the bundle", async () => {
  const manifest = JSON.parse(readFileSync(new URL("../plugins/ip-classification.manifest.json", import.meta.url), "utf8"));
  assert.equal(manifest.identifier, pack.identifier);
  assert.equal(manifest.version, pack.version);
  assert.equal(manifest.plugins[0].identifier, plugin.manifest.identifier);
  assert.equal(manifest.plugins[0].name, plugin.manifest.name);
  assert.ok(manifest.plugins[0].description.length <= 1024);
  assert.ok(manifest.plugins[0].name.length <= 128);
  assert.ok(manifest.description.length <= 1024);
  assert.ok(BASE.includes("ip-observation-history"));
});
