// Removes one plugin object from a hand-written, minified Vineyard bundle.
//
//   node scripts/remove-plugin.mjs <bundle> <pluginIdentifier>
//
// The packs in this org are distributed as a single hand-built ESM file with no source tree, so
// removing a plugin means cutting an object literal out of minified code. A naive brace counter
// breaks on braces inside strings, template literals and regexes; this scanner tracks those.
import { readFileSync, writeFileSync } from "node:fs";

const [file, identifier] = process.argv.slice(2);
if (!file || !identifier) {
  console.error("usage: remove-plugin.mjs <bundle> <pluginIdentifier>");
  process.exit(1);
}

let src = readFileSync(file, "utf8");

const anchor = `{manifest:{identifier:"${identifier}"`;
const at = src.indexOf(anchor);
if (at < 0) {
  console.error(`identifier not found: ${identifier}`);
  process.exit(1);
}

/** Index just past the object literal that starts at `start`. */
function endOfObject(text, start) {
  let depth = 0;
  let i = start;
  let prev = ""; // last significant character in code mode, to tell a regex from a division
  let mode = "code"; // code | single | double | template | regex | line-comment | block-comment
  while (i < text.length) {
    const c = text[i];
    const next = text[i + 1];
    if (mode === "code") {
      if (c === '"') mode = "double";
      else if (c === "'") mode = "single";
      else if (c === "`") mode = "template";
      else if (c === "/" && next === "/") { mode = "line-comment"; i++; }
      else if (c === "/" && next === "*") { mode = "block-comment"; i++; }
      else if (c === "/") {
        // A "/" starts a regex only where a value can begin; after an identifier, ")" or "]" it is
        // division, and treating it as a regex would swallow the rest of the file.
        mode = prev && !"([{,;:=&|!?+-*%<>~^}".includes(prev) ? "code" : "regex";
      }
      else if (c === "{") depth++;
      else if (c === "}") {
        depth--;
        if (depth === 0) return i + 1;
      }
      if (!/\s/.test(c)) prev = c;
    } else if (mode === "double" || mode === "single" || mode === "template") {
      if (c === "\\") i++;
      else if ((mode === "double" && c === '"') || (mode === "single" && c === "'") || (mode === "template" && c === "`")) mode = "code";
    } else if (mode === "regex") {
      if (c === "\\") i++;
      else if (c === "/") mode = "code";
      else if (c === "\n") mode = "code"; // not a regex after all
    } else if (mode === "line-comment") {
      if (c === "\n") mode = "code";
    } else if (mode === "block-comment") {
      if (c === "*" && next === "/") { mode = "code"; i++; }
    }
    i++;
  }
  return -1;
}

const end = endOfObject(src, at);
if (end < 0) {
  console.error("unterminated object literal");
  process.exit(1);
}

// Back up over `X=` (and `var ` or a leading comma) so the declaration goes too.
let start = at;
while (start > 0 && /\s/.test(src[start - 1])) start--;
if (src[start - 1] !== "=") {
  console.error("expected `=` before the object literal");
  process.exit(1);
}
start--;
while (start > 0 && /[A-Za-z0-9_$]/.test(src[start - 1])) start--;
let leadingComma = false;
if (src.slice(start - 4, start) === "var ") start -= 4;
else if (src[start - 1] === ",") {
  start -= 1;
  leadingComma = true;
}

// Drop a trailing separator instead when the declaration did not start with one.
let stop = end;
if (src[stop] === ";") stop++;
else if (!leadingComma && src[stop] === ",") stop++;

const removed = src.slice(start, stop);
const name = removed.match(/([A-Za-z0-9_$]+)\s*=\s*\{/)?.[1];
if (!name) {
  console.error(`could not read the variable name from ${JSON.stringify(removed.slice(0, 40))}`);
  process.exit(1);
}

src = src.slice(0, start) + src.slice(stop);

// Drop the name from the pack's plugins array, without leaving a trailing comma behind.
// Plain string surgery rather than a RegExp: the minified bundle has no spaces to anchor on, and
// escaping a dynamic name into a pattern is easy to get wrong.
const last = `,${name}]`;
const first = `[${name},`;
const middle = `,${name},`;
if (src.includes(last)) src = src.replace(last, "]");
else if (src.includes(first)) src = src.replace(first, "[");
else if (src.includes(middle)) src = src.replace(middle, ",");
else console.warn(`warning: no plugins[] entry referencing ${name} was found`);

writeFileSync(file, src);
console.log(`removed ${identifier} (${name}, ${removed.length} bytes) → ${src.length} bytes`);
