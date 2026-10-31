// Copyright (c) 2026 TrueSignal Deception. All rights reserved.
//
// Fails the build if UI sources use constructs that would bypass output
// escaping or the CSP: raw HTML injection, eval-like calls, inline style
// attributes, or external URLs loaded at runtime. Untrusted data (event
// details, node aliases, manifest documentation) must only ever be rendered
// as text.
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "../src");
const rules = [
  [/dangerouslySetInnerHTML/, "raw HTML injection"],
  [/\.innerHTML\b|\.outerHTML\b|insertAdjacentHTML/, "raw HTML injection"],
  [/\beval\s*\(|new\s+Function\s*\(/, "dynamic code"],
  [/setAttribute\(\s*["']style["']/, "inline style attribute"],
  [/\sstyle=\{/, "inline style prop (use classes)"],
  [/document\.write/, "document.write"],
  [/@import\s+url\(\s*["']?https?:/, "external stylesheet"],
  [/fonts\.googleapis|cdn\.|unpkg|jsdelivr/, "external resource"],
];
let bad = 0;
async function walk(dir) {
  for (const e of await readdir(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) { await walk(p); continue; }
    if (!/\.(tsx?|css)$/.test(e.name)) continue;
    const lines = (await readFile(p, "utf8")).split("\n");
    lines.forEach((line, i) => {
      for (const [re, why] of rules) {
        if (re.test(line)) { console.error(`${path.relative(root, p)}:${i + 1}: ${why}`); bad++; }
      }
    });
  }
}
await walk(root);
if (bad) process.exit(1);
console.log("ui safety lint: ok");
