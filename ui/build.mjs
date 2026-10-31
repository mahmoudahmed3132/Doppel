// Copyright (c) 2026 TrueSignal Deception. All rights reserved.
//
// Builds the admin UI into hub/internal/webui/dist, which the Hub embeds.
// Output is one hashed script and one hashed stylesheet referenced from a
// static index.html: no inline script or style, so the Hub's strict CSP
// applies unchanged.
import { build } from "esbuild";
import { mkdir, readdir, rm, writeFile, copyFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const out = path.resolve(here, "../hub/internal/webui/dist");
const keep = new Set([".placeholder"]);

await mkdir(out, { recursive: true });
for (const f of await readdir(out)) {
  if (!keep.has(f)) await rm(path.join(out, f), { recursive: true, force: true });
}

const result = await build({
  entryPoints: [path.join(here, "src/main.tsx")],
  bundle: true,
  minify: true,
  sourcemap: false,
  format: "esm",
  target: ["es2022"],
  outdir: path.join(out, "assets"),
  entryNames: "[name]-[hash]",
  assetNames: "[name]-[hash]",
  metafile: true,
  legalComments: "none",
  jsx: "automatic",
  jsxImportSource: "preact",
  logLevel: "warning",
});

let js = "", css = "";
for (const [file, meta] of Object.entries(result.metafile.outputs)) {
  if (!meta.entryPoint && !file.endsWith(".css")) continue;
  const rel = "/" + path.relative(out, path.resolve(file)).split(path.sep).join("/");
  if (file.endsWith(".js")) js = rel;
  if (file.endsWith(".css")) css = rel;
}
if (!js || !css) throw new Error("build produced no entry script or stylesheet");

await copyFile(path.join(here, "public/favicon.svg"), path.join(out, "assets/favicon.svg"));

const html = `<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>TrueSignal</title>
<link rel="icon" href="/assets/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="${css}">
<script type="module" src="${js}"></script>
</head>
<body>
<div id="app"><noscript>The TrueSignal admin UI requires JavaScript.</noscript></div>
</body>
</html>
`;
await writeFile(path.join(out, "index.html"), html);
console.log(`ui: ${js} ${css}`);
