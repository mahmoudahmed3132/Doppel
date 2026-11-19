// Copyright (c) 2026 TrueSignal Deception. All rights reserved.
//
// Builds the admin UI into hub/internal/webui/dist, which the Hub embeds.
// Output is one hashed script and one hashed stylesheet referenced from a
// static index.html: no inline script or style, so the Hub's strict CSP
// applies unchanged.
import { build } from "esbuild";
import { mkdir, readdir, readFile, rm, writeFile, copyFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const out = path.resolve(here, "../hub/internal/webui/dist");
const keep = new Set([".placeholder"]);

// Compile world-atlas Natural Earth 1:110m TopoJSON into static equirectangular
// SVG path strings (viewBox="0 0 1000 500") so the Geo map renders offline
// with zero runtime TopoJSON library and zero runtime network fetches.
async function generateWorldPaths() {
  const topoPath = path.join(here, "node_modules/world-atlas/countries-110m.json");
  const topo = JSON.parse(await readFile(topoPath, "utf8"));
  const { scale, translate } = topo.transform;
  const decodedArcs = topo.arcs.map((arc) => {
    let x = 0, y = 0;
    return arc.map(([dx, dy]) => {
      x += dx;
      y += dy;
      const lon = x * scale[0] + translate[0];
      const lat = y * scale[1] + translate[1];
      return [
        Math.round(((lon + 180) * (1000 / 360)) * 10) / 10,
        Math.round(((90 - lat) * (500 / 180)) * 10) / 10,
      ];
    });
  });

  const ringToPath = (ring) => {
    const pts = [];
    for (const idx of ring) {
      const arc = idx >= 0 ? decodedArcs[idx] : decodedArcs[~idx].slice().reverse();
      for (let i = pts.length ? 1 : 0; i < arc.length; i++) pts.push(arc[i]);
    }
    if (pts.length < 3) return "";
    let d = `M${pts[0][0]},${pts[0][1]}`;
    for (let i = 1; i < pts.length; i++) d += `L${pts[i][0]},${pts[i][1]}`;
    return d + "Z";
  };

  const countries = [];
  for (const g of topo.objects.countries.geometries) {
    const polys = g.type === "Polygon" ? [g.arcs] : g.type === "MultiPolygon" ? g.arcs : [];
    const parts = [];
    for (const poly of polys) {
      for (const ring of poly) {
        const seg = ringToPath(ring);
        if (seg) parts.push(seg);
      }
    }
    if (!parts.length) continue;
    countries.push({
      id: String(g.id ?? ""),
      name: String(g.properties?.name ?? ""),
      d: parts.join(""),
    });
  }
  countries.sort((a, b) => a.id.localeCompare(b.id) || a.name.localeCompare(b.name));

  const genDir = path.join(here, "src/generated");
  await mkdir(genDir, { recursive: true });
  const ts = [
    "// Copyright (c) 2026 TrueSignal Deception. All rights reserved.",
    "//",
    "// Generated at build time by ui/build.mjs from world-atlas/countries-110m.json",
    "// (Natural Earth 1:110m, ISC). Do not edit by hand.",
    "",
    'export const WORLD_VIEWBOX = "0 0 1000 500";',
    "export const WORLD_WIDTH = 1000;",
    "export const WORLD_HEIGHT = 500;",
    "",
    "export interface WorldCountryPath {",
    "  readonly id: string;",
    "  readonly name: string;",
    "  readonly d: string;",
    "}",
    "",
    `export const WORLD_COUNTRIES: readonly WorldCountryPath[] = ${JSON.stringify(countries)};`,
    "",
  ].join("\n");
  await writeFile(path.join(genDir, "world-paths.ts"), ts);
}

await generateWorldPaths();

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
<title>Doppel</title>
<link rel="icon" href="/assets/favicon.svg" type="image/svg+xml">
<link rel="stylesheet" href="${css}">
<script type="module" src="${js}"></script>
</head>
<body>
<div id="app"><noscript>The Doppel admin UI requires JavaScript.</noscript></div>
</body>
</html>
`;
await writeFile(path.join(out, "index.html"), html);
console.log(`ui: ${js} ${css}`);
