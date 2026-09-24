#!/usr/bin/env node
// Render site/ for one deployment: the tree ic-git serves at /site/<repo>/.
//
//   node tools/stage-site.mjs --src site --out dist/site --poll-canister ID [--git-canister ID]
//
// Three things distinguish the served bundle from the source tree, and all
// are done here rather than by hand so that they cannot be done halfway:
//
// 1. config.js names the poll canister. It is `null` in the source on
//    purpose (config.js explains why the trust anchors live in the bundle),
//    and the id only exists once ic-git has created the app canister, so
//    it is injected at staging time.
//
// 2. The page's JavaScript is one file. In the source tree app.js imports
//    config.js and lib/*.js as ES modules. A browser applies a <script>
//    tag's `integrity` to the one file the tag names and to nothing else:
//    import specifiers carry no hash, so every module the pinned script
//    pulls in would be fetched from the gateway unchecked, and a gateway
//    could serve the honest index.html and app.js while swapping the module
//    that holds the trust anchors or computes the verdict. ic-git's scanner
//    stops at the same line and says so (site.rs, unverifiable_subresource:
//    the import chain of a pinned module "is the operator's job"). So the
//    whole module graph is linked into a single app.js here, and the served
//    tree carries no other script. The linker is small and strict on
//    purpose: each module keeps its own scope, an import becomes a read of
//    a module that has already been evaluated, a module's exports become
//    the object it evaluates to, modules are emitted in the order the
//    browser would have evaluated them, and any import or export shape the
//    linker does not recognise fails the stage instead of being guessed at.
//
// 3. index.html loads ./style.css and ./app.js. ic-git refuses to serve an
//    entrypoint whose subresources carry no `integrity` (site.rs,
//    unverifiable_subresource): a hash on the page alone attests one blob,
//    and a gateway could swap an unpinned stylesheet or script while every
//    other check passed. So each tag gets a sha384 of the file it names,
//    and with (2) that covers every byte the page runs.
//
// After writing, the page is scanned again from the bytes on disk with the
// same rule the canister applies, so a stage that would be refused at serve
// time fails here instead. Zero dependencies.

import { cpSync, readFileSync, writeFileSync, rmSync, existsSync, readdirSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { join, posix } from "node:path";

function fail(msg) {
  console.error(`stage-site: ${msg}`);
  process.exit(1);
}

const args = { src: "site", out: "dist/site", poll: "", git: "" };
const argv = process.argv.slice(2);
for (let i = 0; i < argv.length; i++) {
  const next = () => argv[++i] ?? fail(`${argv[i - 1]} needs a value`);
  switch (argv[i]) {
    case "--src": args.src = next(); break;
    case "--out": args.out = next(); break;
    case "--poll-canister": args.poll = next(); break;
    case "--git-canister": args.git = next(); break;
    default: fail(`unknown arg: ${argv[i]}`);
  }
}
if (!args.poll) fail("--poll-canister is required");
// Principal text: groups of base32 separated by dashes. Loose on purpose;
// the canister rejects a malformed id, this only catches a pasted blank.
const principal = /^[a-z0-9]+(-[a-z0-9]+)+$/;
if (!principal.test(args.poll)) fail(`not a principal: ${args.poll}`);
if (args.git && !principal.test(args.git)) fail(`not a principal: ${args.git}`);

rmSync(args.out, { recursive: true, force: true });
cpSync(args.src, args.out, { recursive: true });

// --- 1. config.js -----------------------------------------------------------

const cfgPath = join(args.out, "config.js");
let cfg = readFileSync(cfgPath, "utf8");
// Test for the pattern, not for changed bytes: a value that is already what
// was asked for is a match that happens to rewrite nothing.
const setField = (name, pattern, value) => {
  if (!pattern.test(cfg)) fail(`config.js has no \`${name}\` line to set`);
  cfg = cfg.replace(pattern, `$1${JSON.stringify(value)},`);
};
setField("pollCanisterId: null", /^(\s*pollCanisterId:\s*)null,/m, args.poll);
if (args.git) setField("siteCanisterId", /^(\s*siteCanisterId:\s*)"[^"]*",/m, args.git);
writeFileSync(cfgPath, cfg);

// --- 2. link the module graph into one app.js ---------------------------------
//
// Only these statement shapes are understood, each at the start of a line:
//
//   import * as ns from "./x.js";
//   import { a, b as c } from "./x.js";        (may span lines)
//   export const|class|function|async function name
//   export { a, b as c };
//
// Not understood, and refused: default imports and exports, re-exports
// (`export ... from`), `export let|var` (a binding the module could reassign
// after evaluation, which the snapshot below would not follow), dynamic
// `import()`, `import.meta`, bare specifiers, and circular imports. None
// occur in site/; if one is added, extend the linker deliberately or the
// stage fails.

const ENTRY = "app.js";
const sha256hex = (bytes) => createHash("sha256").update(bytes).digest("hex");
const ident = "[A-Za-z_$][\\w$]*";
const RE_IMPORT = new RegExp(`^import (\\* as (${ident})|\\{([^}]*)\\}) from "([^"]+)";[ \\t]*\\n?`, "gm");
const RE_EXPORT_DECL = new RegExp(`^export (const|class|function|async function) (${ident})\\b`, "gm");
const RE_EXPORT_LIST = /^export \{([^}]*)\};[ \t]*\n?/gm;

const splitNames = (list, where) =>
  list.split(",").map((s) => s.trim()).filter(Boolean).map((raw) => {
    const m = new RegExp(`^(${ident})(?: as (${ident}))?$`).exec(raw);
    if (!m) fail(`${where}: cannot read the name \`${raw}\``);
    return { from: m[1], to: m[2] ?? m[1] };
  });

const modules = new Map(); // key -> { key, body, imports, exports }
const order = []; // evaluation order: dependencies before dependents
const visiting = new Set();

function link(key, importedBy) {
  if (modules.has(key)) return;
  if (visiting.has(key)) fail(`circular import: ${key} is imported by ${importedBy} and (transitively) imports it`);
  const file = join(args.out, key);
  if (!existsSync(file)) fail(`${importedBy} imports ${key}, which is not in the bundle`);
  visiting.add(key);
  const source = readFileSync(file, "utf8");
  if (/\bimport\s*\(|\bimport\.meta\b/.test(source)) {
    fail(`${key} uses import() or import.meta, which the linker cannot pin`);
  }

  const imports = [];
  let body = source.replace(RE_IMPORT, (_whole, _kind, ns, names, spec) => {
    if (!spec.startsWith("./") && !spec.startsWith("../")) fail(`${key} imports bare specifier "${spec}"`);
    const target = posix.normalize(posix.join(posix.dirname(key), spec));
    if (target.startsWith("../")) fail(`${key} imports ${spec}, which leaves the bundle`);
    imports.push(ns ? { target, ns } : { target, names: splitNames(names, `${key} import from ${spec}`) });
    return "";
  });

  const exports = []; // { local, exported }
  body = body.replace(RE_EXPORT_DECL, (_whole, kind, name) => {
    exports.push({ local: name, exported: name });
    return `${kind} ${name}`;
  });
  body = body.replace(RE_EXPORT_LIST, (_whole, list) => {
    for (const { from, to } of splitNames(list, `${key} export list`)) exports.push({ local: from, exported: to });
    return "";
  });

  const leftover = /^(import|export)\b.*$/m.exec(body);
  if (leftover) fail(`${key}: the linker does not understand \`${leftover[0].trim()}\``);
  const seen = new Set();
  for (const e of exports) {
    if (seen.has(e.exported)) fail(`${key} exports \`${e.exported}\` twice`);
    seen.add(e.exported);
  }

  // Dependencies first, in import order: the order the browser evaluates them.
  for (const imp of imports) link(imp.target, key);
  visiting.delete(key);
  modules.set(key, { key, body, imports, exports, sha256: sha256hex(source) });
  order.push(key);
}
link(ENTRY, "index.html");

// Every named import must be something its target actually exports. The
// browser would refuse the graph at link time; refuse it here instead.
for (const mod of modules.values()) {
  for (const imp of mod.imports) {
    if (!imp.names) continue;
    const have = new Set(modules.get(imp.target).exports.map((e) => e.exported));
    for (const { from } of imp.names) {
      if (!have.has(from)) fail(`${mod.key} imports \`${from}\` from ${imp.target}, which does not export it`);
    }
  }
}

const q = JSON.stringify;
let linked = `// ${ENTRY}: the site's module graph linked into one file by tools/stage-site.mjs,
// so that the integrity hash index.html carries for this file covers every
// module the page runs. Not hand-written; edit the source tree and re-stage.
// Modules in evaluation order, each with the sha256 of its source:
${order.map((k) => `//   ${k.padEnd(22)} ${modules.get(k).sha256}`).join("\n")}
"use strict";
const __modules = new Map();
const __mod = (key) => {
  const m = __modules.get(key);
  if (m === undefined) throw new Error("module " + key + " read before it was evaluated");
  return m;
};
`;
for (const key of order) {
  const mod = modules.get(key);
  const heads = mod.imports.map((imp) =>
    imp.ns
      ? `const ${imp.ns} = __mod(${q(imp.target)});`
      : `const { ${imp.names.map(({ from, to }) => (from === to ? from : `${from}: ${to}`)).join(", ")} } = __mod(${q(imp.target)});`
  );
  const tail = mod.exports.map(({ local, exported }) => (local === exported ? local : `${exported}: ${local}`));
  linked += `
// ---- ${key} ${"-".repeat(Math.max(3, 72 - key.length))}
__modules.set(${q(key)}, (() => {
${heads.join("\n")}${heads.length ? "\n" : ""}${mod.body.replace(/\s+$/, "")}
return Object.freeze({ ${tail.join(", ")} });
})());
`;
}
const appPath = join(args.out, ENTRY);
writeFileSync(appPath, linked);
try {
  execFileSync(process.execPath, ["--check", appPath], { stdio: "pipe" });
} catch (e) {
  fail(`the linked ${ENTRY} does not parse:\n${String(e.stderr ?? e.message)}`);
}

// The served tree carries no script but the linked one. The sources it was
// linked from are removed, and a script that was never linked is an error,
// not dead weight: nothing pins it, and a reader would take it for live code.
for (const key of order) if (key !== ENTRY) rmSync(join(args.out, key));
const stray = [];
const walk = (dir, rel) => {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const r = rel ? posix.join(rel, name) : name;
    if (statSync(p).isDirectory()) {
      walk(p, r);
      if (readdirSync(p).length === 0) rmSync(p, { recursive: true });
    } else if (/\.(m?js)$/.test(name) && r !== ENTRY) {
      stray.push(r);
    }
  }
};
walk(args.out, "");
if (stray.length) fail(`scripts in the bundle that ${ENTRY} does not import, so nothing pins them: ${stray.join(", ")}`);

// --- 3. index.html: pin every subresource --------------------------------------

const sri = (file) => "sha384-" + createHash("sha384").update(readFileSync(file)).digest("base64");
const indexPath = join(args.out, "index.html");
let html = readFileSync(indexPath, "utf8");
const tag = /<(link|script)\b([^>]*?)\s(href|src)="([^"]*)"([^>]*)>/g;
let pinned = 0;
html = html.replace(tag, (whole, name, pre, attr, ref, post) => {
  if (/\bintegrity=/.test(pre + post)) {
    fail(`index.html already pins ${ref}; the source must not carry integrity attributes, staging adds them`);
  }
  if (!ref.startsWith("./") || ref.includes("..")) {
    fail(`index.html references ${ref}; only ./relative files inside the bundle can be pinned`);
  }
  const file = join(args.out, ref.slice(2));
  if (!existsSync(file)) fail(`index.html references ${ref}, which is not in the bundle`);
  pinned++;
  return `<${name}${pre} ${attr}="${ref}" integrity="${sri(file)}"${post}>`;
});
writeFileSync(indexPath, html);

// --- 4. Re-scan from disk, the way the canister will ------------------------------

const served = readFileSync(indexPath, "utf8");
const problems = [];
for (const m of served.matchAll(/<(link|script)\b([^>]*)>/g)) {
  const attrs = m[2];
  const ref = /\s(?:href|src)="([^"]*)"/.exec(attrs)?.[1];
  if (ref === undefined) continue; // inline <script> or a <link> without href
  const integrity = /\sintegrity="([^"]*)"/.exec(attrs)?.[1];
  if (!integrity) { problems.push(`${ref}: no integrity`); continue; }
  if (/^[a-z]+:|^\/\//i.test(ref)) { problems.push(`${ref}: external reference`); continue; }
  const want = sri(join(args.out, ref.replace(/^\.\//, "")));
  if (integrity !== want) problems.push(`${ref}: integrity does not match the file`);
}
if (/&/.test(served.match(/<(link|script)\b[^>]*>/g)?.join("") ?? "")) {
  // The canister refuses a `&` inside a tag it must decide on, since it does
  // not decode character references and the browser does.
  problems.push("a <link> or <script> tag contains `&`");
}
if (problems.length) fail("the staged page would be refused by ic-git:\n  " + problems.join("\n  "));

console.log(`staged ${args.out}: pollCanisterId=${args.poll}${args.git ? ` siteCanisterId=${args.git}` : ""}, ${order.length} modules linked into ${ENTRY}, ${pinned} subresources pinned`);
