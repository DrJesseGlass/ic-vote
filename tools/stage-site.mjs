#!/usr/bin/env node
// Render site/ for one deployment: the tree ic-git serves at /site/<repo>/.
//
//   node tools/stage-site.mjs --src site --out dist/site --poll-canister ID [--git-canister ID]
//
// Two things distinguish the served bundle from the source tree, and both
// are done here rather than by hand so that they cannot be done halfway:
//
// 1. config.js names the poll canister. It is `null` in the source on
//    purpose (config.js explains why the trust anchors live in the bundle),
//    and the id only exists once ic-git has created the app canister, so
//    it is injected at staging time.
//
// 2. index.html loads ./style.css and ./app.js. ic-git refuses to serve an
//    entrypoint whose subresources carry no `integrity` (site.rs,
//    unverifiable_subresource): a hash on the page alone attests one blob,
//    and a gateway could swap an unpinned stylesheet or script while every
//    other check passed. So each tag gets a sha384 of the file it names.
//    Module imports inside app.js need no pin; they are issued by code the
//    pin already covers (the same reasoning the canister documents).
//
// After writing, the page is scanned again from the bytes on disk with the
// same rule the canister applies, so a stage that would be refused at serve
// time fails here instead. Zero dependencies.

import { cpSync, readFileSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";

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

// --- 2. index.html: pin every subresource --------------------------------------

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

// --- 3. Re-scan from disk, the way the canister will ------------------------------

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

console.log(`staged ${args.out}: pollCanisterId=${args.poll}${args.git ? ` siteCanisterId=${args.git}` : ""}, ${pinned} subresources pinned`);
