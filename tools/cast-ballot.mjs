#!/usr/bin/env node
// Cast one ballot from the command line, the same way the page does it.
//
// dfx cannot do this: dfx identities are secp256k1 and sign only the ingress
// envelope, but a ballot is credentialed by an in-ballot Ed25519 signature
// and submitted from a single-use transport key (THREAT_MODEL.md 2.7). So
// this tool drives the SAME hand-written libraries the page ships
// (site/lib/agent.js, site/lib/election-hash.js), which makes every scripted
// cast in tools/demo-election.sh a live test of the voter's real code path.
//
// Usage:
//   node tools/cast-ballot.mjs keygen --key <file>
//       Generate an Ed25519 voting credential, store it (pkcs8 hex), print
//       the principal to enrol. Refuses to overwrite an existing file.
//   node tools/cast-ballot.mjs principal --key <file>
//       Print the principal of an existing credential.
//   node tools/cast-ballot.mjs cast --key <file> --canister <id>
//       --election <id> --choice <n> [--host <url>] [--sign-choice <n>]
//       Fetch the manifest, recompute its hash, sign, submit from a fresh
//       transport key. --sign-choice signs a DIFFERENT choice than the one
//       submitted; it exists so the demo can prove the canister rejects a
//       mismatched signature, and has no honest use.

import { webcrypto } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
if (!globalThis.crypto) globalThis.crypto = webcrypto;

const { Agent, Ed25519Identity } = await import("../site/lib/agent.js");
const { toHex, fromHex } = await import("../site/lib/sha256.js");
const eh = await import("../site/lib/election-hash.js");

function opt(name, def) {
  const i = process.argv.indexOf(`--${name}`);
  if (i < 0) return def;
  const v = process.argv[i + 1];
  // A flag at the end of the line, or followed by another flag, has no value.
  // Falling through to `undefined` here used to bypass defaults and coerce to
  // NaN downstream, which setUint32 renders as choice 0 -- a silently
  // miscast ballot.
  if (v === undefined || v.startsWith("--")) {
    console.error(`--${name} is missing its value`);
    process.exit(2);
  }
  return v;
}

function req(name) {
  const v = opt(name);
  if (v === undefined) {
    console.error(`missing --${name}`);
    process.exit(2);
  }
  return v;
}

/// Parse a ballot choice strictly. Number() would turn "abc" into NaN, and
/// every DataView.setUint32 downstream renders NaN as 0 -- so a typo would
/// sign and irrevocably cast a valid ballot for option 0. Digits only, and
/// within nat32, or the tool refuses to sign anything.
function u32Arg(name, raw) {
  if (!/^\d+$/.test(raw) || Number(raw) > 0xffffffff) {
    console.error(`--${name} must be a decimal option index (0..4294967295), got '${raw}'`);
    process.exit(2);
  }
  return Number(raw);
}

async function loadKey(path) {
  return await Ed25519Identity.fromPkcs8(fromHex(readFileSync(path, "utf8").trim()));
}

const mode = process.argv[2];

if (mode === "keygen") {
  const path = req("key");
  if (existsSync(path)) {
    // Overwriting a credential disenfranchises whoever held it; make that an
    // explicit `rm`, never a side effect of a rerun.
    console.error(`refusing to overwrite existing key file ${path}`);
    process.exit(1);
  }
  const identity = await Ed25519Identity.generate();
  writeFileSync(path, toHex(await identity.exportPkcs8()) + "\n", { mode: 0o600 });
  console.log(identity.principalText);
} else if (mode === "principal") {
  console.log((await loadKey(req("key"))).principalText);
} else if (mode === "cast") {
  const identity = await loadKey(req("key"));
  const canisterId = req("canister");
  const electionRaw = req("election");
  if (!/^\d+$/.test(electionRaw)) {
    console.error(`--election must be a decimal election id, got '${electionRaw}'`);
    process.exit(2);
  }
  const electionId = BigInt(electionRaw);
  const choice = u32Arg("choice", req("choice"));
  const signChoiceRaw = opt("sign-choice");
  const signChoice = signChoiceRaw === undefined ? choice : u32Arg("sign-choice", signChoiceRaw);
  const host = opt("host", "http://127.0.0.1:4943");

  const reader = new Agent({ host, canisterId });
  const manifest = unwrap(await reader.query("get_manifest", [["nat64", electionId]]));
  // Sign over the RECOMPUTED manifest hash, exactly as the page does: the
  // signature endorses the election as this client derived it, not as the
  // canister described it.
  const mh = eh.manifestHash(manifest);
  if (mh !== manifest.manifest_hash) {
    console.error(`manifest hash mismatch: recomputed ${mh}, canister says ${manifest.manifest_hash}`);
    process.exit(1);
  }
  // Five minutes, matching the browser client: the signature must die about
  // as fast as the ingress envelope it replaced would have.
  const sigExpiresAt = BigInt(Date.now()) * 1_000_000n + 5n * 60n * 1_000_000_000n;
  const sig = await identity.signMessage(eh.ballotSigMessage(canisterId, mh, signChoice, sigExpiresAt));

  // Fresh transport key, used for this one message and dropped.
  const transport = await Ed25519Identity.generate();
  const submitting = new Agent({ host, canisterId, identity: transport });
  const { value } = await submitting.call("cast", [
    ["nat64", electionId],
    ["nat32", choice],
    ["blob", identity.der],
    ["blob", sig],
    ["nat64", sigExpiresAt],
  ]);
  const receipt = unwrap(value);
  console.log(`voter      ${receipt.voter}`);
  console.log(`transport  ${transport.principalText} (single-use, now discarded)`);
  console.log(`choice     ${receipt.choice}`);
  console.log(`sequence   ${receipt.seq}`);
  console.log(`entry hash ${receipt.entry_hash}`);
} else {
  console.error("usage: cast-ballot.mjs keygen|principal|cast [options]  (see file header)");
  process.exit(2);
}

function unwrap(result) {
  if (result && typeof result === "object" && "Ok" in result) return result.Ok;
  const err = JSON.stringify(result?.Err ?? result, (_k, v) => (typeof v === "bigint" ? String(v) : v));
  console.error(`canister refused: ${err}`);
  process.exit(1);
}
