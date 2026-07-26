#!/usr/bin/env node
// Tests for everything in site/lib.
//
// The frontend is hand-written down to sha256 and keccak256, which is only
// defensible if those pieces are pinned by vectors rather than by confidence.
// Everything with a published test vector is checked against it; everything
// else is checked against a live replica, so the agent, the candid decoder and
// the certificate reader are exercised on bytes the IC actually produced
// rather than on bytes this repo also wrote.
//
//   node tools/test-site-lib.mjs                 # offline tests only
//   node tools/test-site-lib.mjs --live <id>     # plus a live local replica
//
// `--live` takes the poll canister id (dfx canister id poll).

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { sha256, sha224, toHex, utf8, fromHex, concat } from "../site/lib/sha256.js";
import { keccak256, selector, sha3_256 } from "../site/lib/keccak.js";
import {
  ANONYMOUS,
  principalToBytes,
  principalToText,
  derEncodeEd25519,
  selfAuthenticating,
} from "../site/lib/principal.js";
import * as cbor from "../site/lib/cbor.js";
import * as candid from "../site/lib/candid.js";
import { Agent, Ed25519Identity, requestId } from "../site/lib/agent.js";
import { certifiedData, parseCertificate, hashTree } from "../site/lib/certificate.js";
import * as eh from "../site/lib/election-hash.js";
import {
  computeVerdict,
  GREEN,
  YELLOW,
  RED,
  OK,
} from "../site/lib/verifier.js";

/// The identity used for the administrative calls the live test needs
/// (creating an election and enrolling the generated voter). Named rather than
/// ambient, for the reason in tools/check.sh: an administrative identity that
/// gets picked up from whatever `dfx identity use` ran last is one nobody
/// chose.
const ADMIN_IDENTITY = process.env.ADMIN_IDENTITY ?? "icvote-admin";

let passed = 0;
let failed = 0;

function check(label, actual, expected) {
  const a = typeof actual === "object" ? JSON.stringify(actual) : String(actual);
  const e = typeof expected === "object" ? JSON.stringify(expected) : String(expected);
  if (a === e) {
    passed++;
    console.log(`  ok    ${label}`);
  } else {
    failed++;
    console.log(`  FAIL  ${label}\n          expected ${e}\n          actual   ${a}`);
  }
}

async function group(name, fn) {
  console.log(`\n${name}`);
  return await fn();
}

// --- hashing --------------------------------------------------------------

group("sha256 / sha224 (NIST vectors)", () => {
  check("sha256('')", toHex(sha256(utf8(""))),
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  check("sha256('abc')", toHex(sha256(utf8("abc"))),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  check("sha256(448-bit msg)", toHex(sha256(utf8("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))),
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
  // Multi-block, exercising the padding branch where length spills a block.
  check("sha256(1,000,000 x 'a')", toHex(sha256(utf8("a".repeat(1000000)))),
    "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
  check("sha224('abc')", toHex(sha224(utf8("abc"))),
    "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
});

group("keccak256", () => {
  check("keccak256('')", toHex(keccak256(utf8(""))),
    "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
  check("keccak256('abc')", toHex(keccak256(utf8("abc"))),
    "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
  // The selector ic-git pins in docs/ATTESTATION.md. If this fails, our
  // keccak is wrong and every registry read would hit the wrong slot.
  check("selector('get(string)')", selector("get(string)"), "693ec85e");

  // The permutation, cross-checked against Node's own SHA3-256 rather than
  // against digests written from memory. SHA3-256 and keccak256 are the same
  // sponge with a different padding byte, so agreeing on every length that
  // crosses a block boundary is agreement about all 24 rounds.
  let sha3Mismatch = null;
  for (const n of [0, 1, 135, 136, 137, 271, 272, 273, 500]) {
    const msg = utf8("a".repeat(n));
    const ours = toHex(sha3_256(msg));
    const theirs = createHash("sha3-256").update(Buffer.from(msg)).digest("hex");
    if (ours !== theirs && !sha3Mismatch) sha3Mismatch = `length ${n}: ${ours} != ${theirs}`;
  }
  check("permutation agrees with Node's sha3-256 across block boundaries", sha3Mismatch, null);
});

group("principals", () => {
  check("management canister", principalToText(new Uint8Array([])), "aaaaa-aa");
  check("anonymous", principalToText(ANONYMOUS), "2vxsx-fae");
  check("round-trip", principalToText(principalToBytes("2vxsx-fae")), "2vxsx-fae");
  const known = "umobs-yiaaa-aaaab-agyrq-cai";
  check("round-trip (canister)", principalToText(principalToBytes(known)), known);
  let threw = false;
  try {
    principalToBytes("2vxsx-faf");
  } catch {
    threw = true;
  }
  check("rejects a bad checksum", threw, true);
});

group("cbor", () => {
  const value = new Map([
    ["request_type", "query"],
    ["arg", new Uint8Array([1, 2, 3])],
    ["ingress_expiry", 1785026947500345000n],
    ["paths", [[utf8("time")]]],
  ]);
  const round = cbor.decode(cbor.encode(value));
  check("text survives", round.get("request_type"), "query");
  check("bytes survive", toHex(round.get("arg")), "010203");
  check("u64 survives", round.get("ingress_expiry"), 1785026947500345000n);
  check("nested arrays survive", toHex(round.get("paths")[0][0]), toHex(utf8("time")));
  let threw = false;
  try {
    cbor.decode(new Uint8Array([0xa1, 0x61, 0x61, 0x01, 0xff]));
  } catch {
    threw = true;
  }
  check("rejects trailing bytes", threw, true);
});

group("candid encoding", () => {
  check("encodeArgs([nat64 0])", toHex(candid.encodeArgs([["nat64", 0n]])),
    "4449444c0001780000000000000000");
  check("encodeArgs([nat64 1, nat32 2])",
    toHex(candid.encodeArgs([["nat64", 1n], ["nat32", 2]])),
    "4449444c000278790100000000000000" + "02000000");
  let threw = false;
  try {
    candid.encodeArgs([["text", "hello"]]);
  } catch {
    threw = true;
  }
  check("refuses unsupported argument types", threw, true);
  check("fieldHash('id') is stable", candid.fieldHash("id"), 23515);
});

group("request id (representation-independent hash)", () => {
  // Field order must not change the id; that is the property the whole
  // signing scheme rests on.
  const a = requestId({ request_type: "call", method_name: "cast", sender: ANONYMOUS });
  const b = requestId({ sender: ANONYMOUS, method_name: "cast", request_type: "call" });
  check("order-independent", toHex(a), toHex(b));
  const c = requestId({ request_type: "call", method_name: "casT", sender: ANONYMOUS });
  check("content-sensitive", toHex(a) !== toHex(c), true);
});

group("election hashing", () => {
  // Chain order-sensitivity and manifest binding, matching the Rust tests.
  const m = "a".repeat(64);
  const g = eh.logGenesis(m);
  const v1 = "2vxsx-fae";
  const v2 = principalToText(new Uint8Array([7]));
  const ab = eh.logAppend(eh.logAppend(g, 0, v1, 0, 1), 1, v2, 1, 2);
  const ba = eh.logAppend(eh.logAppend(g, 0, v2, 1, 2), 1, v1, 0, 1);
  check("chain is order-sensitive", ab !== ba, true);
  check("chain is bound to its manifest",
    eh.logAppend(eh.logGenesis("b".repeat(64)), 0, v1, 0, 1) !== eh.logAppend(g, 0, v1, 0, 1), true);
  // Witness recomputation over every shape, as in hashing.rs.
  const leaves = Array.from({ length: 9 }, (_, i) => toHex(sha256(utf8(`leaf${i}`))));
  const root = buildRoot(leaves);
  for (let i = 0; i < leaves.length; i++) {
    check(`witness[${i}] recomputes the root`, eh.merkleRecompute(leaves[i], witness(leaves, i)), root);
  }
});

function buildRoot(leaves) {
  if (leaves.length === 0) return eh.merkleEmpty();
  let level = [...leaves];
  while (level.length > 1) {
    const next = [];
    let i = 0;
    for (; i + 1 < level.length; i += 2) next.push(eh.merkleNode(level[i], level[i + 1]));
    if (i < level.length) next.push(level[i]);
    level = next;
  }
  return level[0];
}

function witness(leaves, index) {
  const steps = [];
  let level = [...leaves];
  let idx = index;
  while (level.length > 1) {
    const next = [];
    let i = 0;
    for (; i + 1 < level.length; i += 2) next.push(eh.merkleNode(level[i], level[i + 1]));
    const promoted = i < level.length;
    if (promoted) next.push(level[i]);
    if (!(promoted && idx === level.length - 1)) {
      steps.push(
        idx % 2 === 0
          ? { sibling: level[idx + 1], sibling_is_right: true }
          : { sibling: level[idx - 1], sibling_is_right: false }
      );
    }
    idx = Math.floor(idx / 2);
    level = next;
  }
  return steps;
}

// --- the verdict ----------------------------------------------------------

group("verdict rules", () => {
  const pin = {
    repo: "ic-vote",
    commit: "a".repeat(40),
    bundle_sha256: "b".repeat(64),
    site_canister: "umobs-yiaaa-aaaab-agyrq-cai",
    module_sha256: "c".repeat(64),
    registry_chain_id: 11155111,
    registry_address: "0x0000000000000000000000000000000000000001",
  };
  const healthy = {
    pin,
    served: { sha256: "b".repeat(64), commitHeader: "a".repeat(40) },
    registryRecord: { commit: "a".repeat(40), bundleHash: "b".repeat(64), updatedAt: 1n },
    liveModuleHash: { hash: "c".repeat(64), signature: { status: OK } },
    attestations: [
      { verifier: "0xA", moduleHash: "c".repeat(64), commit: "d".repeat(40), recipeHash: "e".repeat(64) },
      { verifier: "0xB", moduleHash: "c".repeat(64), commit: "d".repeat(40), recipeHash: "e".repeat(64) },
    ],
    trusted: { verifiers: ["0xa", "0xb"], K: 2 },
  };

  check("fully verified is GREEN", computeVerdict(healthy).verdict, GREEN);
  check("GREEN allows the ballot", computeVerdict(healthy).ballot, "allowed");

  check("served bytes differ -> RED",
    computeVerdict({ ...healthy, served: { sha256: "f".repeat(64) } }).verdict, RED);
  check("RED blocks the ballot",
    computeVerdict({ ...healthy, served: { sha256: "f".repeat(64) } }).ballot, "blocked");

  check("registry disagrees with the pin -> RED",
    computeVerdict({
      ...healthy,
      registryRecord: { commit: "9".repeat(40), bundleHash: "b".repeat(64), updatedAt: 1n },
    }).verdict, RED);

  check("live module hash != pinned -> RED",
    computeVerdict({
      ...healthy,
      liveModuleHash: { hash: "9".repeat(64), signature: { status: OK } },
      attestations: [
        { verifier: "0xA", moduleHash: "9".repeat(64), commit: "d".repeat(40), recipeHash: "e".repeat(64) },
        { verifier: "0xB", moduleHash: "9".repeat(64), commit: "d".repeat(40), recipeHash: "e".repeat(64) },
      ],
    }).verdict, RED);

  check("no trusted attestation for the running wasm -> RED",
    computeVerdict({ ...healthy, attestations: [] }).verdict, RED);

  check("below threshold -> YELLOW",
    computeVerdict({ ...healthy, attestations: [healthy.attestations[0]] }).verdict, YELLOW);

  check("YELLOW requires acknowledgement",
    computeVerdict({ ...healthy, attestations: [healthy.attestations[0]] }).ballot,
    "requires-acknowledgement");

  check("duplicate verifier cannot make a threshold",
    computeVerdict({
      ...healthy,
      attestations: [healthy.attestations[0], { ...healthy.attestations[0] }],
    }).verdict, YELLOW);

  check("same wasm, disagreeing recipe -> RED",
    computeVerdict({
      ...healthy,
      attestations: [
        healthy.attestations[0],
        { ...healthy.attestations[1], recipeHash: "0".repeat(64) },
      ],
    }).verdict, RED);

  // The load-bearing one: an unauthenticated certificate must never be
  // allowed to produce GREEN, no matter how healthy everything else is.
  check("unverified certificate cannot reach GREEN",
    computeVerdict({
      ...healthy,
      liveModuleHash: { hash: "c".repeat(64), signature: { status: "UNAVAILABLE", reason: "no BLS" } },
    }).verdict, YELLOW);

  // Change detection may only lower. A malicious upgrade is RED from the
  // checks; the clamp must not lift it to YELLOW.
  const upgraded = computeVerdict({
    ...healthy,
    liveModuleHash: { hash: "9".repeat(64), signature: { status: OK } },
    attestations: [],
    lastSeenModuleHash: "c".repeat(64),
  });
  check("change detection does not raise RED to YELLOW", upgraded.verdict, RED);
  check("change detection is reported", upgraded.warnings.length > 0, true);

  const benignChange = computeVerdict({ ...healthy, lastSeenModuleHash: "1".repeat(64) });
  check("a benign change clamps GREEN to YELLOW", benignChange.verdict, YELLOW);

  check("an election with no pin -> RED", computeVerdict({ ...healthy, pin: null }).verdict, RED);
  check("K = 0 is a configuration error, not a pass",
    computeVerdict({ ...healthy, trusted: { verifiers: [], K: 0 } }).verdict, RED);
});

// --- the module graph -----------------------------------------------------
//
// app.js is the one file here with no unit tests: it is all DOM wiring, and a
// DOM shim faithful enough to test it would be a bigger thing to trust than
// the file itself. What CAN be checked without a browser is that it parses and
// that every symbol it imports actually exists -- which is where a rename or a
// typo would otherwise sit undetected until a voter loaded the page.

await group("site module graph", async () => {
  const siteDir = new URL("../site/", import.meta.url);
  const files = [];
  for (const entry of readdirSync(siteDir, { recursive: true })) {
    if (String(entry).endsWith(".js")) files.push(String(entry));
  }
  check("every site .js file is discoverable", files.length > 0, true);

  for (const file of files.sort()) {
    const path = fileURLToPath(new URL(file, siteDir));
    let syntaxError = null;
    try {
      execFileSync(process.execPath, ["--check", path], { stdio: "pipe" });
    } catch (e) {
      syntaxError = String(e.stderr ?? e.message).split("\n")[1] ?? "syntax error";
    }
    check(`${file} parses`, syntaxError, null);
  }

  // Resolve every named import against the module it names.
  let unresolved = [];
  for (const file of files.sort()) {
    const source = readFileSync(fileURLToPath(new URL(file, siteDir)), "utf8");
    const importRe = /import\s+(?:\*\s+as\s+\w+|\{([^}]*)\})\s+from\s+["']([^"']+)["']/g;
    for (const [, names, spec] of source.matchAll(importRe)) {
      if (!spec.startsWith(".")) continue;
      const target = new URL(spec, new URL(file, siteDir));
      const mod = await import(target.href);
      for (const raw of (names ?? "").split(",").map((s) => s.trim()).filter(Boolean)) {
        const name = raw.split(/\s+as\s+/)[0].trim();
        if (!(name in mod)) unresolved.push(`${file} imports '${name}' from ${spec}, which does not export it`);
      }
    }
  }
  check("every named import resolves", unresolved, []);
});

// --- live replica ---------------------------------------------------------

const liveIdx = process.argv.indexOf("--live");
if (liveIdx >= 0) {
  const canisterId = process.argv[liveIdx + 1];
  const hostIdx = process.argv.indexOf("--host");
  const host = hostIdx >= 0 ? process.argv[hostIdx + 1] : "http://127.0.0.1:4943";
  await live(canisterId, host);
} else {
  console.log("\n(skipping live-replica tests; pass --live <poll-canister-id> to run them)");
}

async function live(canisterId, host) {
  console.log(`\nlive replica ${host} canister ${canisterId}`);
  const agent = new Agent({ host, canisterId });

  const elections = await agent.query("list_elections");
  check("list_elections returns at least one election", elections.length > 0, true);

  const id = elections[0].id;
  const manifest = unwrap(await agent.query("get_manifest", [["nat64", id]]));
  const head = unwrap(await agent.query("certified_head", [["nat64", id]]));
  const roll = unwrap(await agent.query("get_roll", [["nat64", id], ["nat64", 0n], ["nat64", 10000n]]));
  const log = unwrap(await agent.query("get_log", [["nat64", id], ["nat64", 0n], ["nat64", 1000n]]));
  const tally = unwrap(await agent.query("get_tally", [["nat64", id]]));

  // The decoder is only trustworthy if the values it produces are the ones
  // the canister meant; recomputing the hashes from them is that check.
  const board = eh.recomputeBoard({
    manifest: { ...manifest, id: manifest.id },
    roll,
    log: log.map((b) => ({ ...b, seq: b.seq, choice: b.choice, at: b.at })),
  });
  check("no structural problems in the board", board.problems, []);
  check("recomputed manifest hash matches", board.manifestHash, manifest.manifest_hash);
  check("recomputed log head matches", board.logHead, head.log_head);
  check("recomputed tally matches the canister's", board.counts.map(Number), tally.counts.map(Number));
  check("recomputed tally hash matches", board.tallyHash, tally.tally_hash);

  // Certificate: structural verification end to end.
  const cert = parseCertificate(head.certificate);
  const leaf = eh.merkleLeaf(id, manifest.manifest_hash, head.log_head, head.ballot_count);
  const root = eh.merkleRecompute(leaf, head.witness);
  const certified = certifiedData(cert, principalToBytes(canisterId));
  check("certified_data matches the recomputed Merkle root", toHex(certified), root);
  check("hash tree reconstructs", hashTree(cert.tree).length, 32);

  // An update call, signed by a generated Ed25519 identity. Enrolling it needs
  // an administrative call, which the JS encoder deliberately cannot make, so
  // dfx does that part -- which is also a fair reproduction of how a real
  // organization would enrol a member.
  const identity = await Ed25519Identity.generate();
  const voter = identity.principalText;
  check("self-authenticating principal has the right suffix",
    principalToBytes(voter).slice(-1)[0], 2);

  const newId = dfx(["canister", "call", "--network", "local", "--identity", ADMIN_IDENTITY,
    canisterId, "create_election",
    '(record { title = "agent test"; question = "does the hand-written agent work?"; options = vec { "yes"; "no" } })'])
    .match(/([0-9_]+) : nat64/)[1].replace(/_/g, "");
  dfx(["canister", "call", "--network", "local", "--identity", ADMIN_IDENTITY, canisterId,
    "set_roll", `(${newId}:nat64, vec { principal "${voter}" })`]);
  dfx(["canister", "call", "--network", "local", "--identity", ADMIN_IDENTITY, canisterId,
    "pin_release", `(${newId}:nat64, record {
      repo = "ic-vote"; commit = "${"0".repeat(40)}"; bundle_sha256 = "${"0".repeat(64)}";
      site_canister = "umobs-yiaaa-aaaab-agyrq-cai"; module_sha256 = "${"0".repeat(64)}";
      registry_chain_id = 11155111:nat64;
      registry_address = "0xa1362DAda583c56a395D305a8C7A458E0B62A209" })`]);
  dfx(["canister", "call", "--network", "local", "--identity", ADMIN_IDENTITY, canisterId,
    "open_election", `(${newId}:nat64)`]);

  const signing = new Agent({ host, canisterId, identity });
  const { value } = await signing.call("cast", [["nat64", BigInt(newId)], ["nat32", 1]]);
  const receipt = unwrap(value);
  check("the signed update call was accepted", receipt.voter, voter);
  check("the receipt's choice is the one we sent", receipt.choice, 1);

  const after = unwrap(await agent.query("certified_head", [["nat64", BigInt(newId)]]));
  const m2 = unwrap(await agent.query("get_manifest", [["nat64", BigInt(newId)]]));
  check("the receipt hash is the new log head",
    receipt.entry_hash,
    eh.logAppend(eh.logGenesis(m2.manifest_hash), 0n, voter, 1, receipt.at));
  check("and the canister agrees", after.log_head, receipt.entry_hash);

  // Casting twice must be refused by the canister, not by the UI.
  let rejected = false;
  try {
    const second = await signing.call("cast", [["nat64", BigInt(newId)], ["nat32", 0]]);
    rejected = "Err" in second.value && "AlreadyVoted" in second.value.Err;
  } catch {
    rejected = true;
  }
  check("a second ballot from the same identity is refused", rejected, true);
}

function unwrap(result) {
  if (result && typeof result === "object" && "Ok" in result) return result.Ok;
  throw new Error(`canister returned an error: ${JSON.stringify(result, bigintSafe)}`);
}

const bigintSafe = (_k, v) => (typeof v === "bigint" ? String(v) : v);

function dfx(args) {
  return execFileSync("dfx", args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
