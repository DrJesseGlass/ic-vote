#!/usr/bin/env node
// Independent verifier for an ic-vote V0 election.
//
// This is a SECOND implementation of canisters/poll/src/hashing.rs, written
// against the spec in that file rather than by translating it. That is the
// whole point: a verifier that shares code with the thing it verifies checks
// nothing. If this tool and the canister ever disagree, the bulletin board is
// not verifiable and the election is void.
//
// What it checks, in order, refusing to continue past a structural failure:
//
//   A. roll_hash  -- the published roll hashes to what the manifest commits to
//   B. manifest   -- manifest_hash is what its own published fields produce
//   C. chain      -- every log entry_hash chains from genesis; head matches
//   D. franchise  -- every ballot's key derives a roll member, once, in
//                    range, with a valid signature over (canister, manifest,
//                    choice)
//   E. tally      -- counts recomputed from the log, and tally_hash over them
//   F. inclusion  -- the election's Merkle leaf + witness reproduce a root
//   G. certified  -- that root is the certified_data inside the IC certificate
//
// Check G is where this stops short, and it stops short honestly. Extracting
// certified_data from the certificate needs only CBOR and sha256, both of
// which are here. VERIFYING the certificate's BLS signature against the NNS
// root key does not, and that reader is ic-git ROADMAP dependency 1 -- unbuilt.
// So G reports MATCHED-BUT-UNSIGNED and the overall verdict is capped below
// full verification. It is never reported as passing. See the doctrine in
// ic-git docs/ATTESTATION.md: a check may add warnings, never falsely upgrade.
//
// Zero dependencies (node >= 18).
//
// Usage:
//   node tools/verify-election.mjs --file bulletin.json
//   node tools/verify-election.mjs --fetch <election-id> [--canister <id>]
//     [--network local|ic] [--identity <dfx-identity>]
//
// --fetch shells out to `dfx` purely as a transport. dfx is not trusted:
// everything it returns is re-derived here.

import { createHash, createPublicKey, verify as ed25519Verify } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";

// --------------------------------------------------------------------------
// hashing -- mirrors canisters/poll/src/hashing.rs
// --------------------------------------------------------------------------

const D_MANIFEST = "ic-vote/v0/manifest";
const D_ROLL = "ic-vote/v0/roll";
const D_GENESIS = "ic-vote/v0/log-genesis";
// "-signed": see the note on D_ENTRY in canisters/poll/src/hashing.rs.
const D_ENTRY = "ic-vote/v0/log-entry-signed";
const D_BALLOT_SIG = "ic-vote/v0/ballot-sig";
const D_TALLY = "ic-vote/v0/tally";
const D_LEAF = "ic-vote/v0/merkle-leaf";
const D_NODE = "ic-vote/v0/merkle-node";
const D_EMPTY = "ic-vote/v0/merkle-empty";

const u32be = (n) => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0);
  return b;
};

const u64be = (n) => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return b;
};

// The Rust side enforces length prefixing through its writer type. Here the
// discipline is manual, so every variable-length field goes through `lp` and
// nothing else appends bytes directly.
class W {
  constructor(domain) {
    this.parts = [];
    this.lp(Buffer.from(domain, "utf8"));
  }
  lp(buf) {
    this.parts.push(u32be(buf.length), buf);
    return this;
  }
  u32(n) {
    this.parts.push(u32be(n));
    return this;
  }
  u64(n) {
    this.parts.push(u64be(n));
    return this;
  }
  h(hex) {
    const b = Buffer.from(hex, "hex");
    if (b.length !== 32) throw new Error(`expected 32-byte hash, got ${hex}`);
    this.parts.push(b);
    return this;
  }
  text(s) {
    return this.lp(Buffer.from(s, "utf8"));
  }
  out() {
    return createHash("sha256").update(Buffer.concat(this.parts)).digest("hex");
  }
}

const rollHash = (principalBlobs) => {
  const w = new W(D_ROLL).u32(principalBlobs.length);
  for (const p of principalBlobs) w.lp(p);
  return w.out();
};

const manifestHash = (m) => {
  const w = new W(D_MANIFEST)
    .u64(m.id)
    .text(m.title)
    .text(m.question)
    .u32(m.options.length);
  for (const o of m.options) w.text(o);
  return w
    .lp(principalToBytes(m.admin))
    .u64(m.opened_at)
    .h(m.roll_hash)
    .text(m.pin.repo)
    .text(m.pin.commit)
    .text(m.pin.bundle_sha256)
    .text(m.pin.site_canister)
    .text(m.pin.module_sha256)
    .text(m.pin.poll_module_sha256)
    .u64(m.pin.registry_chain_id)
    .text(m.pin.registry_address)
    .out();
};

const logGenesis = (manifest) => new W(D_GENESIS).h(manifest).out();

const logAppend = (prev, seq, pubkeyDer, choice, at, sigExpiresAt, sig) =>
  new W(D_ENTRY).h(prev).u64(seq).lp(pubkeyDer).u32(choice).u64(at).u64(sigExpiresAt).lp(sig).out();

// --------------------------------------------------------------------------
// the ballot credential -- mirrors canisters/poll/src/credential.rs
// --------------------------------------------------------------------------

/// The one DER spelling of an Ed25519 SPKI key the canister accepts.
const DER_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/// Self-authenticating principal: sha224(DER) || 0x02, the IC's own rule.
const principalOfKey = (pubkeyDer) =>
  Buffer.concat([createHash("sha224").update(pubkeyDer).digest(), Buffer.from([0x02])]);

/// The exact bytes the roll key signed: length-prefixed domain, length-
/// prefixed poll canister principal, manifest hash, u32be choice, u64be
/// expiry. The expiry is the replay bound; it is republished per ballot so
/// this reconstruction is possible.
function ballotSigMessage(canisterBytes, manifestHex, choice, sigExpiresAt) {
  const domain = Buffer.from(D_BALLOT_SIG, "utf8");
  return Buffer.concat([
    u32be(domain.length), domain,
    u32be(canisterBytes.length), canisterBytes,
    Buffer.from(manifestHex, "hex"),
    u32be(choice),
    u64be(sigExpiresAt),
  ]);
}

/// Strict lowercase-hex decode, agreeing byte-for-byte with the browser's
/// fromHexBytes (site/lib/election-hash.js). Node's Buffer.from(s, "hex")
/// accepts uppercase and silently truncates at the first bad character, so
/// using it here let this tool pass bulletins every voter's browser flags as
/// forged -- the two independent implementations must reject the same inputs.
/// Returns null on anything non-conforming; callers turn that into a FAIL.
function strictHex(s) {
  if (typeof s !== "string" || s.length % 2 !== 0 || /[^0-9a-f]/.test(s)) return null;
  return Buffer.from(s, "hex");
}

/// Node's Ed25519 accepts the SPKI DER directly. Its check is laxer than the
/// canister's verify_strict, so everything the canister accepted verifies
/// here; the reverse direction never matters because this tool only reads
/// logs the canister built.
function sigVerifies(pubkeyDer, message, sig) {
  try {
    const key = createPublicKey({ key: pubkeyDer, format: "der", type: "spki" });
    return ed25519Verify(null, message, key, sig);
  } catch {
    return false;
  }
}

const tallyHash = (manifest, head, counts) => {
  const w = new W(D_TALLY).h(manifest).h(head).u32(counts.length);
  for (const c of counts) w.u64(c);
  return w.out();
};

const merkleLeaf = (id, manifest, head, ballotCount) =>
  new W(D_LEAF).u64(id).h(manifest).h(head).u64(ballotCount).out();

const merkleNode = (l, r) => new W(D_NODE).h(l).h(r).out();

const merkleRecompute = (leaf, steps) => {
  let acc = leaf;
  for (const s of steps) {
    acc = s.sibling_is_right
      ? merkleNode(acc, s.sibling)
      : merkleNode(s.sibling, acc);
  }
  return acc;
};

// --------------------------------------------------------------------------
// principals -- base32(crc32 || blob) with dashes, per the IC textual form
// --------------------------------------------------------------------------

const B32 = "abcdefghijklmnopqrstuvwxyz234567";

function principalToBytes(text) {
  const clean = String(text).toLowerCase().replace(/-/g, "");
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of clean) {
    const idx = B32.indexOf(ch);
    if (idx < 0) throw new Error(`invalid principal character '${ch}' in ${text}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >> bits) & 0xff);
    }
  }
  const buf = Buffer.from(out);
  if (buf.length < 4) throw new Error(`principal too short: ${text}`);
  const crc = buf.subarray(0, 4);
  const body = buf.subarray(4);
  // The checksum is not decoration: a principal whose blob is silently
  // mistranscoded produces a valid-looking roll hash over the wrong members.
  if (!crc32(body).equals(crc)) throw new Error(`principal checksum failed: ${text}`);
  return body;
}

let CRC_TABLE = null;
function crc32(buf) {
  if (!CRC_TABLE) {
    CRC_TABLE = new Int32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      CRC_TABLE[n] = c;
    }
  }
  let c = 0 ^ -1;
  for (const b of buf) c = (c >>> 8) ^ CRC_TABLE[(c ^ b) & 0xff];
  const out = Buffer.alloc(4);
  out.writeUInt32BE((c ^ -1) >>> 0);
  return out;
}

// --------------------------------------------------------------------------
// CBOR (decode subset) and the IC HashTree
// --------------------------------------------------------------------------

function cborDecode(buf) {
  let i = 0;
  const need = (n) => {
    if (i + n > buf.length) throw new Error("truncated CBOR");
  };
  function argument(ai) {
    if (ai < 24) return BigInt(ai);
    if (ai === 24) { need(1); return BigInt(buf[i++]); }
    if (ai === 25) { need(2); const v = BigInt(buf.readUInt16BE(i)); i += 2; return v; }
    if (ai === 26) { need(4); const v = BigInt(buf.readUInt32BE(i)); i += 4; return v; }
    if (ai === 27) { need(8); const v = buf.readBigUInt64BE(i); i += 8; return v; }
    throw new Error(`unsupported CBOR additional info ${ai}`);
  }
  function value() {
    need(1);
    const b = buf[i++];
    const major = b >> 5;
    const ai = b & 0x1f;
    switch (major) {
      case 0: return argument(ai);
      case 1: return -1n - argument(ai);
      case 2: {
        const n = Number(argument(ai));
        need(n);
        const v = buf.subarray(i, i + n);
        i += n;
        return v;
      }
      case 3: {
        const n = Number(argument(ai));
        need(n);
        const v = buf.subarray(i, i + n).toString("utf8");
        i += n;
        return v;
      }
      case 4: {
        const n = Number(argument(ai));
        const arr = [];
        for (let k = 0; k < n; k++) arr.push(value());
        return arr;
      }
      case 5: {
        const n = Number(argument(ai));
        const m = new Map();
        for (let k = 0; k < n; k++) {
          const key = value();
          m.set(typeof key === "string" ? key : String(key), value());
        }
        return m;
      }
      case 6: {
        argument(ai); // self-describe tag 55799 and friends: ignore, decode payload
        return value();
      }
      default:
        throw new Error(`unsupported CBOR major type ${major}`);
    }
  }
  const v = value();
  return v;
}

const domainSep = (s) => Buffer.concat([Buffer.from([s.length]), Buffer.from(s, "utf8")]);
const sha = (...parts) => createHash("sha256").update(Buffer.concat(parts)).digest();

// Node tags per the IC interface spec: 0 empty, 1 fork, 2 labeled, 3 leaf,
// 4 pruned.
function hashTree(node) {
  if (!Array.isArray(node)) throw new Error("malformed hash tree node");
  switch (Number(node[0])) {
    case 0: return sha(domainSep("ic-hashtree-empty"));
    case 1: return sha(domainSep("ic-hashtree-fork"), hashTree(node[1]), hashTree(node[2]));
    case 2: return sha(domainSep("ic-hashtree-labeled"), Buffer.from(node[1]), hashTree(node[2]));
    case 3: return sha(domainSep("ic-hashtree-leaf"), Buffer.from(node[1]));
    case 4: return Buffer.from(node[1]);
    default: throw new Error(`unknown hash tree tag ${node[0]}`);
  }
}

/// Walk `path` (array of Buffers/strings) through the tree, returning the leaf
/// value or null. A pruned subtree along the path yields null rather than a
/// value -- "absent from my copy", not "absent from the state".
function lookupPath(node, path) {
  if (path.length === 0) {
    return Number(node[0]) === 3 ? Buffer.from(node[1]) : null;
  }
  const [head, ...rest] = path;
  const want = Buffer.isBuffer(head) ? head : Buffer.from(head, "utf8");
  const found = findLabel(node, want);
  return found ? lookupPath(found, rest) : null;
}

function findLabel(node, label) {
  const tag = Number(node[0]);
  if (tag === 2) {
    return Buffer.from(node[1]).equals(label) ? node[2] : null;
  }
  if (tag === 1) {
    return findLabel(node[1], label) || findLabel(node[2], label);
  }
  return null;
}

// --------------------------------------------------------------------------
// input handling
// --------------------------------------------------------------------------

/// u64 fields (timestamps in nanoseconds) exceed 2^53, so a JSON parser that
/// produced a plain number has already rounded them. A rounded timestamp
/// hashes to garbage and would surface as a bogus chain failure, so reject the
/// input rather than report a failure that is really a parsing bug.
function u64(v, what) {
  if (typeof v === "bigint") return v;
  if (typeof v === "string") return BigInt(v.replace(/_/g, ""));
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) {
      throw new Error(
        `${what} arrived as an unsafe JSON number (${v}); it must be a string to survive parsing`
      );
    }
    return BigInt(v);
  }
  throw new Error(`${what} has unexpected type ${typeof v}`);
}

/// Candid `opt blob` reaches JSON in several shapes depending on who wrote it:
/// dfx renders it as `[[..bytes..]]` (an array holding the option's one
/// value, which is itself an array of byte values), a hand-built bulletin may
/// use a flat byte array or a hex string, and an absent option is `[]`.
/// Accept all of them; return null only for genuinely absent.
function optBlob(v) {
  if (v == null) return null;
  if (typeof v === "string") return Buffer.from(v, "hex");
  if (!Array.isArray(v)) return null;
  if (v.length === 0) return null;
  if (Array.isArray(v[0])) return Buffer.from(v[0]);
  if (v.every((n) => typeof n === "number")) return Buffer.from(v);
  return null;
}

function loadFile(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

/// dfx is a transport here, not a trusted party -- but which identity it signs
/// with still matters operationally. Left to the ambient selection, these reads
/// block on a keychain prompt when the operator's identity is encrypted, or
/// fail outright if it has been removed. Callers pass `--identity`; omitting it
/// keeps the ambient behaviour for interactive use.
function dfxCall(opts, canister, method, arg) {
  const args = ["canister", "call", "--network", opts.network, "--output", "json"];
  if (opts.identity) args.push("--identity", opts.identity);
  args.push(canister, method, arg);
  const out = execFileSync("dfx", args, {
    encoding: "utf8",
    maxBuffer: 256 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
  return JSON.parse(out);
}

function unwrap(res, what) {
  if (res && typeof res === "object" && "Ok" in res) return res.Ok;
  throw new Error(`${what} failed: ${JSON.stringify(res)}`);
}

function fetchBulletin(opts, canister, id) {
  const election = unwrap(dfxCall(opts, canister, "get_election", `(${id}:nat64)`), "get_election");
  const manifest = unwrap(dfxCall(opts, canister, "get_manifest", `(${id}:nat64)`), "get_manifest");
  const head = unwrap(dfxCall(opts, canister, "certified_head", `(${id}:nat64)`), "certified_head");

  const roll = [];
  for (let off = 0; ; off += 10000) {
    const page = unwrap(
      dfxCall(opts, canister, "get_roll", `(${id}:nat64, ${off}:nat64, 10000:nat64)`),
      "get_roll"
    );
    roll.push(...page);
    if (page.length < 10000) break;
  }

  const log = [];
  for (let off = 0; ; off += 1000) {
    const page = unwrap(
      dfxCall(opts, canister, "get_log", `(${id}:nat64, ${off}:nat64, 1000:nat64)`),
      "get_log"
    );
    log.push(...page);
    if (page.length < 1000) break;
  }

  return { canister, election, manifest, roll, log, certified_head: head };
}

// --------------------------------------------------------------------------
// the checks
// --------------------------------------------------------------------------

let failures = 0;
let warnings = 0;
const pass = (label, detail) => console.log(`PASS  ${label}${detail ? `  -- ${detail}` : ""}`);
const fail = (label, detail) => {
  failures++;
  console.log(`FAIL  ${label}${detail ? `  -- ${detail}` : ""}`);
};
const warn = (label, detail) => {
  warnings++;
  console.log(`WARN  ${label}${detail ? `  -- ${detail}` : ""}`);
};

function verify(b) {
  const m = b.manifest;
  const id = u64(m.id, "manifest.id");

  // A -- the published roll is the roll the manifest commits to.
  const rollBytes = b.roll.map(principalToBytes);
  const sorted = [...rollBytes].map((x) => x.toString("hex")).sort();
  const asGiven = rollBytes.map((x) => x.toString("hex"));
  if (JSON.stringify(sorted) !== JSON.stringify(asGiven)) {
    // Sorting here would paper over the canister failing to canonicalize, and
    // the commitment is order-dependent, so this is a hard failure.
    fail("A. roll ordering", "published roll is not in canonical sorted order");
  }
  const rh = rollHash(rollBytes);
  rh === m.roll_hash
    ? pass("A. roll hash", `${b.roll.length} members`)
    : fail("A. roll hash", `recomputed ${rh}, manifest says ${m.roll_hash}`);

  // B -- the manifest hash is what its own fields produce.
  const mh = manifestHash({
    id,
    title: m.title,
    question: m.question,
    options: m.options,
    admin: m.admin,
    opened_at: u64(m.opened_at, "manifest.opened_at"),
    roll_hash: rh,
    pin: { ...m.pin, registry_chain_id: u64(m.pin.registry_chain_id, "pin.registry_chain_id") },
  });
  mh === m.manifest_hash
    ? pass("B. manifest hash", mh)
    : fail("B. manifest hash", `recomputed ${mh}, canister says ${m.manifest_hash}`);

  // C -- the chain. Recomputed from OUR manifest hash, not the canister's, so
  // a canister that lies about the manifest cannot also hand us a chain that
  // validates against the lie. The chain covers each ballot's credential and
  // signature, so none of them can have been swapped after the fact.
  let head = logGenesis(mh);
  let chainOk = true;
  b.log.forEach((entry, idx) => {
    const seq = u64(entry.seq, `log[${idx}].seq`);
    if (seq !== BigInt(idx)) {
      fail("C. chain", `entry ${idx} has seq ${seq}; the log must be dense and in order`);
      chainOk = false;
    }
    const pubkeyDer = strictHex(entry.voter_pubkey);
    const sig = strictHex(entry.sig);
    if (!pubkeyDer || !sig) {
      fail("C. chain", `entry ${idx} credential/signature is not lowercase even-length hex`);
      chainOk = false;
    }
    head = logAppend(
      head,
      seq,
      pubkeyDer ?? Buffer.alloc(0),
      Number(entry.choice),
      u64(entry.at, `log[${idx}].at`),
      u64(entry.sig_expires_at, `log[${idx}].sig_expires_at`),
      sig ?? Buffer.alloc(0)
    );
    if (head !== entry.entry_hash) {
      fail("C. chain", `entry ${idx} hash ${entry.entry_hash} != recomputed ${head}`);
      chainOk = false;
    }
  });
  if (chainOk) pass("C. chain", `${b.log.length} entries link to genesis`);
  head === b.certified_head.log_head
    ? pass("C. head", head)
    : fail("C. head", `recomputed ${head}, canister says ${b.certified_head.log_head}`);

  // D -- franchise, derived entirely from published credentials. For every
  // ballot: the key is well-formed, the principal DERIVED from it (never the
  // one the canister printed) is on the roll and voted once, the choice is in
  // range, and the signature verifies over (this canister, our manifest hash,
  // the recorded choice). This is the check that used to be impossible: the
  // old log recorded callers, and only the canister ever saw those.
  const canisterBytes = principalToBytes(b.canister);
  const rollSet = new Set(asGiven);
  const seen = new Set();
  let franchiseOk = true;
  b.log.forEach((entry, idx) => {
    const pubkeyDer = strictHex(entry.voter_pubkey);
    const sig = strictHex(entry.sig);
    if (!pubkeyDer || !sig || pubkeyDer.length !== 44 || !pubkeyDer.subarray(0, 12).equals(DER_PREFIX)) {
      fail("D. franchise", `ballot ${idx} carries a malformed Ed25519 credential`);
      franchiseOk = false;
      return;
    }
    const derived = principalOfKey(pubkeyDer);
    const v = derived.toString("hex");
    if (!derived.equals(principalToBytes(entry.voter))) {
      fail("D. franchise", `ballot ${idx} names ${entry.voter}, but its key derives another principal`);
      franchiseOk = false;
    }
    if (!rollSet.has(v)) {
      fail("D. franchise", `ballot ${idx} is from a key not on the roll`);
      franchiseOk = false;
    }
    if (seen.has(v)) {
      fail("D. franchise", `the key behind ballot ${idx} appears more than once in the log`);
      franchiseOk = false;
    }
    seen.add(v);
    const choice = Number(entry.choice);
    if (!Number.isInteger(choice) || choice < 0 || choice >= m.options.length) {
      fail("D. franchise", `choice ${entry.choice} is outside 0..${m.options.length - 1}`);
      franchiseOk = false;
    }
    // The freshness invariant is public: an honest canister enforcing the
    // signed expiry can never record `at` past it.
    if (u64(entry.at, `log[${idx}].at`) > u64(entry.sig_expires_at, `log[${idx}].sig_expires_at`)) {
      fail("D. franchise", `ballot ${idx} was recorded after its signature expired`);
      franchiseOk = false;
    }
    const msg = ballotSigMessage(canisterBytes, mh, choice, u64(entry.sig_expires_at, `log[${idx}].sig_expires_at`));
    if (!sigVerifies(pubkeyDer, msg, sig)) {
      fail("D. franchise", `ballot ${idx} has an invalid signature`);
      franchiseOk = false;
    }
  });
  if (franchiseOk) pass("D. franchise", `${b.log.length} of ${b.roll.length} eligible voted, all signatures verify`);

  // E -- the tally, recomputed. This is the number that matters; the
  // canister's get_tally is not consulted.
  const counts = new Array(m.options.length).fill(0n);
  for (const entry of b.log) {
    const c = Number(entry.choice);
    // Out-of-range choices already failed check D; counting them here would
    // index off the array and crash on a BigInt/undefined mix, aborting the
    // run before the verdict line -- exactly what a hostile bulletin wants.
    if (Number.isInteger(c) && c >= 0 && c < counts.length) counts[c] += 1n;
  }
  const th = tallyHash(mh, head, counts);
  console.log("");
  console.log(`      ${m.title}`);
  console.log(`      ${m.question}`);
  m.options.forEach((o, i) => console.log(`        ${String(counts[i]).padStart(6)}  ${o}`));
  console.log(`      tally_hash ${th}`);
  console.log("");

  // F -- inclusion of this election in the canister's certified tree.
  const ch = b.certified_head;
  const leaf = merkleLeaf(id, mh, head, u64(ch.ballot_count, "certified_head.ballot_count"));
  const root = merkleRecompute(leaf, ch.witness);
  pass("F. inclusion", `leaf + ${ch.witness.length}-step witness -> root ${root}`);

  // G -- does that root appear as certified_data in the IC certificate?
  const certBytes = optBlob(ch.certificate);
  if (!certBytes || certBytes.length === 0) {
    fail("G. certificate", "no certificate in the reply (was this read as a query?)");
    return;
  }
  let cert;
  try {
    cert = cborDecode(certBytes);
  } catch (e) {
    fail("G. certificate", `undecodable: ${e.message}`);
    return;
  }
  const tree = cert.get("tree");
  const canisterId = principalToBytes(b.canister);
  const certified = lookupPath(tree, ["canister", canisterId, "certified_data"]);
  if (!certified) {
    fail("G. certificate", "certificate does not contain /canister/<id>/certified_data");
    return;
  }
  if (certified.toString("hex") !== root) {
    fail(
      "G. certificate",
      `certified_data ${certified.toString("hex")} != recomputed root ${root}`
    );
    return;
  }
  const rootHash = hashTree(tree).toString("hex");
  pass("G. certificate", `certified_data matches; tree root ${rootHash}`);

  // The one thing this tool cannot do. Stated as a warning, never folded into
  // a pass: without the BLS check, everything above is consistent with a
  // replica that fabricated the whole certificate.
  warn(
    "G. signature",
    "certificate NOT signature-checked -- needs BLS12-381 against the pinned NNS root key " +
      "(ic-git ROADMAP dependency 1, unbuilt). Until it lands, treat this as " +
      "internally-consistent-but-unauthenticated."
  );
  if (cert.get("delegation")) {
    warn("G. delegation", "subnet delegation present and also unchecked");
  }
}

// --------------------------------------------------------------------------

function main() {
  const argv = process.argv.slice(2);
  const opt = (name, def) => {
    const i = argv.indexOf(`--${name}`);
    return i >= 0 ? argv[i + 1] : def;
  };

  let bulletin;
  const file = opt("file");
  const fetchId = opt("fetch");
  if (file) {
    bulletin = loadFile(file);
  } else if (fetchId !== undefined) {
    const dfxOpts = { network: opt("network", "local"), identity: opt("identity") };
    // dfx happily accepts a canister NAME as transport, but the bulletin's
    // `canister` field feeds principalToBytes in checks D and G; resolve a
    // name to its principal up front rather than crashing mid-verification.
    const canister = resolveCanister(dfxOpts, opt("canister", "poll"));
    bulletin = fetchBulletin(dfxOpts, canister, fetchId);
    if (opt("save")) {
      writeFileSync(opt("save"), JSON.stringify(bulletin, null, 2));
    }
  } else {
    console.error(
      "usage: verify-election.mjs --file <bulletin.json>\n" +
        "       verify-election.mjs --fetch <election-id> [--canister <id>] [--network local|ic] [--identity <name>]"
    );
    process.exit(2);
  }

  // The canister principal is needed to derive the signed ballot messages
  // (check D) and to look up certified_data (check G); a name or a missing
  // value cannot do either, so fail up front with instructions.
  if (!bulletin.canister || !isPrincipal(bulletin.canister)) {
    console.error(
      `bulletin's \`canister\` must be the poll canister's principal id, got ` +
        `'${bulletin.canister}'. Use \`dfx canister id poll\` and pass --canister.`
    );
    process.exit(2);
  }

  console.log(`ic-vote V0 verifier -- canister ${bulletin.canister}\n`);
  // A bulletin is untrusted input, and a verifier that dies with a stack
  // trace on hostile data has failed at its one job: whatever verify() ran
  // before the throw stands, the exception becomes one more failure, and the
  // RED verdict below still prints.
  try {
    verify(bulletin);
  } catch (e) {
    fail("verifier", `aborted by malformed bulletin data: ${e.message}`);
  }

  console.log("");
  if (failures > 0) {
    console.log(`VERDICT: RED -- ${failures} check(s) failed. This election is not verifiable.`);
    process.exit(1);
  }
  console.log(
    `VERDICT: YELLOW -- every recomputable claim holds, but ${warnings} check(s) could not be ` +
      `completed.\n         Not GREEN: see the WARN lines. A verdict is never upgraded past ` +
      `what was\n         actually checked.`
  );
}

function isPrincipal(text) {
  try {
    principalToBytes(text);
    return true;
  } catch {
    return false;
  }
}

function resolveCanister(opts, canister) {
  if (isPrincipal(canister)) return canister;
  const args = ["canister", "id", "--network", opts.network];
  if (opts.identity) args.push("--identity", opts.identity);
  args.push(canister);
  try {
    return execFileSync("dfx", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  } catch {
    console.error(
      `--canister '${canister}' is neither a principal nor a name dfx can resolve on ` +
        `network '${opts.network}'`
    );
    process.exit(2);
  }
}

main();
