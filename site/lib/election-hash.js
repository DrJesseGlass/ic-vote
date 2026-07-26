// The ic-vote V0 hash rules, in the browser.
//
// A third implementation of canisters/poll/src/hashing.rs, alongside
// tools/verify-election.mjs. That is not duplication for its own sake: the
// voter's own client has to be able to recompute the board without shipping
// the canister's Rust, and tools/test-site-lib.mjs asserts all three agree on
// the same vectors. Three implementations that agree is evidence; one
// implementation used three times is a single point of failure wearing a
// disguise.
//
// The two rules from the Rust file apply unchanged: every hash is
// domain-separated, and every variable-length field is length-prefixed.

import { concat, sha256, toHex, utf8 } from "./sha256.js";
import { principalToBytes } from "./principal.js";

const D_MANIFEST = "ic-vote/v0/manifest";
const D_ROLL = "ic-vote/v0/roll";
const D_GENESIS = "ic-vote/v0/log-genesis";
const D_ENTRY = "ic-vote/v0/log-entry";
const D_TALLY = "ic-vote/v0/tally";
const D_LEAF = "ic-vote/v0/merkle-leaf";
const D_NODE = "ic-vote/v0/merkle-node";
const D_EMPTY = "ic-vote/v0/merkle-empty";

const u32be = (n) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, Number(n));
  return b;
};

const u64be = (n) => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n));
  return b;
};

class W {
  constructor(domain) {
    const d = utf8(domain);
    this.parts = [u32be(d.length), d];
  }
  lp(bytes) {
    this.parts.push(u32be(bytes.length), bytes);
    return this;
  }
  text(s) {
    return this.lp(utf8(s));
  }
  u32(n) {
    this.parts.push(u32be(n));
    return this;
  }
  u64(n) {
    this.parts.push(u64be(n));
    return this;
  }
  hash(hex) {
    const b = fromHex32(hex);
    this.parts.push(b);
    return this;
  }
  out() {
    return toHex(sha256(concat(...this.parts)));
  }
}

function fromHex32(hex) {
  if (typeof hex !== "string" || hex.length !== 64 || /[^0-9a-f]/.test(hex)) {
    throw new Error(`expected a 64-char lowercase hex hash, got ${hex}`);
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

export function rollHash(principalTexts) {
  const w = new W(D_ROLL).u32(principalTexts.length);
  for (const p of principalTexts) w.lp(principalToBytes(p));
  return w.out();
}

/// `m.pin` fields and `m.options` come straight from `get_manifest`, so this
/// recomputes the commitment from the same object the UI renders -- if the two
/// ever diverge, the voter is looking at a ballot that is not the one being
/// hashed.
export function manifestHash(m) {
  const w = new W(D_MANIFEST)
    .u64(m.id)
    .text(m.title)
    .text(m.question)
    .u32(m.options.length);
  for (const o of m.options) w.text(o);
  return w
    .lp(principalToBytes(m.admin))
    .u64(m.opened_at)
    .hash(m.roll_hash)
    .text(m.pin.repo)
    .text(m.pin.commit)
    .text(m.pin.bundle_sha256)
    .text(m.pin.site_canister)
    .text(m.pin.module_sha256)
    .u64(m.pin.registry_chain_id)
    .text(m.pin.registry_address)
    .out();
}

export const logGenesis = (manifestHex) => new W(D_GENESIS).hash(manifestHex).out();

export const logAppend = (prevHex, seq, voterText, choice, at) =>
  new W(D_ENTRY).hash(prevHex).u64(seq).lp(principalToBytes(voterText)).u32(choice).u64(at).out();

export function tallyHash(manifestHex, headHex, counts) {
  const w = new W(D_TALLY).hash(manifestHex).hash(headHex).u32(counts.length);
  for (const c of counts) w.u64(c);
  return w.out();
}

export const merkleLeaf = (id, manifestHex, headHex, ballotCount) =>
  new W(D_LEAF).u64(id).hash(manifestHex).hash(headHex).u64(ballotCount).out();

export const merkleNode = (l, r) => new W(D_NODE).hash(l).hash(r).out();

export const merkleEmpty = () => new W(D_EMPTY).out();

export function merkleRecompute(leafHex, steps) {
  let acc = leafHex;
  for (const s of steps) {
    acc = s.sibling_is_right ? merkleNode(acc, s.sibling) : merkleNode(s.sibling, acc);
  }
  return acc;
}

/// Recompute the whole board from published data.
///
/// Returns the head, per-option counts, and the tally hash, plus the first
/// problem found. Nothing here consults the canister's own `get_tally`.
export function recomputeBoard({ manifest, roll, log }) {
  const problems = [];
  const rh = rollHash(roll);
  if (rh !== manifest.roll_hash) {
    problems.push(`roll hash ${rh} does not match the manifest's ${manifest.roll_hash}`);
  }
  const mh = manifestHash({ ...manifest, roll_hash: rh });
  if (mh !== manifest.manifest_hash) {
    problems.push(`manifest hash ${mh} does not match the canister's ${manifest.manifest_hash}`);
  }

  const rollSet = new Set(roll);
  const seen = new Set();
  const counts = new Array(manifest.options.length).fill(0);
  // Chained from OUR manifest hash, not the canister's: a canister that lies
  // about the manifest must not also be able to supply a log that validates
  // against the lie.
  let head = logGenesis(mh);
  log.forEach((entry, idx) => {
    if (Number(entry.seq) !== idx) {
      problems.push(`log entry ${idx} claims seq ${entry.seq}; the log must be dense and ordered`);
    }
    head = logAppend(head, entry.seq, entry.voter, entry.choice, entry.at);
    if (head !== entry.entry_hash) {
      problems.push(`log entry ${idx} hash does not chain`);
    }
    if (!rollSet.has(entry.voter)) problems.push(`ballot ${idx} is from a voter not on the roll`);
    if (seen.has(entry.voter)) problems.push(`voter in ballot ${idx} appears more than once`);
    seen.add(entry.voter);
    if (entry.choice >= counts.length) {
      problems.push(`ballot ${idx} has choice ${entry.choice}, outside the option list`);
    } else {
      counts[entry.choice] += 1;
    }
  });

  return {
    manifestHash: mh,
    rollHash: rh,
    logHead: head,
    counts,
    tallyHash: tallyHash(mh, head, counts.map(BigInt)),
    problems,
  };
}
