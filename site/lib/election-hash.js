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

import { concat, equalBytes, sha256, toHex, utf8 } from "./sha256.js";
import {
  ED25519_DER_PREFIX,
  principalToBytes,
  principalToText,
  selfAuthenticating,
} from "./principal.js";

const D_MANIFEST = "ic-vote/v0/manifest-trustees";
const D_ROLL = "ic-vote/v0/roll";
const D_GENESIS = "ic-vote/v0/log-genesis";
// "-signed": the entry format changed when ballots became self-credentialed;
// see the note on D_ENTRY in canisters/poll/src/hashing.rs.
const D_ENTRY = "ic-vote/v0/log-entry-signed";
const D_BALLOT_SIG = "ic-vote/v0/ballot-sig";
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
  /// The framed bytes themselves, unhashed -- for messages that get signed
  /// rather than digested. Living on W keeps this file to ONE framing
  /// implementation, which is the property everything here depends on.
  outBytes() {
    return concat(...this.parts);
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
  w.lp(principalToBytes(m.admin)).u32(m.trustees.length);
  for (const t of m.trustees) w.lp(principalToBytes(t));
  return w
    .u32(m.threshold)
    .hash(m.roll_hash)
    .text(m.pin.repo)
    .text(m.pin.commit)
    .text(m.pin.bundle_sha256)
    .text(m.pin.site_canister)
    .text(m.pin.module_sha256)
    .text(m.pin.poll_module_sha256)
    .u64(m.pin.registry_chain_id)
    .text(m.pin.registry_address)
    .out();
}

export const logGenesis = (manifestHex) => new W(D_GENESIS).hash(manifestHex).out();

/// The entry hashes the credential (DER public key), the signed expiry, and
/// the signature -- not the voter principal, which is derived from the key.
export const logAppend = (prevHex, seq, pubkeyDer, choice, at, sigExpiresAt, sig) =>
  new W(D_ENTRY)
    .hash(prevHex)
    .u64(seq)
    .lp(pubkeyDer)
    .u32(choice)
    .u64(at)
    .u64(sigExpiresAt)
    .lp(sig)
    .out();

/// The exact bytes a roll key signs for one ballot. Mirrors
/// `hashing::ballot_sig_message`: length-prefixed domain, length-prefixed
/// poll canister principal, 32-byte manifest hash, u32be choice, u64be
/// expiry (ns). The expiry is the replay bound: without it a harvested
/// signature would authorize the ballot for the whole voting window.
/// `canisterId` may be principal text or the already-decoded bytes.
export function ballotSigMessage(canisterId, manifestHex, choice, expiresAt) {
  const canister =
    canisterId instanceof Uint8Array ? canisterId : principalToBytes(canisterId);
  return new W(D_BALLOT_SIG).lp(canister).hash(manifestHex).u32(choice).u64(expiresAt).outBytes();
}

/// Ed25519 verification via WebCrypto. The canister verifies strictly
/// (verify_strict in ed25519-dalek), and strict acceptance implies acceptance
/// here, so a log the canister built never reads as forged in a browser.
async function sigVerifies(pubkeyDer, message, sig) {
  try {
    // Raw key: the last 32 bytes of the fixed 44-byte DER encoding. Import as
    // raw rather than spki so a malformed DER prefix fails the explicit check
    // below instead of whatever the platform's ASN.1 parser tolerates.
    const key = await crypto.subtle.importKey(
      "raw",
      pubkeyDer.slice(12),
      { name: "Ed25519" },
      false,
      ["verify"]
    );
    return await crypto.subtle.verify({ name: "Ed25519" }, key, sig, message);
  } catch {
    return false;
  }
}

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
///
/// `canisterId` is the poll canister's principal text: the ballot signatures
/// bind to it, so the franchise check needs to know which canister's board
/// this claims to be. Async because signature verification is (WebCrypto).
export async function recomputeBoard({ manifest, roll, log, canisterId }) {
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
  // Decoded once: every ballot's signed message starts with the same
  // canister principal, and re-deriving it per entry was pure waste.
  const canisterBytes = principalToBytes(canisterId);
  // Signature checks are independent of each other, so they all start now
  // and are awaited together after the synchronous pass -- N WebCrypto
  // round-trips in flight at once instead of serialized.
  const sigChecks = [];
  // Chained from OUR manifest hash, not the canister's: a canister that lies
  // about the manifest must not also be able to supply a log that validates
  // against the lie.
  let head = logGenesis(mh);
  for (const [idx, entry] of log.entries()) {
    if (Number(entry.seq) !== idx) {
      problems.push(`log entry ${idx} claims seq ${entry.seq}; the log must be dense and ordered`);
    }
    const pubkeyDer = fromHexBytes(entry.voter_pubkey);
    const sig = fromHexBytes(entry.sig);
    head = logAppend(head, entry.seq, pubkeyDer, entry.choice, entry.at, entry.sig_expires_at, sig);
    if (head !== entry.entry_hash) {
      problems.push(`log entry ${idx} hash does not chain`);
    }
    // The franchise is derived from the published credential, never taken
    // from the canister's `voter` field -- that field is checked FOR
    // CONSISTENCY with the key, which is the opposite direction of trust.
    if (pubkeyDer.length !== 44 || !equalBytes(pubkeyDer.subarray(0, 12), ED25519_DER_PREFIX)) {
      problems.push(`ballot ${idx} carries a malformed Ed25519 credential`);
    } else {
      const voter = principalToText(selfAuthenticating(pubkeyDer));
      if (voter !== entry.voter) {
        problems.push(`ballot ${idx} names ${entry.voter}, but its key derives ${voter}`);
      }
      if (!rollSet.has(voter)) problems.push(`ballot ${idx} is from a voter not on the roll`);
      if (seen.has(voter)) problems.push(`voter in ballot ${idx} appears more than once`);
      seen.add(voter);
      // The freshness invariant is public: a canister honestly enforcing the
      // signed expiry can never record `at` past it.
      if (BigInt(entry.at) > BigInt(entry.sig_expires_at)) {
        problems.push(`ballot ${idx} was recorded after its signature expired`);
      }
      const msg = ballotSigMessage(canisterBytes, mh, entry.choice, entry.sig_expires_at);
      sigChecks.push([idx, sigVerifies(pubkeyDer, msg, sig)]);
    }
    if (entry.choice >= counts.length) {
      problems.push(`ballot ${idx} has choice ${entry.choice}, outside the option list`);
    } else {
      counts[entry.choice] += 1;
    }
  }
  // Awaited in index order so `problems` stays deterministic.
  for (const [idx, check] of sigChecks) {
    if (!(await check)) problems.push(`ballot ${idx} has an invalid signature`);
  }

  return {
    manifestHash: mh,
    rollHash: rh,
    logHead: head,
    counts,
    tallyHash: tallyHash(mh, head, counts.map(BigInt)),
    problems,
  };
}

function fromHexBytes(hex) {
  if (typeof hex !== "string" || hex.length % 2 !== 0 || /[^0-9a-f]/.test(hex)) return new Uint8Array(0);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
