// Reads the facts the verdict is computed from:
//
//   1. what the ProvenanceRegistry says about this repo: the site bundle it
//      serves (`<repo>#site`), the build ic-git installed in its poll
//      canister (`<repo>#app`), and the build ic-git itself runs
//      (`ic-git#canister`);
//   2. what the serving canister, the poll canister and ic-git's governor
//      actually run, and who controls each, on the IC's own word;
//   3. what bytes were actually served for this page.
//
// Fact 1 comes from an EVM JSON-RPC endpoint, 2 and 3 from the IC. Both are
// untrusted transports. A lying RPC node can only fabricate a record, and a
// record is compared against a certified read, never taken for one; a lying
// gateway can serve other bytes, which is what hashing them catches. Fact 2
// has no anchor of its own -- the module hash IS the fact being asked for --
// which is why it comes through a state certificate: ic-git's core
// (ic-git-core.js, vendored by tools/sync-ic-git-core.mjs) verifies the
// subnet's BLS12-381 signature over the state tree, chained through the
// subnet delegation to the NNS root key it pins, before it reads anything
// out of the tree. A read that fails any of those checks comes back
// `certified: false`, and the verdict treats it as not read.

import { sha256, toHex, utf8 } from "./sha256.js";
import { selector } from "./keccak.js";
import * as cbor from "./cbor.js";
import { Verifier } from "./ic-git-core.js";

// Computed, not hardcoded. `get(string)` must come out as 693ec85e -- ic-git
// docs/ATTESTATION.md pins that selector because tools/verify.mjs depends on
// it, and tools/test-site-lib.mjs asserts our keccak reproduces it. A
// mismatch means our keccak is wrong, and we would rather fail that assertion
// than silently read the wrong storage slot.
export const SEL_GET = selector("get(string)");

const pad32 = (hex) => hex.padStart(64, "0");

function encodeString(s) {
  const bytes = utf8(s);
  const len = pad32(bytes.length.toString(16));
  let data = "";
  for (const b of bytes) data += b.toString(16).padStart(2, "0");
  const padded = data.padEnd(Math.ceil(bytes.length / 32) * 64, "0");
  return len + padded;
}

async function ethCall(rpcUrl, to, data) {
  const res = await fetch(rpcUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "eth_call",
      params: [{ to, data: `0x${data}` }, "latest"],
    }),
  });
  if (!res.ok) throw new Error(`RPC returned HTTP ${res.status}`);
  const body = await res.json();
  if (body.error) throw new Error(`RPC error: ${body.error.message}`);
  const out = String(body.result || "").replace(/^0x/, "");
  return out;
}

const slot = (hex, i) => hex.slice(i * 64, (i + 1) * 64);

/// `get(key)` -> one registry record: what the ic-git canister published
/// under that key. Every record has the same shape, (commit, sha256, when):
/// for `<repo>#site` the sha256 is of the served page, for `<repo>#app` and
/// `ic-git#canister` it is of an installed wasm module, which is what the IC
/// certifies as that canister's module hash.
///
/// Returns null when the record has never been written: the contract returns
/// an all-zero struct rather than reverting, and `updatedAt == 0` is the
/// existence flag. Reading absence as "commit 0x00.., sha256 0x00.." would let
/// a never-published repo match a page that hashes to zero.
export async function registryRecord(rpcUrl, registry, key) {
  const out = await ethCall(rpcUrl, registry, SEL_GET + pad32("20") + encodeString(key));
  if (out.length < 192) throw new Error("registry get() returned a short reply");
  const updatedAt = BigInt(`0x${slot(out, 2)}`);
  if (updatedAt === 0n) return null;
  return {
    commit: slot(out, 0).slice(0, 40), // bytes20 is left-aligned in its slot
    bundleHash: slot(out, 1),
    updatedAt,
  };
}

/// The certified state of any canister: its module hash and controllers, out
/// of a certificate the IC signed, verified by ic-git's core.
///
/// Resolves to the core's report: `{ certified, moduleHash, controllers,
/// stale, time, checks }`. `certified` is true only when every check passed
/// (the reply is a certificate, its signing key is delegated by the NNS root
/// key, the signature verifies, the certificate is dated, and the tree shows
/// both paths); otherwise `checks` says which failed and `moduleHash` and
/// `controllers` are null. `stale` means the certificate is genuine but older
/// than the core's freshness bound.
///
/// `rootKey` overrides the pinned NNS root key and exists for one caller:
/// a page served from a local replica, whose certificates are signed by that
/// replica's own key (see `localRootKey`). Off this machine nothing passes it.
export async function canisterState(icApi, canisterText, { rootKey, now, fetch: fetchImpl } = {}) {
  // Built field by field: a key present but undefined would override the
  // core's default with undefined, and the read would throw instead of
  // falling back to the pinned key.
  const options = { icApi };
  if (rootKey !== undefined) options.rootKey = rootKey;
  if (now !== undefined) options.now = now;
  if (fetchImpl !== undefined) options.fetch = fetchImpl;
  return Verifier.readCanisterState(canisterText, options);
}

/// The root key a LOCAL replica signs with, read from the replica itself.
///
/// A key read from the network being checked proves nothing about it, and
/// this is used only for a page served from this machine (config.js, the same
/// rule as every local override): it lets the whole certificate path --
/// delegation, BLS signature, freshness, tree -- run end to end on bytes a real
/// replica produced, instead of being skipped locally and first exercised on
/// mainnet. The mainnet key is pinned inside ic-git's core and is never read
/// from anywhere.
export async function localRootKey(icApi) {
  const res = await fetch(`${icApi.replace(/\/$/, "")}/api/v2/status`);
  if (!res.ok) throw new Error(`status returned HTTP ${res.status}`);
  const status = cbor.decode(new Uint8Array(await res.arrayBuffer()));
  const key = status instanceof Map ? status.get("root_key") : status?.root_key;
  if (!(key instanceof Uint8Array) || key.length !== 133) throw new Error("status reply carries no root key");
  return toHex(key);
}

/// sha256 of the bytes actually served for this page.
///
/// Re-fetched with `cache: "no-store"` rather than hashing the live DOM: the
/// DOM has already been transformed by the parser and by any script that ran,
/// so hashing it would compare a derived artifact against a hash of the source
/// bytes and never match. The re-fetch is also what the registry's bundleHash
/// is defined over (sha256 of the served site entrypoint).
export async function servedBundle(url) {
  const res = await fetch(url, { cache: "no-store" });
  if (!res.ok) throw new Error(`could not re-fetch ${url}: HTTP ${res.status}`);
  const bytes = new Uint8Array(await res.arrayBuffer());
  return {
    sha256: toHex(sha256(bytes)),
    bytes: bytes.length,
    // ic-git binds every served response to the commit it came from.
    commitHeader: res.headers.get("X-Ic-Git-Commit"),
    repoHeader: res.headers.get("X-Ic-Git-Repo"),
  };
}
