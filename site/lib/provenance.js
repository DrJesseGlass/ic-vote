// Reads the three facts the verdict is computed from:
//
//   1. what the ProvenanceRegistry says this repo's site bundle should be;
//   2. which trusted verifiers have attested the serving canister's wasm;
//   3. what the serving canister's module hash and served bytes actually are.
//
// Facts 1 and 2 come from an EVM JSON-RPC endpoint, fact 3 from the IC. Both
// are untrusted transports: an RPC node can lie about chain state and a
// gateway can lie about served bytes. That is fine for 1 and 2 in one
// direction only -- a lying RPC can fabricate agreement, which is why the
// trusted verifier set is pinned in this bundle and the read is a point read
// per verifier rather than a summary the contract computes.

import { sha256, toHex, utf8 } from "./sha256.js";
import { selector } from "./keccak.js";
import { certifiedData, moduleHash, parseCertificate, verifySignature } from "./certificate.js";
import { principalToBytes } from "./principal.js";

// Computed, not hardcoded. `get(string)` must come out as 693ec85e -- ic-git
// docs/ATTESTATION.md pins that selector because tools/verify.mjs depends on
// it, and tools/test-site-lib.mjs asserts our keccak reproduces it. A
// mismatch means our keccak is wrong, and we would rather fail that assertion
// than silently read the wrong storage slot.
export const SEL_GET = selector("get(string)");
export const SEL_ATTESTATION = selector("attestation(string,address)");

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

/// `get(recordKey)` -> the canister's own attestation of what it serves.
/// Returns null when the record has never been written: the contract returns
/// an all-zero struct rather than reverting, and `updatedAt == 0` is the
/// existence flag (ic-git docs/ATTESTATION.md makes the same point about
/// `at` on attestations). Reading absence as "commit 0x00.., bundle 0x00.."
/// would let a never-published repo match a page that hashes to zero.
export async function registrySite(rpcUrl, registry, recordKey) {
  const out = await ethCall(rpcUrl, registry, SEL_GET + pad32("20") + encodeString(recordKey));
  if (out.length < 192) throw new Error("registry get() returned a short reply");
  const updatedAt = BigInt(`0x${slot(out, 2)}`);
  if (updatedAt === 0n) return null;
  return {
    commit: slot(out, 0).slice(0, 40), // bytes20 is left-aligned in its slot
    bundleHash: slot(out, 1),
    updatedAt,
  };
}

/// One verifier's latest attestation, or null if they have never attested.
export async function registryAttestation(rpcUrl, registry, canisterText, verifier) {
  const data =
    SEL_ATTESTATION +
    pad32("40") +
    pad32(verifier.replace(/^0x/, "").toLowerCase()) +
    encodeString(canisterText);
  const out = await ethCall(rpcUrl, registry, data);
  if (out.length < 256) throw new Error("registry attestation() returned a short reply");
  const at = BigInt(`0x${slot(out, 3)}`);
  if (at === 0n) return null;
  return {
    verifier: verifier.toLowerCase(),
    moduleHash: slot(out, 0),
    commit: slot(out, 1).slice(0, 40),
    recipeHash: slot(out, 2),
    at,
  };
}

/// The certified module hash of any canister.
///
/// Named for what it does rather than for one caller: it is used for both the
/// canister serving the bundle and the canister holding the ballots, and an
/// earlier name (`servingCanisterModuleHash`) is part of why only the first of
/// those was ever checked.
///
/// `signature` is the whole story: the hash is extracted from a real IC
/// certificate, but nothing has checked that the certificate is genuine. See
/// certificate.js.
export async function canisterModuleHash(agent, canisterText) {
  const certBytes = await agent.readModuleHash(canisterText);
  const cert = parseCertificate(certBytes);
  const raw = moduleHash(cert, principalToBytes(canisterText));
  return {
    certBytes,
    cert,
    hash: raw ? toHex(raw) : null,
    signature: verifySignature(cert),
  };
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

export { certifiedData, verifySignature };
