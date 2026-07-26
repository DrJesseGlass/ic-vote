// IC state certificates: hash-tree reconstruction, path lookup, and an
// explicit hole where the signature check belongs.
//
// Everything here is structural. Reconstructing the tree root and reading a
// value out of it needs only sha256, so it is all present and exercised.
// Deciding that the root is *authentic* needs a BLS12-381 verification of the
// subnet signature, chained through the NNS delegation to a pinned root key --
// which is ic-git ROADMAP dependency 1 and is not built. `verifySignature`
// therefore returns UNAVAILABLE rather than throwing or, worse, returning
// true.
//
// This is the single most important place in the codebase not to be
// optimistic. A certificate whose structure checks out but whose signature was
// never verified is exactly what a malicious replica would produce; treating
// it as verified converts the project's central claim into a lie. Callers must
// propagate UNAVAILABLE into their verdict.

import { concat, equalBytes, sha256, utf8 } from "./sha256.js";
import * as cbor from "./cbor.js";

const EMPTY = 0;
const FORK = 1;
const LABELED = 2;
const LEAF = 3;
const PRUNED = 4;

const domainSep = (name) => concat(new Uint8Array([name.length]), utf8(name));

export function hashTree(node) {
  if (!Array.isArray(node) || node.length === 0) {
    throw new Error("malformed hash tree node");
  }
  switch (Number(node[0])) {
    case EMPTY:
      return sha256(domainSep("ic-hashtree-empty"));
    case FORK:
      return sha256(concat(domainSep("ic-hashtree-fork"), hashTree(node[1]), hashTree(node[2])));
    case LABELED:
      return sha256(concat(domainSep("ic-hashtree-labeled"), node[1], hashTree(node[2])));
    case LEAF:
      return sha256(concat(domainSep("ic-hashtree-leaf"), node[1]));
    case PRUNED:
      return node[1];
    default:
      throw new Error(`unknown hash tree tag ${node[0]}`);
  }
}

function findLabel(node, label) {
  const tag = Number(node[0]);
  if (tag === LABELED) return equalBytes(node[1], label) ? node[2] : null;
  if (tag === FORK) return findLabel(node[1], label) ?? findLabel(node[2], label);
  return null;
}

/// Read a leaf out of the tree. Returns null when the path is absent OR
/// pruned; the caller must not read that as "the state does not contain it",
/// only as "this certificate does not show it to me".
export function lookupPath(tree, path) {
  let node = tree;
  for (const segment of path) {
    const label = typeof segment === "string" ? utf8(segment) : segment;
    node = findLabel(node, label);
    if (!node) return null;
  }
  return Number(node[0]) === LEAF ? node[1] : null;
}

export function parseCertificate(bytes) {
  const decoded = cbor.decode(bytes);
  if (!(decoded instanceof Map) || !decoded.has("tree")) {
    throw new Error("certificate is not a map containing 'tree'");
  }
  return {
    tree: decoded.get("tree"),
    signature: decoded.get("signature") ?? null,
    delegation: decoded.get("delegation") ?? null,
  };
}

export const CERT_UNAVAILABLE = "UNAVAILABLE";

/// The unbuilt check, named so that its absence is visible in the call graph
/// rather than implied by omission.
///
/// When ic-git ships the certified module-hash reader (BLS12-381 + pinned NNS
/// root key + freshness), this becomes a real verification and the callers'
/// verdict logic does not have to change -- they already treat anything other
/// than a positive result as disqualifying.
export function verifySignature(_certificate) {
  return {
    status: CERT_UNAVAILABLE,
    reason:
      "BLS12-381 verification against the pinned NNS root key is not implemented. " +
      "It is ic-git ROADMAP dependency 1 (docs/ATTESTATION.md, 'Certified live " +
      "module-hash read'), the highest-risk unbuilt component in the stack. " +
      "Until it exists, no certificate on this page has been authenticated.",
  };
}

/// certified_data for a canister, as shown by this certificate. Structural
/// only -- see `verifySignature`.
export function certifiedData(cert, canisterBlob) {
  return lookupPath(cert.tree, ["canister", canisterBlob, "certified_data"]);
}

/// A canister's module hash, as shown by this certificate. Structural only.
export function moduleHash(cert, canisterBlob) {
  return lookupPath(cert.tree, ["canister", canisterBlob, "module_hash"]);
}

/// The certificate's own timestamp, in nanoseconds. Needed for the freshness
/// bound in ic-git's step 4: without it, an attacker replays an old
/// certificate showing the previously-verified module hash after a malicious
/// upgrade. Parsed here so the shape is ready; it is not yet trustworthy,
/// because an unsigned certificate can claim any time it likes.
export function certificateTime(cert) {
  const raw = lookupPath(cert.tree, ["time"]);
  if (!raw) return null;
  let result = 0n;
  let shift = 0n;
  for (const byte of raw) {
    result |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) break;
    shift += 7n;
  }
  return result;
}
