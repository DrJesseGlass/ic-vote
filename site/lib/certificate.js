// IC state certificates: hash-tree reconstruction and path lookup. Structural
// only, and said so at every export.
//
// Reconstructing the tree root and reading a value out of it needs only
// sha256, so it is all here and exercised. Deciding that the root is
// *authentic* -- a BLS12-381 verification of the subnet signature, chained
// through the NNS delegation to a pinned root key -- is NOT done here. For a
// canister's module hash and controllers the page no longer reads a
// certificate through this file at all: provenance.canisterState hands that
// to ic-git's vendored core, which verifies the chain before it reads the
// tree (ic-git docs/CERTIFIED.md). What remains here serves one reader: the
// election's `certified_head`, whose certificate the page and the CLI
// verifier still take apart structurally (check G) without authenticating
// it. That gap is named in docs/V0_STATUS.md; a certificate whose structure
// checks out but whose signature was never verified is exactly what a
// malicious replica would produce, and nothing in this file may be described
// as proving otherwise.

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

/// certified_data for a canister, as shown by this certificate. Structural
/// only: the certificate's signature is not checked here (see the header).
export function certifiedData(cert, canisterBlob) {
  return lookupPath(cert.tree, ["canister", canisterBlob, "certified_data"]);
}

/// The certificate's own timestamp, in nanoseconds. Structural only: an
/// unsigned certificate can claim any time it likes, so this is a value to
/// show, not a freshness bound to rely on. (ic-git's core applies a real one
/// to the certificates it verifies.)
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
