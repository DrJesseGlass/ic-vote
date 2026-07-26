// keccak256, as Ethereum uses it (padding 0x01, not SHA3's 0x06).
//
// Needed because reading the ProvenanceRegistry means computing ABI function
// selectors and mapping keys, both of which are keccak256. ic-git's
// tools/verify.mjs sidesteps this by hardcoding the one selector it needs and
// telling the reader to recompute it with an external tool. That is fine for a
// CLI; it is not fine here, where hardcoded constants would be four more magic
// numbers a build reviewer has to verify by hand inside the very bundle whose
// reviewability is the product.
//
// BigInt lanes rather than 32-bit halves: half the code, and this hashes a
// handful of short strings per page load, so the constant factor is
// irrelevant. Checked against known vectors in tools/test-site-lib.mjs.

import { utf8 } from "./sha256.js";

const MASK = (1n << 64n) - 1n;

const RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];

// Rotation offsets, indexed x + 5*y.
const ROT = [
  0, 1, 62, 28, 27,
  36, 44, 6, 55, 20,
  3, 10, 43, 25, 39,
  41, 45, 15, 21, 8,
  18, 2, 61, 56, 14,
];

const rotl = (v, n) => (n === 0 ? v : ((v << BigInt(n)) | (v >> BigInt(64 - n))) & MASK);

function permute(A) {
  for (let round = 0; round < 24; round++) {
    // theta
    const C = new Array(5);
    for (let x = 0; x < 5; x++) {
      C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
    }
    for (let x = 0; x < 5; x++) {
      const D = C[(x + 4) % 5] ^ rotl(C[(x + 1) % 5], 1);
      for (let y = 0; y < 5; y++) A[x + 5 * y] ^= D;
    }
    // rho + pi
    const B = new Array(25).fill(0n);
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(A[x + 5 * y], ROT[x + 5 * y]);
      }
    }
    // chi
    for (let y = 0; y < 5; y++) {
      for (let x = 0; x < 5; x++) {
        A[x + 5 * y] = B[x + 5 * y] ^ (~B[((x + 1) % 5) + 5 * y] & B[((x + 2) % 5) + 5 * y] & MASK);
      }
    }
    // iota
    A[0] ^= RC[round];
  }
}

function sponge(bytes, padByte) {
  const RATE = 136; // 1088 bits, the rate for a 256-bit digest
  const padded = new Uint8Array(Math.ceil((bytes.length + 1) / RATE) * RATE);
  padded.set(bytes);
  padded[bytes.length] = padByte;
  padded[padded.length - 1] |= 0x80;

  const A = new Array(25).fill(0n);
  const view = new DataView(padded.buffer);
  for (let off = 0; off < padded.length; off += RATE) {
    for (let i = 0; i < RATE / 8; i++) {
      A[i] ^= view.getBigUint64(off + i * 8, true);
    }
    permute(A);
  }

  const out = new Uint8Array(32);
  const ov = new DataView(out.buffer);
  for (let i = 0; i < 4; i++) ov.setBigUint64(i * 8, A[i], true);
  return out;
}

/// Ethereum's keccak256: original Keccak padding (0x01).
export const keccak256 = (bytes) => sponge(bytes, 0x01);

/// NIST SHA3-256: identical sponge, standardized padding (0x06).
///
/// Present solely so the permutation above can be cross-checked against a
/// reference implementation. Ethereum's keccak256 has no equivalent in Node or
/// in WebCrypto, so a mistake in the 24 rounds would otherwise only be
/// detectable against hardcoded digests -- and a hardcoded digest recalled
/// from memory is not a test, it is the same guess written twice.
/// tools/test-site-lib.mjs compares this against Node's built-in `sha3-256`
/// across every length that crosses a block boundary; the two functions differ
/// by one byte, so agreement there is agreement about the permutation.
export const sha3_256 = (bytes) => sponge(bytes, 0x06);

/// First four bytes of keccak256 of a canonical signature, as hex without 0x.
export function selector(signature) {
  const h = keccak256(utf8(signature));
  let s = "";
  for (let i = 0; i < 4; i++) s += h[i].toString(16).padStart(2, "0");
  return s;
}
