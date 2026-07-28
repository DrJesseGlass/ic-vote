// IC principals: textual form <-> raw blob.
//
// The textual form is base32(crc32(blob) || blob), lowercased, in dash-
// separated groups of five. The checksum is load-bearing for us: a principal
// that is mistranscoded but still decodes would silently produce a roll hash
// over the wrong members, and the roll hash is what the manifest commits to.
// So decoding always verifies the checksum and throws otherwise.

import { concat, sha224 } from "./sha256.js";

const ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";

let TABLE = null;
function crc32(bytes) {
  if (!TABLE) {
    TABLE = new Int32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      TABLE[n] = c;
    }
  }
  let c = -1;
  for (const b of bytes) c = (c >>> 8) ^ TABLE[(c ^ b) & 0xff];
  c = (c ^ -1) >>> 0;
  return new Uint8Array([c >>> 24, (c >>> 16) & 0xff, (c >>> 8) & 0xff, c & 0xff]);
}

function base32Encode(bytes) {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += ALPHABET[(value >>> bits) & 31];
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

function base32Decode(text) {
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of text) {
    const idx = ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error(`invalid principal character '${ch}'`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

export function principalToBytes(text) {
  const clean = String(text).toLowerCase().replace(/-/g, "");
  const raw = base32Decode(clean);
  if (raw.length < 4) throw new Error(`principal too short: ${text}`);
  const checksum = raw.subarray(0, 4);
  const blob = raw.subarray(4);
  const want = crc32(blob);
  for (let i = 0; i < 4; i++) {
    if (checksum[i] !== want[i]) throw new Error(`principal checksum failed: ${text}`);
  }
  return blob;
}

export function principalToText(blob) {
  const body = base32Encode(concat(crc32(blob), blob));
  return (body.match(/.{1,5}/g) || []).join("-");
}

export const ANONYMOUS = new Uint8Array([4]);
export const ANONYMOUS_TEXT = principalToText(ANONYMOUS);

/// The IC's DER wrapper for an Ed25519 SPKI public key. Fixed 12-byte prefix
/// followed by the 32-byte raw key. Exported because election-hash.js checks
/// credentials against it -- the encoder and the checker must share one copy
/// of this constant or they can drift apart.
export const ED25519_DER_PREFIX = new Uint8Array([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

export const derEncodeEd25519 = (rawPublicKey) =>
  concat(ED25519_DER_PREFIX, rawPublicKey);

/// Self-authenticating principal: sha224(DER public key) || 0x02.
export const selfAuthenticating = (derPublicKey) =>
  concat(sha224(derPublicKey), new Uint8Array([0x02]));
