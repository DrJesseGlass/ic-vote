// A minimal IC agent: query, call, read_state.
//
// Hand-written rather than bundled from npm, because the whole premise of this
// project is that a voter can check the bytes in their browser against
// reviewed source. A minified vendor bundle is bytes nobody reviewed; shipping
// one inside the attested bundle would mean the attestation covers code that
// no reviewer read, which is the exact gap VISION.md says this project closes.
// The cost is that this file is ours to get right, so it stays small and its
// behaviour is pinned by tools/test-site-lib.mjs against a live replica.

import * as cbor from "./cbor.js";
import * as candid from "./candid.js";
import { lookupPath, parseCertificate } from "./certificate.js";
import { concat, sha256, utf8 } from "./sha256.js";
import {
  ANONYMOUS,
  derEncodeEd25519,
  principalToBytes,
  principalToText,
  selfAuthenticating,
} from "./principal.js";

/// Ingress messages expire; the replica rejects anything more than ~5 minutes
/// out. Four leaves room for clock skew without inviting replay.
const EXPIRY_NS = 4n * 60n * 1_000_000_000n;

// --- representation-independent hashing (the request id) ------------------

function leb128(nBig) {
  let n = BigInt(nBig);
  const out = [];
  do {
    let byte = Number(n & 0x7fn);
    n >>= 7n;
    if (n !== 0n) byte |= 0x80;
    out.push(byte);
  } while (n !== 0n);
  return new Uint8Array(out);
}

function hashValue(value) {
  if (value instanceof Uint8Array) return sha256(value);
  if (typeof value === "string") return sha256(utf8(value));
  if (typeof value === "bigint" || typeof value === "number") return sha256(leb128(value));
  if (Array.isArray(value)) return sha256(concat(...value.map(hashValue)));
  if (value instanceof Map) return hashMap(value);
  if (value && typeof value === "object") return hashMap(new Map(Object.entries(value)));
  throw new Error(`cannot hash ${typeof value} in a request`);
}

function hashMap(map) {
  const rows = [];
  for (const [k, v] of map) {
    if (v === undefined) continue;
    rows.push(concat(sha256(utf8(k)), hashValue(v)));
  }
  // Sorted bytewise, which is what makes the hash independent of field order.
  rows.sort((a, b) => {
    for (let i = 0; i < Math.min(a.length, b.length); i++) {
      if (a[i] !== b[i]) return a[i] - b[i];
    }
    return a.length - b.length;
  });
  return sha256(concat(...rows));
}

export const requestId = (content) => hashMap(new Map(Object.entries(content)));

// --- identities -----------------------------------------------------------

export class AnonymousIdentity {
  get principal() {
    return ANONYMOUS;
  }
  get principalText() {
    return principalToText(ANONYMOUS);
  }
  async transform(content) {
    return { content };
  }
}

/// An Ed25519 keypair held in the page.
///
/// This is a DEMO identity, and calling it anything else would be dishonest.
/// A key in localStorage is readable by anything that achieves script
/// execution on this origin -- which, note, is a strictly weaker adversary
/// than the malicious-client attacker this project exists to stop, so it does
/// not undermine the V0 claim; it does mean this is not how a real
/// organizational election should enrol voters. The production path is
/// Internet Identity or an organization-issued credential, and it is the
/// T4/enrolment work in THREAT_MODEL.md, not a crypto problem.
export class Ed25519Identity {
  constructor(keyPair, derPublicKey) {
    this.keyPair = keyPair;
    this.der = derPublicKey;
    this.principal = selfAuthenticating(derPublicKey);
  }

  get principalText() {
    return principalToText(this.principal);
  }

  static async generate() {
    const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
    return new Ed25519Identity(kp, derEncodeEd25519(raw));
  }

  static async fromPkcs8(pkcs8) {
    const privateKey = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, true, [
      "sign",
    ]);
    // Recovering the public key needs care: WebCrypto exports Ed25519 as
    // pkcs8 v1, which contains ONLY the private seed -- an earlier version
    // read "the last 32 bytes" and got the seed, so every reloaded identity
    // silently became a different principal. The JWK view of the same private
    // key does carry the public half (its `x` parameter, base64url), in both
    // browsers and Node.
    const jwk = await crypto.subtle.exportKey("jwk", privateKey);
    const b64 = jwk.x.replace(/-/g, "+").replace(/_/g, "/");
    const raw = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    return new Ed25519Identity({ privateKey }, derEncodeEd25519(raw));
  }

  async exportPkcs8() {
    return new Uint8Array(await crypto.subtle.exportKey("pkcs8", this.keyPair.privateKey));
  }

  /// Sign arbitrary bytes -- used for the in-ballot credential signature
  /// (election-hash.js ballotSigMessage). Safe next to `transform` because
  /// the two domains cannot collide: an ic-request signature covers bytes
  /// beginning 0x0A "ic-request", a ballot signature covers bytes beginning
  /// with a u32be length (0x00...), so no signature made here can be replayed
  /// as an ingress envelope or vice versa.
  async signMessage(bytes) {
    return new Uint8Array(
      await crypto.subtle.sign({ name: "Ed25519" }, this.keyPair.privateKey, bytes)
    );
  }

  async transform(content) {
    const id = requestId(content);
    const signature = new Uint8Array(
      await crypto.subtle.sign(
        { name: "Ed25519" },
        this.keyPair.privateKey,
        // Domain separation: the signature covers "\x0Aic-request" || id, so a
        // signature over a request can never be replayed as a signature over
        // anything else the IC asks this key to sign.
        concat(new Uint8Array([10]), utf8("ic-request"), id)
      )
    );
    return { content, sender_pubkey: this.der, sender_sig: signature };
  }
}

// --- the agent ------------------------------------------------------------

export class RejectedError extends Error {
  constructor(code, message) {
    super(`canister rejected the request (code ${code}): ${message}`);
    this.code = code;
  }
}

export class Agent {
  /// `host` is the replica or gateway origin. Note that using a gateway makes
  /// it a trusted party for transport (T5 in THREAT_MODEL.md) until the
  /// certificate check in certificate.js is real.
  constructor({ host, canisterId, identity = new AnonymousIdentity() }) {
    this.host = host.replace(/\/$/, "");
    this.canisterId = canisterId;
    this.canisterBlob = principalToBytes(canisterId);
    this.identity = identity;
  }

  expiry() {
    return BigInt(Date.now()) * 1_000_000n + EXPIRY_NS;
  }

  async post(path, envelope) {
    const res = await fetch(`${this.host}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/cbor" },
      body: cbor.encode(envelope),
    });
    if (res.status !== 200 && res.status !== 202) {
      throw new Error(`${path} returned HTTP ${res.status}: ${await res.text()}`);
    }
    const body = new Uint8Array(await res.arrayBuffer());
    return body.length ? cbor.decode(body) : null;
  }

  async query(method, args = []) {
    const content = {
      request_type: "query",
      canister_id: this.canisterBlob,
      method_name: method,
      arg: candid.encodeArgs(args),
      sender: this.identity.principal,
      ingress_expiry: this.expiry(),
    };
    const envelope = await this.identity.transform(content);
    const reply = await this.post(`/api/v2/canister/${this.canisterId}/query`, envelope);
    const status = reply.get("status");
    if (status === "rejected") {
      throw new RejectedError(reply.get("reject_code"), reply.get("reject_message"));
    }
    if (status !== "replied") throw new Error(`unexpected query status '${status}'`);
    return candid.decodeOne(reply.get("reply").get("arg"), principalToText);
  }

  async readState(paths) {
    const content = {
      request_type: "read_state",
      paths,
      sender: this.identity.principal,
      ingress_expiry: this.expiry(),
    };
    const envelope = await this.identity.transform(content);
    const reply = await this.post(`/api/v2/canister/${this.canisterId}/read_state`, envelope);
    return reply.get("certificate");
  }

  /// Submit an update call and poll until it resolves.
  ///
  /// Deliberately uses the v2 submit + read_state polling path rather than
  /// v3's synchronous reply: the result then arrives inside a certificate we
  /// parse ourselves, which is the same object the verifier reasons about.
  /// One code path, one thing to review.
  async call(method, args = [], { timeoutMs = 30_000, intervalMs = 500 } = {}) {
    const content = {
      request_type: "call",
      canister_id: this.canisterBlob,
      method_name: method,
      arg: candid.encodeArgs(args),
      sender: this.identity.principal,
      ingress_expiry: this.expiry(),
      nonce: crypto.getRandomValues(new Uint8Array(16)),
    };
    const id = requestId(content);
    const envelope = await this.identity.transform(content);
    await this.post(`/api/v2/canister/${this.canisterId}/call`, envelope);

    const deadline = Date.now() + timeoutMs;
    for (;;) {
      // Path segments are blobs, not text: the IC hashes them as byte strings
      // and a CBOR text segment produces a different request that reads
      // nothing.
      const certBytes = await this.readState([[utf8("request_status"), id]]);
      const cert = parseCertificate(certBytes);
      const statusBytes = lookupPath(cert.tree, ["request_status", id, "status"]);
      const status = statusBytes ? new TextDecoder().decode(statusBytes) : null;
      if (status === "replied") {
        const arg = lookupPath(cert.tree, ["request_status", id, "reply"]);
        return { value: candid.decodeOne(arg, principalToText), certificate: certBytes };
      }
      if (status === "rejected") {
        const code = lookupPath(cert.tree, ["request_status", id, "reject_code"]);
        const msg = lookupPath(cert.tree, ["request_status", id, "reject_message"]);
        throw new RejectedError(
          code ? code[0] : "?",
          msg ? new TextDecoder().decode(msg) : "no message"
        );
      }
      if (status === "done") {
        throw new Error("call resolved before we read it; the reply is no longer retrievable");
      }
      if (Date.now() > deadline) throw new Error(`call to ${method} did not resolve in ${timeoutMs}ms`);
      await new Promise((r) => setTimeout(r, intervalMs));
    }
  }

  /// Certified module hash of an arbitrary canister -- the read ic-git's
  /// attestation flow is built on. The certificate comes back unverified; see
  /// certificate.js.
  async readModuleHash(canisterIdText) {
    const blob = principalToBytes(canisterIdText);
    const content = {
      request_type: "read_state",
      paths: [[utf8("canister"), blob, utf8("module_hash")]],
      sender: this.identity.principal,
      ingress_expiry: this.expiry(),
    };
    const envelope = await this.identity.transform(content);
    const reply = await this.post(`/api/v2/canister/${canisterIdText}/read_state`, envelope);
    return reply.get("certificate");
  }
}
