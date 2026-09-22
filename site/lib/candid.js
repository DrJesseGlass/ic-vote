// Candid: a general decoder, and an encoder for exactly the argument types
// this frontend sends.
//
// The asymmetry is deliberate. Decoding has to be general because the poll
// canister's replies are records of records of variants and we must read all
// of them. Encoding does not: the voter-facing app calls
// `cast(nat64, nat32, blob, blob)` and paginated queries over `nat64`, so the
// encoder supports nat32/nat64/blob and refuses everything else loudly.
// Administration (creating elections, uploading rolls, pinning releases) is
// deliberately CLI-only in V0 -- it is the operation that decides who may
// vote, and it should not be reachable from a web page a voter can be phished
// onto.

const PRIM = {
  "-1": "null",
  "-2": "bool",
  "-3": "nat",
  "-4": "int",
  "-5": "nat8",
  "-6": "nat16",
  "-7": "nat32",
  "-8": "nat64",
  "-9": "int8",
  "-10": "int16",
  "-11": "int32",
  "-12": "int64",
  "-13": "float32",
  "-14": "float64",
  "-15": "text",
  "-16": "reserved",
  "-17": "empty",
  "-24": "principal",
};
const OPT = -18;
const VEC = -19;
const RECORD = -20;
const VARIANT = -21;
const FUNC = -22;
const SERVICE = -23;

const MAGIC = [0x44, 0x49, 0x44, 0x4c]; // "DIDL"

/// Candid's field-name hash. Only the hash travels on the wire, so names are
/// recovered by hashing a caller-supplied dictionary and matching.
export function fieldHash(name) {
  let h = 0;
  for (const byte of new TextEncoder().encode(name)) {
    h = (Math.imul(h, 223) + byte) >>> 0;
  }
  return h;
}

/// Every field and variant label in poll.did. A name missing here decodes to
/// `_<hash>_`, which is visible in the UI as a broken field rather than
/// silently dropped -- the same reason the canister's .did is pinned by a
/// test.
export const POLL_NAMES = [
  "Ok", "Err",
  "Draft", "Open", "Closed",
  "NotFound", "NotAdmin", "NotTrustee", "NotApproved", "WrongPhase", "EmptyRoll",
  "NoPin", "NotEligible", "AlreadyVoted", "InvalidChoice", "AnonymousCaller",
  "InvalidSignature", "SignatureExpired", "InvalidInput",
  "expected", "actual",
  "id", "title", "question", "options", "admin", "phase", "created_at",
  "opened_at", "closed_at", "pin", "roll_size", "ballot_count",
  "trustees", "threshold",
  // Stage::Open shares its label with Phase::Open above.
  "Close", "stage", "subject", "ballots", "trustee", "approve",
  "approvals", "rejections", "required", "reached",
  "manifest_hash", "log_head", "roll_hash", "tally_hash", "counts",
  "election_id", "seq", "voter", "voter_pubkey", "choice", "at", "sig",
  "sig_expires_at", "entry_hash",
  "witness", "sibling", "sibling_is_right", "certificate",
  "repo", "commit", "bundle_sha256", "site_canister", "module_sha256",
  "poll_module_sha256", "registry_chain_id", "registry_address",
];

let NAME_BY_HASH = null;
function nameOf(hash) {
  if (!NAME_BY_HASH) {
    NAME_BY_HASH = new Map();
    for (const n of POLL_NAMES) NAME_BY_HASH.set(fieldHash(n), n);
  }
  return NAME_BY_HASH.get(hash) ?? `_${hash}_`;
}

// --- encoding -------------------------------------------------------------

function leb(nBig) {
  let n = BigInt(nBig);
  const out = [];
  do {
    let byte = Number(n & 0x7fn);
    n >>= 7n;
    if (n !== 0n) byte |= 0x80;
    out.push(byte);
  } while (n !== 0n);
  return out;
}

function sleb(nBig) {
  let n = BigInt(nBig);
  const out = [];
  for (;;) {
    const byte = Number(n & 0x7fn);
    n >>= 7n;
    const signBit = (byte & 0x40) !== 0;
    if ((n === 0n && !signBit) || (n === -1n && signBit)) {
      out.push(byte);
      return out;
    }
    out.push(byte | 0x80);
  }
}

/// `args` is a list of [type, value] pairs, e.g. [["nat64", 3n]] or
/// [["blob", new Uint8Array([...])]].
export function encodeArgs(args) {
  const table = [];
  const types = [];
  const values = [];
  // `blob` is a constructed type (vec nat8), so it needs a type-table entry;
  // one entry is shared by every blob argument.
  let blobIndex = -1;
  for (const [type, value] of args) {
    switch (type) {
      case "nat64": {
        types.push(...sleb(-8));
        const b = new Uint8Array(8);
        new DataView(b.buffer).setBigUint64(0, BigInt(value), true);
        values.push(...b);
        break;
      }
      case "nat32": {
        types.push(...sleb(-7));
        const b = new Uint8Array(4);
        new DataView(b.buffer).setUint32(0, Number(value), true);
        values.push(...b);
        break;
      }
      case "blob": {
        if (!(value instanceof Uint8Array)) {
          throw new Error("blob arguments must be Uint8Array");
        }
        if (blobIndex < 0) {
          blobIndex = table.length;
          table.push([...sleb(VEC), ...sleb(-5)]);
        }
        types.push(...sleb(blobIndex));
        values.push(...leb(value.length), ...value);
        break;
      }
      default:
        throw new Error(
          `candid encoder does not support '${type}'. Administrative calls are ` +
            `CLI-only in V0 by design; see the note at the top of candid.js.`
        );
    }
  }
  return new Uint8Array([
    ...MAGIC,
    ...leb(table.length),
    ...table.flat(),
    ...leb(args.length),
    ...types,
    ...values,
  ]);
}

// --- decoding -------------------------------------------------------------

class Reader {
  constructor(bytes) {
    this.b = bytes;
    this.i = 0;
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }
  byte() {
    if (this.i >= this.b.length) throw new Error("truncated candid message");
    return this.b[this.i++];
  }
  take(n) {
    if (this.i + n > this.b.length) throw new Error("truncated candid message");
    const v = this.b.subarray(this.i, this.i + n);
    this.i += n;
    return v;
  }
  leb() {
    let result = 0n;
    let shift = 0n;
    for (;;) {
      const byte = this.byte();
      result |= BigInt(byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) return result;
      shift += 7n;
    }
  }
  sleb() {
    let result = 0n;
    let shift = 0n;
    for (;;) {
      const byte = this.byte();
      result |= BigInt(byte & 0x7f) << shift;
      shift += 7n;
      if ((byte & 0x80) === 0) {
        if (byte & 0x40) result -= 1n << shift;
        return result;
      }
    }
  }
}

function readTypeTable(r) {
  const count = Number(r.leb());
  const table = [];
  for (let i = 0; i < count; i++) {
    const op = Number(r.sleb());
    if (op === OPT || op === VEC) {
      table.push({ kind: op === OPT ? "opt" : "vec", inner: Number(r.sleb()) });
    } else if (op === RECORD || op === VARIANT) {
      const n = Number(r.leb());
      const fields = [];
      for (let k = 0; k < n; k++) {
        fields.push({ hash: Number(r.leb()), type: Number(r.sleb()) });
      }
      table.push({ kind: op === RECORD ? "record" : "variant", fields });
    } else if (op === FUNC) {
      // Skip: arg types, ret types, annotations. Never appears in our replies,
      // but a table entry we cannot skip would desynchronize everything after
      // it, so parse the shape rather than throwing.
      for (const _ of [0, 1]) {
        const n = Number(r.leb());
        for (let k = 0; k < n; k++) r.sleb();
      }
      const ann = Number(r.leb());
      for (let k = 0; k < ann; k++) r.byte();
      table.push({ kind: "func" });
    } else if (op === SERVICE) {
      const n = Number(r.leb());
      for (let k = 0; k < n; k++) {
        const nameLen = Number(r.leb());
        r.take(nameLen);
        r.sleb();
      }
      table.push({ kind: "service" });
    } else {
      throw new Error(`unsupported candid type constructor ${op}`);
    }
  }
  return table;
}

function readValue(r, type, table, principalToText) {
  if (type < 0) {
    const prim = PRIM[String(type)];
    switch (prim) {
      case "null":
      case "reserved":
        return null;
      case "bool": {
        const b = r.byte();
        if (b > 1) throw new Error(`invalid bool byte ${b}`);
        return b === 1;
      }
      case "nat":
        return r.leb();
      case "int":
        return r.sleb();
      case "nat8":
        return r.byte();
      case "nat16": {
        const v = r.view.getUint16(r.i, true);
        r.i += 2;
        return v;
      }
      case "nat32": {
        const v = r.view.getUint32(r.i, true);
        r.i += 4;
        return v;
      }
      case "nat64": {
        const v = r.view.getBigUint64(r.i, true);
        r.i += 8;
        return v;
      }
      case "int8": {
        const v = r.view.getInt8(r.i);
        r.i += 1;
        return v;
      }
      case "int16": {
        const v = r.view.getInt16(r.i, true);
        r.i += 2;
        return v;
      }
      case "int32": {
        const v = r.view.getInt32(r.i, true);
        r.i += 4;
        return v;
      }
      case "int64": {
        const v = r.view.getBigInt64(r.i, true);
        r.i += 8;
        return v;
      }
      case "text": {
        const n = Number(r.leb());
        return new TextDecoder().decode(r.take(n));
      }
      case "principal": {
        const tag = r.byte();
        // 0 would mean a transparent (opaque reference) id, which a canister
        // reply never contains.
        if (tag !== 1) throw new Error(`unsupported principal tag ${tag}`);
        const n = Number(r.leb());
        return principalToText(r.take(n));
      }
      case "empty":
        throw new Error("value of type 'empty' cannot exist");
      default:
        throw new Error(`unsupported candid primitive ${type}`);
    }
  }

  const entry = table[type];
  if (!entry) throw new Error(`type index ${type} is outside the type table`);
  switch (entry.kind) {
    case "opt": {
      const present = r.byte();
      if (present > 1) throw new Error(`invalid opt tag ${present}`);
      return present === 0 ? null : readValue(r, entry.inner, table, principalToText);
    }
    case "vec": {
      const n = Number(r.leb());
      // vec nat8 is candid's blob; hand it back as bytes rather than an array
      // of 20,000 numbers.
      if (entry.inner === -5) return r.take(n).slice();
      const out = [];
      for (let i = 0; i < n; i++) out.push(readValue(r, entry.inner, table, principalToText));
      return out;
    }
    case "record": {
      const out = {};
      // Fields arrive in the type table's order, which candid defines as
      // ascending field hash. Reading them in any other order desynchronizes
      // the value stream, so trust the table, not a guess about the .did.
      for (const f of entry.fields) {
        out[nameOf(f.hash)] = readValue(r, f.type, table, principalToText);
      }
      return out;
    }
    case "variant": {
      const idx = Number(r.leb());
      const f = entry.fields[idx];
      if (!f) throw new Error(`variant index ${idx} is out of range`);
      return { [nameOf(f.hash)]: readValue(r, f.type, table, principalToText) };
    }
    default:
      throw new Error(`cannot decode a value of kind '${entry.kind}'`);
  }
}

export function decodeArgs(bytes, principalToText) {
  const r = new Reader(bytes);
  for (const m of MAGIC) {
    if (r.byte() !== m) throw new Error("reply is not a candid message (bad DIDL magic)");
  }
  const table = readTypeTable(r);
  const n = Number(r.leb());
  const types = [];
  for (let i = 0; i < n; i++) types.push(Number(r.sleb()));
  const values = types.map((t) => readValue(r, t, table, principalToText));
  return values;
}

/// Convenience for the single-return methods this app calls.
export function decodeOne(bytes, principalToText) {
  const vals = decodeArgs(bytes, principalToText);
  if (vals.length !== 1) throw new Error(`expected 1 return value, got ${vals.length}`);
  return vals[0];
}
