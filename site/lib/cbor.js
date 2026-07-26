// CBOR, restricted to the subset the IC's HTTP interface actually uses:
// unsigned ints, byte strings, text strings, arrays, maps with text keys, the
// self-describe tag, and the three simple values. Floats and negative integers
// are not in the subset and throw.
//
// Indefinite-length items ARE in the subset, on evidence rather than
// assumption: a local replica returns query replies as indefinite-length maps
// (major type 5, additional info 31, terminated by a break byte). An earlier
// version of this file excluded them on the theory that the IC only emits
// definite lengths, and every query failed. Encoding stays definite-length --
// we only have to be understood, not to imitate.

export function encode(value) {
  const chunks = [];
  write(value, chunks);
  let n = 0;
  for (const c of chunks) n += c.length;
  const out = new Uint8Array(n);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

function head(major, arg, chunks) {
  const n = BigInt(arg);
  if (n < 24n) {
    chunks.push(new Uint8Array([(major << 5) | Number(n)]));
  } else if (n < 0x100n) {
    chunks.push(new Uint8Array([(major << 5) | 24, Number(n)]));
  } else if (n < 0x10000n) {
    chunks.push(new Uint8Array([(major << 5) | 25, Number(n >> 8n), Number(n & 0xffn)]));
  } else if (n < 0x100000000n) {
    const b = new Uint8Array(5);
    b[0] = (major << 5) | 26;
    new DataView(b.buffer).setUint32(1, Number(n));
    chunks.push(b);
  } else {
    const b = new Uint8Array(9);
    b[0] = (major << 5) | 27;
    new DataView(b.buffer).setBigUint64(1, n);
    chunks.push(b);
  }
}

function write(value, chunks) {
  if (typeof value === "bigint" || typeof value === "number") {
    if (value < 0) throw new Error("negative integers are not in the CBOR subset");
    if (typeof value === "number" && !Number.isSafeInteger(value)) {
      throw new Error(`unsafe integer ${value}: pass a BigInt`);
    }
    return head(0, value, chunks);
  }
  if (value instanceof Uint8Array) {
    head(2, value.length, chunks);
    return chunks.push(value);
  }
  if (typeof value === "string") {
    const bytes = new TextEncoder().encode(value);
    head(3, bytes.length, chunks);
    return chunks.push(bytes);
  }
  if (Array.isArray(value)) {
    head(4, value.length, chunks);
    for (const v of value) write(v, chunks);
    return;
  }
  if (value instanceof Map) {
    head(5, value.size, chunks);
    for (const [k, v] of value) {
      write(k, chunks);
      write(v, chunks);
    }
    return;
  }
  if (value && typeof value === "object") {
    const entries = Object.entries(value).filter(([, v]) => v !== undefined);
    head(5, entries.length, chunks);
    for (const [k, v] of entries) {
      write(k, chunks);
      write(v, chunks);
    }
    return;
  }
  throw new Error(`cannot CBOR-encode ${typeof value}`);
}

export function decode(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let i = 0;

  const need = (n) => {
    if (i + n > bytes.length) throw new Error("truncated CBOR");
  };

  function argument(ai) {
    if (ai < 24) return BigInt(ai);
    if (ai === 24) { need(1); return BigInt(bytes[i++]); }
    if (ai === 25) { need(2); const v = BigInt(view.getUint16(i)); i += 2; return v; }
    if (ai === 26) { need(4); const v = BigInt(view.getUint32(i)); i += 4; return v; }
    if (ai === 27) { need(8); const v = view.getBigUint64(i); i += 8; return v; }
    // 28..30 are reserved. 31 (indefinite) is handled by the caller, which
    // must check for it before asking for a length that does not exist.
    throw new Error(`unsupported CBOR additional info ${ai}`);
  }

  const BREAK = 0xff;
  const atBreak = () => {
    need(1);
    return bytes[i] === BREAK;
  };

  function value() {
    need(1);
    const b = bytes[i++];
    const major = b >> 5;
    const ai = b & 0x1f;
    switch (major) {
      case 0:
        return argument(ai);
      case 2: {
        if (ai === 31) {
          // Indefinite byte string: a sequence of definite-length chunks.
          const chunks = [];
          let total = 0;
          while (!atBreak()) {
            const chunk = value();
            if (!(chunk instanceof Uint8Array)) throw new Error("bad chunk in indefinite bytes");
            chunks.push(chunk);
            total += chunk.length;
          }
          i++;
          const out = new Uint8Array(total);
          let off = 0;
          for (const c of chunks) {
            out.set(c, off);
            off += c.length;
          }
          return out;
        }
        const n = Number(argument(ai));
        need(n);
        const v = bytes.subarray(i, i + n);
        i += n;
        return v;
      }
      case 3: {
        if (ai === 31) {
          let out = "";
          while (!atBreak()) out += value();
          i++;
          return out;
        }
        const n = Number(argument(ai));
        need(n);
        const v = new TextDecoder().decode(bytes.subarray(i, i + n));
        i += n;
        return v;
      }
      case 4: {
        const arr = [];
        if (ai === 31) {
          while (!atBreak()) arr.push(value());
          i++;
          return arr;
        }
        const n = Number(argument(ai));
        for (let k = 0; k < n; k++) arr.push(value());
        return arr;
      }
      case 5: {
        const m = new Map();
        const put = () => {
          const key = value();
          m.set(typeof key === "string" ? key : String(key), value());
        };
        if (ai === 31) {
          while (!atBreak()) put();
          i++;
          return m;
        }
        const n = Number(argument(ai));
        for (let k = 0; k < n; k++) put();
        return m;
      }
      case 6:
        // Tags (notably the 55799 self-describe prefix on certificates) carry
        // no information we act on; decode straight through to the payload.
        argument(ai);
        return value();
      case 7:
        if (ai === 20) return false;
        if (ai === 21) return true;
        if (ai === 22) return null;
        if (ai === 23) return undefined;
        throw new Error(`unsupported CBOR simple value ${ai}`);
      default:
        throw new Error(`unsupported CBOR major type ${major}`);
    }
  }

  const out = value();
  if (i !== bytes.length) throw new Error(`${bytes.length - i} trailing bytes after CBOR value`);
  return out;
}
