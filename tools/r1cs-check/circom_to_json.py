#!/usr/bin/env python3
"""Convert Circom's compiled output into the JSON r1cs_check.py consumes.

This is the piece that turns "the screen exists" into "the screen has been run
against a real constraint system". Circom emits a binary `.r1cs` (iden3 format)
plus an optional `.sym` name table; r1cs_check.py reads a small JSON. Nothing
here is Circom-specific beyond the parsing -- point it at any toolchain that
emits the same container.

    circom circuit.circom --r1cs --sym
    ./circom_to_json.py circuit.r1cs -o circuit.json
    ./r1cs_check.py circuit.json

WHICH SIGNALS BECOME `inputs` -- the one judgement call in this file.

All declared inputs, public and private. That is the property Picus and Ecne
check and it is the right one: it asks whether the circuit computes a *function*
of its inputs, and under-constraining is exactly the failure of that. Excluding
private inputs would be stricter but useless -- a hash-preimage circuit's output
is genuinely not determined by its public inputs alone, so every real circuit
would flag.

What that property does NOT cover, and it matters when reading a clean report:
determinism assumes the inputs are well-formed. A circuit can be perfectly
deterministic and still forgeable if a private input meant to be a bit is never
constrained to {0,1} -- the prover supplies 2 and gets a valid proof of a false
statement. The screen sees a function of its inputs and says ok. Range and
boolean constraints on inputs are a separate review item; see
docs/CIRCUIT_TESTING.md section 6.

WIRE LAYOUT. Circom's witness vector is ordered by convention, and the header
gives the counts rather than the boundaries:

    index 0                     the constant 1
    1 .. nPubOut                public outputs
    next nPubIn                 public inputs
    next nPrvIn                 private inputs
    remainder                   intermediate signals

Getting this wrong is silent: mislabel an intermediate as an input and the screen
assumes it fixed, which is precisely how a real under-constraining bug would be
hidden. `--selftest` pins the layout against two hand-built containers, one
sound and one deliberately broken, so a wrong offset fails loudly here rather
than showing up as an unexplained clean report later.

Usage:  circom_to_json.py FILE.r1cs [--sym FILE.sym] [-o OUT.json]
        circom_to_json.py --selftest
Exit:   0 ok, 2 bad input.
"""

import json
import os
import struct
import sys

MAGIC = b"r1cs"
SEC_HEADER = 1
SEC_CONSTRAINTS = 2


class R1csError(Exception):
    pass


def _u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0], off + 4


def _u64(buf, off):
    return struct.unpack_from("<Q", buf, off)[0], off + 8


def _fe(buf, off, size):
    """Field element: `size` bytes, little-endian."""
    return int.from_bytes(buf[off : off + size], "little"), off + size


def parse_r1cs(buf):
    """Parse an iden3 .r1cs container into a dict of its header + constraints."""
    if buf[:4] != MAGIC:
        raise R1csError("not an r1cs file (magic is %r, expected %r)" % (buf[:4], MAGIC))
    off = 4
    version, off = _u32(buf, off)
    n_sections, off = _u32(buf, off)

    # Sections may appear in any order and the constraints section cannot be
    # parsed without fieldSize from the header, so index them first.
    sections = {}
    for _ in range(n_sections):
        stype, off = _u32(buf, off)
        ssize, off = _u64(buf, off)
        sections.setdefault(stype, []).append((off, ssize))
        off += ssize

    if SEC_HEADER not in sections:
        raise R1csError("no header section (type 1)")
    if SEC_CONSTRAINTS not in sections:
        raise R1csError("no constraints section (type 2)")

    h_off, _ = sections[SEC_HEADER][0]
    field_size, h = _u32(buf, h_off)
    prime, h = _fe(buf, h, field_size)
    n_wires, h = _u32(buf, h)
    n_pub_out, h = _u32(buf, h)
    n_pub_in, h = _u32(buf, h)
    n_prv_in, h = _u32(buf, h)
    n_labels, h = _u64(buf, h)
    n_constraints, h = _u32(buf, h)

    c_off, c_size = sections[SEC_CONSTRAINTS][0]
    c = c_off
    constraints = []
    for i in range(n_constraints):
        abc = []
        for _ in range(3):
            nnz, c = _u32(buf, c)
            lc = {}
            for _ in range(nnz):
                wire, c = _u32(buf, c)
                val, c = _fe(buf, c, field_size)
                if wire >= n_wires:
                    raise R1csError(
                        "constraint %d references wire %d, past nWires=%d"
                        % (i, wire, n_wires)
                    )
                # Decimal strings, not ints: these are up to 254-bit values and
                # r1cs_check.py calls int() on them anyway, so this sidesteps
                # any JSON consumer that would round them.
                lc[str(wire)] = str(val)
            abc.append(lc)
        constraints.append({"a": abc[0], "b": abc[1], "c": abc[2]})
    if c > c_off + c_size:
        raise R1csError("constraints section overran its declared size")

    return {
        "version": version,
        "field_size": field_size,
        "prime": prime,
        "n_wires": n_wires,
        "n_pub_out": n_pub_out,
        "n_pub_in": n_pub_in,
        "n_prv_in": n_prv_in,
        "n_labels": n_labels,
        "constraints": constraints,
    }


def parse_sym(text):
    """wire index -> signal name, from Circom's `.sym`.

    Format is `labelId,wireId,componentId,name` per line. A wireId of -1 marks a
    signal the optimizer eliminated, and several labels can share one wire after
    substitution -- keep the first, which is the declared name rather than a
    generated alias.
    """
    names = {}
    for line in text.splitlines():
        parts = line.strip().split(",")
        if len(parts) < 4:
            continue
        try:
            wire = int(parts[1])
        except ValueError:
            continue
        if wire < 0:
            continue
        names.setdefault(wire, parts[3])
    return names


def to_check_json(r1cs, names=None):
    names = names or {}
    n_out, n_pub, n_prv = r1cs["n_pub_out"], r1cs["n_pub_in"], r1cs["n_prv_in"]

    outputs = list(range(1, 1 + n_out))
    pub_inputs = list(range(1 + n_out, 1 + n_out + n_pub))
    prv_inputs = list(range(1 + n_out + n_pub, 1 + n_out + n_pub + n_prv))

    if 1 + n_out + n_pub + n_prv > r1cs["n_wires"]:
        raise R1csError(
            "header is inconsistent: 1 + %d outputs + %d public + %d private "
            "exceeds nWires=%d" % (n_out, n_pub, n_prv, r1cs["n_wires"])
        )

    signals = []
    for i in range(r1cs["n_wires"]):
        if i == 0:
            signals.append("one")
        else:
            signals.append(names.get(i, "w%d" % i))

    return {
        "prime": str(r1cs["prime"]),
        "signals": signals,
        # Public and private together -- see the module docstring.
        "inputs": pub_inputs + prv_inputs,
        "outputs": outputs,
        "constraints": r1cs["constraints"],
    }


def summarise(r1cs, out_json, stream=sys.stderr):
    n_in = len(out_json["inputs"])
    quadratic = sum(1 for c in r1cs["constraints"] if c["a"] and c["b"])
    print(
        "wires %d | outputs %d | inputs %d (%d public, %d private) | "
        "constraints %d (%d quadratic, %d linear)"
        % (
            r1cs["n_wires"],
            r1cs["n_pub_out"],
            n_in,
            r1cs["n_pub_in"],
            r1cs["n_prv_in"],
            len(r1cs["constraints"]),
            quadratic,
            len(r1cs["constraints"]) - quadratic,
        ),
        file=stream,
    )
    if r1cs["n_pub_out"] == 0:
        print(
            "  warning: no declared outputs, so the screen has nothing to check",
            file=stream,
        )


# --------------------------------------------------------------------------
# Self-tests. Hand-built containers, so the wire layout is pinned without
# needing circom installed. One sound circuit and one under-constrained, run
# through r1cs_check itself -- a wrong offset here would otherwise surface much
# later as a clean report nobody could explain.
# --------------------------------------------------------------------------

BN254 = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def _build_r1cs(prime, n_wires, n_pub_out, n_pub_in, n_prv_in, constraints, fs=32):
    """Encode a minimal but format-correct .r1cs container."""

    def lc(d):
        out = struct.pack("<I", len(d))
        for wire, val in d.items():
            out += struct.pack("<I", wire) + (val % prime).to_bytes(fs, "little")
        return out

    header = (
        struct.pack("<I", fs)
        + prime.to_bytes(fs, "little")
        + struct.pack("<IIII", n_wires, n_pub_out, n_pub_in, n_prv_in)
        + struct.pack("<Q", n_wires)
        + struct.pack("<I", len(constraints))
    )
    body = b"".join(lc(a) + lc(b) + lc(c) for a, b, c in constraints)

    out = MAGIC + struct.pack("<II", 1, 2)
    for stype, data in ((SEC_HEADER, header), (SEC_CONSTRAINTS, body)):
        out += struct.pack("<I", stype) + struct.pack("<Q", len(data)) + data
    return out


def selftest():
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        import r1cs_check
    except ImportError as exc:
        print("cannot import r1cs_check.py from this directory: %s" % exc)
        return 2

    failures = 0

    # out = a * b. wire 0=one, 1=out, 2=a, 3=b.
    sound = _build_r1cs(BN254, 4, 1, 2, 0, [({2: 1}, {3: 1}, {1: 1})])
    # IsZero with the guard dropped: in*inv = 1 - out, and nothing pins inv.
    # wire 0=one, 1=out, 2=in, 3=inv (intermediate, NOT an input).
    broken = _build_r1cs(BN254, 4, 1, 1, 0, [({2: 1}, {3: 1}, {0: 1, 1: -1})])

    for label, blob, want_determined in (
        ("out = a*b (sound)", sound, True),
        ("iszero missing guard (BROKEN)", broken, False),
    ):
        r1cs = parse_r1cs(blob)
        spec = to_check_json(r1cs)
        circuit = r1cs_check.Circuit(spec)
        known = r1cs_check.analyse(circuit)
        determined = not (circuit.outputs - known)
        ok = determined == want_determined
        print(
            "  %-32s outputs=%s inputs=%s -> %s  %s"
            % (
                label,
                spec["outputs"],
                spec["inputs"],
                "DETERMINED" if determined else "UNDETERMINED",
                "ok" if ok else "!! expected the opposite",
            )
        )
        if not ok:
            failures += 1

    # The layout assertions that would silently corrupt every later report.
    r1cs = parse_r1cs(_build_r1cs(BN254, 6, 1, 2, 1, []))
    spec = to_check_json(r1cs)
    checks = [
        ("prime round-trips", int(spec["prime"]) == BN254),
        ("outputs are wires 1..nPubOut", spec["outputs"] == [1]),
        ("public then private inputs follow outputs", spec["inputs"] == [2, 3, 4]),
        ("wire 0 is the constant", spec["signals"][0] == "one"),
        ("intermediates are excluded from inputs", 5 not in spec["inputs"]),
    ]
    for label, ok in checks:
        print("  %-32s %s" % (label, "ok" if ok else "!! FAILED"))
        if not ok:
            failures += 1

    print()
    if failures:
        print("selftest: %d check(s) failed" % failures)
        return 2
    print("selftest: wire layout and both circuits behaved as documented")
    return 0


def main(argv):
    args = argv[1:]
    if not args:
        print(__doc__.strip())
        return 2
    if args[0] == "--selftest":
        return selftest()

    path, sym_path, out_path = None, None, None
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--sym":
            i += 1
            sym_path = args[i] if i < len(args) else None
        elif a in ("-o", "--out"):
            i += 1
            out_path = args[i] if i < len(args) else None
        elif path is None:
            path = a
        else:
            print("unexpected argument %r" % a)
            return 2
        i += 1

    if not path:
        print("need a .r1cs file")
        return 2
    # Convenience: circom emits circuit.r1cs and circuit.sym side by side.
    if sym_path is None:
        guess = os.path.splitext(path)[0] + ".sym"
        if os.path.exists(guess):
            sym_path = guess

    try:
        with open(path, "rb") as fh:
            r1cs = parse_r1cs(fh.read())
        names = None
        if sym_path:
            with open(sym_path) as fh:
                names = parse_sym(fh.read())
        spec = to_check_json(r1cs, names)
    except (OSError, R1csError, struct.error) as exc:
        print("%s: %s" % (path, exc))
        return 2

    summarise(r1cs, spec)
    if sym_path:
        print("  names from %s" % sym_path, file=sys.stderr)

    text = json.dumps(spec, indent=1)
    if out_path:
        with open(out_path, "w") as fh:
            fh.write(text + "\n")
        print("  wrote %s" % out_path, file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
