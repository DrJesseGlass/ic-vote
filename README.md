# ic-vote

End-to-end verifiable voting on the Internet Computer, built as the first
external consumer of [ic-git](https://github.com/DrJesseGlass/ic-git)'s
provenance stack.

**Status: V0 building.** The poll canister, the independent verifier, and the
voter-facing bundle with its provenance gate exist and are tested end to end
against a local replica. The page **cannot currently show GREEN**, on purpose:
the certificate-signature check it would need is an ic-git dependency that is
not built, and an unverifiable input caps the verdict rather than being
ignored. See [docs/V0_STATUS.md](docs/V0_STATUS.md) for exactly what is built,
what is stubbed, and what each stub does instead.

    tools/check.sh --live

## The one-sentence claim

Every remote e-voting system in the literature assumes the voting client is
honest; ic-vote is the first that lets a voter *check* it, because the ballot
page is served by an attested canister from an attested commit.

See [VISION.md](VISION.md) for why that assumption is the open problem, and
[THREAT_MODEL.md](THREAT_MODEL.md) for what this does and does not buy.

## Why this is a separate repo

ic-git is infrastructure; ic-vote is an application that consumes it. If the
voting app lived inside the ic-git tree it would be an *example* -- and
examples get special-cased, reach into internals, and prove nothing. Living
here, hosted by the mainnet git canister, deployed by its push pipeline, and
attested in its ProvenanceRegistry, ic-vote is a *customer*. That forces every
ic-git interface to be real and is the first evidence the stack works for
someone who is not ic-git.

This repo is therefore meant to be pushed to and served from ic-git, not
deployed by hand. Two scripts do it, and neither needs dfx or a key:
everything a wallet can do is done in the ic-git console, signed in as
the wallet that owns the repo -- create the repo, create its app canister,
set "deploy on push" to `app.wasm`, set "serve as site" to `site`, mint a
push token -- and `tools/push-ic-git.sh --repo NAME` does the rest with
the token: it stages `dist/` (`tools/stage-ic-git.sh`: `app.wasm` for
the deploy queue, `site/` rendered for that deployment with the poll
canister's id in `config.js` and an `integrity` hash on each file
`index.html` loads, and the sources that reproduce the wasm), commits it
on top of the repo's tip, pushes, and watches `/api/NAME/deploys` until
the install reports. The ballot page is then at `/site/NAME/` on ic-git
and the poll canister is the repo's app canister.

## Documents

| File | What it holds |
|---|---|
| [VISION.md](VISION.md) | The argument: cast-as-intended, the 20-year gap, what ic-git changes |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Enumerated trust set; coercion resistance stated honestly |
| [ROADMAP.md](ROADMAP.md) | The V0-V3 ladder, with verified IC primitive status |
| [docs/V0_STATUS.md](docs/V0_STATUS.md) | What is built vs. stubbed, and how each stub fails closed |

## Layout

| Path | What it is |
|---|---|
| `canisters/poll/` | The poll canister: roll, ballot box, hash-chained public log, certified Merkle root |
| `site/` | The voter-facing bundle. No build step and no npm dependencies, so the served bytes are the reviewed source |
| `site/lib/` | Hand-written primitives: sha256, keccak256, CBOR, candid, IC agent, certificate reader, verdict rules |
| `tools/` | Independent verifier, tamper tests, end-to-end demo, `check.sh` |

## Target, stated up front

Organizational votes -- co-ops, unions, professional associations,
shareholder meetings, DAOs -- **not** binding government elections. The
reasoning is in THREAT_MODEL.md; the short version is that rolls already
exist, the incumbent is an unverifiable SaaS ballot box, and the coercion
trade-off is one those organizations already make with mail ballots.
