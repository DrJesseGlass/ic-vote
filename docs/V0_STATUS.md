# V0 status: what is built, what is stubbed, and what that means

Companion to ROADMAP.md. That document says what V0 *is*; this one says how
much of it currently exists, and is written to the same rule as THREAT_MODEL.md
-- a mechanism may only ever be described as doing the specific thing it does.

Last updated with the first code commit.

## The dependency question, answered honestly

ROADMAP.md says nothing in ic-vote should start before ic-git dependency 1
(the certified module-hash reader) has a prototype, "because a failure there
changes the whole design."

That is still the right instinct, and this build does not pretend the
dependency is satisfied. What it does instead is make the dependency an
**explicit, named, fail-closed seam** rather than a reason to write nothing:

- `site/lib/certificate.js` reconstructs the IC hash tree, walks it, and reads
  `certified_data` and `module_hash` out of a real certificate. All of that
  needs only sha256 and is built and tested against live replica output.
- `verifySignature()` in that file returns `UNAVAILABLE`. It does not throw and
  it does not return true.
- `site/lib/verifier.js` treats `UNAVAILABLE` as capping the verdict below
  GREEN, structurally: the only function that moves the verdict is monotone
  downward, and "could not check" is a distinct state from "checked and fine".
- Consequently **this app cannot currently display GREEN**, and there is a test
  asserting exactly that
  (`unverified certificate cannot reach GREEN`).

If dependency 1 lands and works, `verifySignature` becomes real and no calling
code changes. If it lands and the design turns out to be wrong, the blast
radius is one file. That is the bet, stated so it can be judged.

## Built and exercised

| Piece | Where | Evidence |
|---|---|---|
| Election lifecycle, roll, one-ballot-per-identity | `canisters/poll/src/state.rs` | 26 unit tests |
| Domain-separated, length-prefixed hash rules | `canisters/poll/src/hashing.rs` | property tests over every tree shape |
| Manifest freezing (question, options, roll, pin) at open | `state.rs::open` | `roll_and_pin_are_frozen_once_open` |
| Hash-chained public ballot log + voter receipt | `state.rs::cast` | `log_chain_is_recomputable_from_the_published_log` |
| Merkle root over elections in `certified_data` | `state.rs::certified_root` | `witness_ties_each_election_to_the_certified_root` |
| Independent CLI verifier (2nd implementation) | `tools/verify-election.mjs` | 12 tamper cases in `tools/tamper-test.sh` |
| Hand-written IC agent (CBOR, candid, Ed25519) | `site/lib/` | live-replica tests |
| Browser-side board recomputation (3rd implementation) | `site/lib/election-hash.js` | agrees with canister + CLI on live data |
| GREEN/YELLOW/RED verdict rules | `site/lib/verifier.js` | 17 rule tests |
| Ballot gate driven by the verdict | `site/app.js` | RED blocks; YELLOW requires acknowledgement |

Run it all: `tools/check.sh --live`.

## Deliberately absent

- **Ballot secrecy.** V0 is a public-ballot system on purpose (ROADMAP.md V0).
  Every ballot is attributable to the principal that cast it, and the replicas
  can read all of it. Deploying this for a secret ballot is a misuse.
- **Re-voting.** Lands in V1 with the tally design, not before. On a public
  append-only log, "last ballot counts" would publish the fact that a voter
  changed their mind -- which is precisely the voter it is meant to protect.
- **Administrative calls from the browser.** `site/lib/candid.js` encodes only
  `nat32`/`nat64` and refuses everything else. Creating elections, uploading
  rolls and pinning releases decide *who may vote*, and should not be reachable
  from a page a voter can be phished onto. They are CLI operations.

## Stubbed, and what the stub does

| Gap | Blocked on | Current behaviour |
|---|---|---|
| BLS verification of IC certificates | ic-git dep. 1 | `UNAVAILABLE`; caps verdict below GREEN |
| Certificate freshness bound | same | `certificateTime()` parses it; not yet trustworthy, because an unsigned certificate can claim any time |
| Trusted verifier set | ic-git dep. 2 (`attest()` + K-of-N tooling) | **empty** in `config.js`; attestation check reports that nobody has attested, verdict RED |
| Real registry record for this repo | ic-git dep. 3 (`registry_publish_site` on mainnet) | `registrySite()` is implemented and reads a live chain; there is simply no record yet |
| Multi-chain registry | ic-git dep. 4 | `config.rpc` is a chain-id map; only the chain in the election's pin is read |
| Voter enrolment | T4, a governance question | demo Ed25519 key in `localStorage`, labelled as such in the UI |

The empty verifier set deserves a note. It would have been easy to put two
plausible addresses in `config.js` and get a page that renders confidently.
That page would verify nothing, which is the failure this project exists to
name. An empty set produces RED, and RED is correct.

## What a reviewer should look at first

1. `canisters/poll/src/hashing.rs` -- if the hash rules are wrong, everything
   downstream agrees on the wrong thing.
2. `site/lib/verifier.js` -- the verdict rules are the product.
3. `site/config.js` -- the trust anchors, which are inside the attested bundle
   on purpose.
4. `site/lib/agent.js`, `cbor.js`, `candid.js`, `sha256.js`, `keccak.js` --
   hand-written primitives. Small, but they are ours to be wrong about. Every
   one with a published test vector is pinned to it; `keccak.js` is
   cross-checked against Node's SHA3-256 because Ethereum's keccak has no
   reference implementation in any runtime we ship on.

## Known rough edges

- The `site` canister in `dfx.json` is dfx's asset canister, for local
  development only. The real deployment path is a push to ic-git, served from
  the git canister and recorded as `<repo>#site` -- which is the whole point of
  the repo being separate (README.md).
- `config.pollCanisterId` is `null` and must be set at deploy time. Until then
  the page reports RED with "nothing to verify", which is the right thing for
  it to say.
- No CI. `tools/check.sh` is the thing CI should run.
