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
| Election lifecycle, roll, one-ballot-per-credential | `canisters/poll/src/state.rs` | 35 unit tests |
| Domain-separated, length-prefixed hash rules | `canisters/poll/src/hashing.rs` | property tests over every tree shape |
| Manifest freezing (question, options, roll, pin) at open | `state.rs::open` | `roll_and_pin_are_frozen_once_open` |
| Hash-chained public ballot log + voter receipt | `state.rs::cast` | `log_chain_is_recomputable_from_the_published_log` |
| Caller-blind cast: in-ballot Ed25519 credential, single-use transport key (THREAT_MODEL.md 2.7) | `state.rs::cast`, `credential.rs`, `site/app.js::onCast` | `franchise_is_recomputable_from_the_published_log`; live test asserts the receipt names the credential, not the transport |
| Merkle root over elections in `certified_data` | `state.rs::certified_root` | `witness_ties_each_election_to_the_certified_root` |
| Independent CLI verifier (2nd implementation) | `tools/verify-election.mjs` | 18 tamper cases in `tools/tamper-test.sh` |
| Hand-written IC agent (CBOR, candid, Ed25519) | `site/lib/` | live-replica tests |
| Browser-side board recomputation (3rd implementation) | `site/lib/election-hash.js` | agrees with canister + CLI on live data |
| GREEN/YELLOW/RED verdict rules | `site/lib/verifier.js` | 17 rule tests |
| Ballot gate driven by the verdict | `site/app.js` | RED blocks; YELLOW requires acknowledgement |

Run it all: `tools/check.sh --live`.

## Deliberately absent

- **Ballot secrecy.** V0 is a public-ballot system on purpose (ROADMAP.md V0).
  Every ballot is attributable -- by its published credential, no longer by
  the message caller -- and the replicas can read all of it. Deploying this
  for a secret ballot is a misuse.
- **Re-voting.** Lands in V1 with the tally design, not before. On a public
  append-only log, "last ballot counts" would publish the fact that a voter
  changed their mind -- which is precisely the voter it is meant to protect.
- **Administrative calls from the browser.** `site/lib/candid.js` encodes only
  `nat32`/`nat64`/`blob` and refuses everything else. Creating elections,
  uploading rolls and pinning releases decide *who may vote*, and should not be
  reachable from a page a voter can be phished onto. They are CLI operations.

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

## The controller is a party (T7), and there are two of them

Whoever deploys a canister is its controller, and a controller can upgrade it.
There are **two** canisters here, with different controllers and different
powers, and an earlier version of this section conflated them:

- the **site canister** serves the ballot bundle. Its controller can change
  what the voter sees.
- the **poll canister** holds the roll, the log and the tally. Its controller
  can change what the ballots *mean*.

The election's pin now names a module hash for each: `Pin.module_sha256` for
the site canister and `Pin.poll_module_sha256` for the poll canister, both
frozen into the manifest hash when the window opens, both compared against a
certified read by `site/lib/verifier.js`. A mismatch on either is RED and the
ballot is blocked.

**This is a correction, not a description of what was always true.** Until it
was fixed, the pin carried only the site canister's hash while this document
claimed it covered the poll canister too. Nothing read the poll canister's
module hash at all, so a controller could have replaced the ballot-counting
code mid-election with no change to any verdict a voter saw. It was found by
review, and it is recorded here rather than quietly patched because a status
document that hides its own corrections is not worth reading.

What the pin does and does not establish, stated exactly:

- It makes a mid-window **change** visible. That is THREAT_MODEL.md 2.5.
- It does **not** establish the starting point. The pinned hash is a value the
  administrator declares; nothing yet proves it was the right one. That is what
  K-of-N attestation is for, and the trusted verifier set is empty.

Three consequences worth stating plainly:

1. Containment is only as good as the module-hash read, and that read is
   currently capped at UNKNOWN because the certificate is unauthenticated (see
   above). Until ic-git dependency 1 lands, an upgrade is *suspected*, not
   detected.
2. **A read that fails is treated more softly than a read that mismatches.** A
   mismatch is BAD, so RED, so the ballot is blocked. A read that cannot
   complete at all is UNKNOWN, so YELLOW, which the UI lets a voter click past
   after an acknowledgement. An attacker who can make the read fail therefore
   gets a better outcome than one who lets it succeed. Closing this means
   deciding that an open voting window should hard-block on an unreachable
   canister, which is a change to the verdict ladder in THREAT_MODEL.md section
   4 and has not been made.
3. Because the controller matters, `tools/check.sh` gives the deployer and the
   administrator **separate** identities: an administrator who can also upgrade
   the canister is not the "availability only" party T6 describes. The check
   asserts the resulting controller set for both canisters and fails the run on
   an unexpected one, rather than printing it and hoping someone reads the
   scrollback.

Every script under `tools/` passes `--identity` explicitly rather than
inheriting the ambient `dfx` selection, including `verify-election.mjs`'s
`dfx canister call` transport, and none of them calls `dfx identity use`, so
none can mutate the operator's selected identity. An early run of these scripts
deployed under an ambient identity nobody had chosen for the purpose, which is
exactly how a canister ends up with a controller no one can account for.

The identities the local checks create are prefixed `icvote-localtest-` and are
created only when absent. The prefix matters: an earlier version auto-created
an unencrypted key under a name this document simultaneously recommended for
real deployments, so a run of the test suite could either mint a plaintext copy
of a production-sounding key or silently deploy under an operator's real one.
`tools/check.sh` deploys only to a local replica it wipes; it is not a
deployment tool.

## Known rough edges

- The `site` canister in `dfx.json` is dfx's asset canister, for local
  development only. The real deployment path is a push to ic-git, served from
  the git canister and recorded as `<repo>#site` -- which is the whole point of
  the repo being separate (README.md).
- `config.pollCanisterId` is `null` and must be set at deploy time. Until then
  the page reports RED with "nothing to verify", which is the right thing for
  it to say.
- No CI. `tools/check.sh` is the thing CI should run.
