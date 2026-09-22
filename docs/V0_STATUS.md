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
| Trustee K-of-N gate on opening and closing (the `ic-multisig` crate, shared with ic-git) | `state.rs::set_trustees`, `approve`, `open`, `close` | `opening_waits_for_k_trustees_to_approve_the_manifest`, `closing_waits_for_trustees_to_attest_the_count`; check H in `tools/verify-election.mjs`; 4 tamper cases |
| Domain-separated, length-prefixed hash rules | `canisters/poll/src/hashing.rs` | property tests over every tree shape |
| Manifest freezing (question, options, roll, pin, trustees) at open | `state.rs::open` | `roll_and_pin_are_frozen_once_open`, `manifest_is_readable_in_draft_and_is_what_open_freezes` |
| Hash-chained public ballot log + voter receipt | `state.rs::cast` | `log_chain_is_recomputable_from_the_published_log` |
| Caller-blind cast: in-ballot Ed25519 credential, single-use transport key (THREAT_MODEL.md 2.7) | `state.rs::cast`, `credential.rs`, `site/app.js::onCast` | `franchise_is_recomputable_from_the_published_log`; live test asserts the receipt names the credential, not the transport |
| Merkle root over elections in `certified_data` | `state.rs::certified_root` | `witness_ties_each_election_to_the_certified_root` |
| Independent CLI verifier (2nd implementation) | `tools/verify-election.mjs` | 22 tamper cases in `tools/tamper-test.sh` |
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
  uploading rolls, pinning releases and naming trustees decide *who may vote*
  and *who may certify the count*, and should not be reachable from a page a
  voter can be phished onto. They are CLI operations. So is a trustee's
  `approve`: it takes a variant and a bool, which the encoder also refuses,
  and `get_approvals` takes only the election id so the page can still
  *read* the trustee record without the encoder growing to write it.

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

## Trustees: the K-of-N that is built, and the one that is not

There are two K-of-N approvals in this design, and only one of them exists.

**Built: trustees gating the election lifecycle.** An election's manifest
names a list of trustees and a threshold K. The administrator cannot open the
window until K trustees have approved the **manifest hash**, and cannot close
it until K trustees have approved the **tally hash**. Both are hashes this
canister already published and every verifier already recomputed; a trustee
approves bytes, not a step label, and a trustee who approves the close is
attesting the count. The rules -- who counts, one ballot per trustee, later
ballots replacing earlier ones, threshold reached or not -- are the
[`ic-multisig`](https://github.com/DrJesseGlass/ic-multisig) crate, the same
code ic-git's voters use to gate its deploy queue, pinned to the same tag.
The trustee is the caller of `approve`; the IC authenticates the envelope,
and no signature travels in the call (the crate's *authenticated* flavour).

What that establishes, stated exactly:

- The trustee list and threshold are **inside the manifest hash**, so the
  policy a voter's client checks is the policy the trustees approved. Editing
  either after the fact is a RED at check B, like editing the question.
- Approvals bind to the subject as it stood. Edit the draft's roll after a
  trustee approved the manifest, or let one more ballot land after the
  trustees approved the count, and the approvals stop counting: the subject
  moved. `close_election` is refused until the trustees have looked at the
  count that will actually be published. Nobody attests a count they did not
  see.
- Threshold zero, the default for every election, is the previous behaviour:
  administrator alone. Existing tooling and elections are unaffected.
- The trustee ballots are public (`get_approvals`), and both verifiers count
  them from the published record against their **own** recomputed tally hash
  and their own reading of the manifest, never from the canister's summary.
  A closed election whose count fewer than K trustees approved is a FAIL at
  check H.

What it does **not** establish:

- That the trustee record is genuine. These are the crate's *authenticated*
  approvals: the IC authenticated each trustee's envelope when it was cast,
  but the stored ballot carries no signature, and `certified_data` commits to
  `(id, manifest_hash, log_head, ballot_count)` -- not to the trustee record.
  A dishonest canister can therefore serve a trustee record it invented, and
  check H would pass it. Check H catches an *inconsistent bulletin* --
  approvals on some other tally, a ballot from an outsider, a missing quorum
  -- not a lying canister, and its PASS line says so. Making it independently
  checkable needs either the crate's *signed* flavour or the record inside
  `certified_data`; neither is built.
- That the *opening* was approved. Both verifiers read only the `Close`
  stage, so the manifest gate is enforced by the canister alone and is not
  recomputed anywhere.
- Who the trustees are. The administrator names them, in Draft, exactly as
  they upload the roll. This is the T4 boundary again, published so members
  can audit it, not removed.
- Anything about the code. This is not the K-of-N on
  `Pin.poll_module_sha256`, which remains **unbuilt** (ic-git dependency 2).
  That one needs the crate's *signed* flavour -- independent verifiers
  signing a module hash so a browser that never talks to this canister can
  count them against the keyset in `config.js` -- and the JavaScript tally
  that both projects will share is on the crate's roadmap, not in this repo.
  `config.trusted.verifiers` is still empty, and the page still cannot show
  GREEN.

**One correction recorded here, in the same spirit as the one above.** The
manifest hash used to include `opened_at`, the time of the `open_election`
call. That made the hash unknowable until the very call it now gates, so
trustees could not have approved it in advance. It was removed, and the
manifest's domain string moved with it (`ic-vote/v0/manifest-trustees`, the
rule `hashing.rs` states for every format change). Nothing was lost: the
election id already distinguishes two elections on one canister, and the
signed ballot message binds the canister principal, so no ballot can move
between elections or canisters. The opening time is still published in the
election view; it is lifecycle metadata, not a commitment. The stable-state
format is v3 and, like v2 before it, refuses to migrate an older state rather
than publish boards its own verifiers would reject.

## Known rough edges

- The `site` canister in `dfx.json` is dfx's asset canister, for local
  development only. The real deployment path is a push to ic-git, served from
  the git canister and recorded as `<repo>#site` -- which is the whole point of
  the repo being separate (README.md).
- `config.pollCanisterId` is `null` and must be set at deploy time. Until then
  the page reports RED with "nothing to verify", which is the right thing for
  it to say.
- No CI. `tools/check.sh` is the thing CI should run.
