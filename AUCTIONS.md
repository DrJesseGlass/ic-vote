# Sealed-bid auctions: the same stack, an easier problem

Companion to VISION.md (why a verifiable client matters), ROADMAP.md (the
voting rungs), and THREAT_MODEL.md. Written 2026-07-26, off the back of the
vetKD re-check that reordered the voting roadmap.

The short version: a sealed-bid second-price auction needs everything ic-vote
needs, needs *less* of it, and closes a trust gap that has a name, a citation,
and a documented history of killing the mechanism in practice. If the point of
V0 is to demonstrate the stack, this may be the better demonstration.

## 1. The fit test

A mechanism suits this stack when all three hold:

1. **Inputs must be secret before close.** Otherwise there is nothing for
   encryption to do and the whole design collapses to a public form.
2. **Full disclosure at close is acceptable, or even wanted.** This is the
   discriminator, and it is the one the voting roadmap failed.
3. **Eligibility is a closed roll, or is handled by collateral.** Otherwise
   you inherit the unsolved issuance problem (ROADMAP.md V2).

Secret-ballot voting fails (2) -- decrypting ballots at close republishes
voter-to-choice, which is why anonymity had to merge into V1. Ranked-choice
voting fails (2) hardest, because a published ranking is a fingerprint (see
ROADMAP.md, "why ranked ballots are not a free extension"). Sealed-bid
auctions pass all three: bids are routinely published after close *for
auditability*, and bidders identify themselves because they have to pay.

Others that pass, unexamined here: sealed procurement tenders, DAO treasury
sales, randomized/lottery allocation of a scarce good.

## 2. The trust gap, which is 35 years old and named

In a Vickrey (sealed-bid second-price) auction the highest bidder wins and
pays the *second*-highest bid. Truthful bidding is a dominant strategy, which
is why the mechanism is beloved in theory. It is rare in practice.

Rothkopf, Teisberg & Kahn, *Why Are Vickrey Auctions Rare?* (Journal of
Political Economy, 1990) give two reasons. The second is ours:

> **The auctioneer can cheat, and cannot be caught.** The auctioneer sees
> every sealed bid. Having seen them, they insert a phantom bid just below the
> winner's, so the winner pays nearly their full bid. The mechanism silently
> becomes a first-price auction and the entire bidder surplus goes to the
> seller. Nothing in the published outcome distinguishes this from an honest
> run.

Note the precondition: **the cheat requires seeing the bids before setting the
phantom one.** A shill bid placed blind is a real gamble -- overshoot and the
shill wins and must pay. The attack is risk-free only for someone who can
peek. That single observation is what makes this a cryptography problem with a
clean solution rather than an economics problem with a mitigation.

The modern instance is digital advertising, where the industry's move from
second-price to first-price exchanges around 2019 is widely attributed, in
part, to buyers being unable to verify that the auctioneer ran the mechanism
it described. A mechanism nobody can audit degrades to a mechanism nobody
trusts, and then it gets replaced by a worse one that at least does not
require trust.

## 3. What closes it

Four properties, three of which ic-vote already builds:

| Property | Mechanism | Status |
|---|---|---|
| The bidding page is the reviewed page | ic-git F0/F2 + K-of-N attestation | ic-vote V0 |
| Nobody sees bids before close, incl. the canister and seller | vetKD IBE / timelock to an auction identity | ic-vote V1 |
| Anyone can recompute the winner and the price | public bulletin board of decrypted bids | ic-vote V0 |
| The seller's reserve is not set after the fact | reserve committed before open, revealed at close | new, trivial |

The last row is small and easy to forget. A secret reserve price is
functionally a bid by the seller, so if it can be chosen after the bids are
visible it is the phantom-bid attack wearing a different hat. Commit it with
everything else.

Put together: the auctioneer cannot peek, so the informed phantom bid is
impossible; every bid is on a public board, so a blind shill bid is a matter
of public record and an accountable act; and the second-price computation is a
sort over published numbers that any observer can redo. The documented reason
Vickrey auctions are rare stops applying.

## 4. What gets easier than voting

- **No anonymity requirement.** The finding that reordered the voting roadmap
  -- decrypt-at-close reveals who chose what -- is simply not a problem here.
  Auctions publish bids afterward as a feature. So the original V1 scope
  (vetKD, nothing else) is sufficient, and the ZK membership machinery is
  optional rather than load-bearing.
- **No eligibility ladder.** Bidders self-identify because they must pay.
  Sybil resistance comes from collateral: a bid without a deposit is not
  binding. The hardest open problem in ROADMAP.md is absent.
- **No coercion problem.** The analogue is bid rings, which are an economics
  and law-enforcement matter, not a cryptographic one. Out of scope, and
  honestly so -- unlike voter coercion, nobody expects the protocol to fix it.
- **Cost is trivially small.** One `vetkd_derive_key` at close, ~$0.036 total
  (ROADMAP.md, verified 2026-07-26). Bidders pay nothing to encrypt.

## 5. What is actually hard

**Rothkopf's *other* reason survives, and this stack makes it worse.** Bidders
dislike revealing their true valuations even to an honest auctioneer, because
those valuations get used against them in the next negotiation. Publishing
every losing bid to an immutable public ledger is a stronger version of
exactly the thing they were avoiding. Three routes:

- **(A) Full disclosure.** Every bid public at close. Verification is a sort.
  Right for one-shot sales between parties with no ongoing relationship;
  wrong for repeat procurement where the same suppliers bid every quarter and
  the buyer accumulates a permanent map of their cost structure.
- **(B) Anonymous bidders.** Reuse ic-vote V1's machinery exactly: Merkle root
  of the qualified-bidder set, membership proof, nullifier, collateral posted
  per commitment. Valuations become public but unattributed; only the winner
  deanonymizes, because only the winner has to pay. Cheap *if* V1 exists,
  which is the argument for building these two things in the same repo.
- **(C) ZK second-price.** Publish only the clearing price plus a proof that
  it is the second-largest of the committed bids. Nothing else is revealed.
  This is what bidders actually want and it is the largest build -- it needs
  comparison and ranking proofs over ciphertexts. The interesting research
  direction; not a first version.

**The close is the fragile moment, again.** `vetkd_derive_key` is a
cross-subnet call that can exceed the replica's 10s synchronous window
(ROADMAP.md, footgun 2). An auction close is *more* timing-sensitive than an
election close, and the settlement path probably touches money. Design close
as asynchronous, resumable, and idempotent from the first commit.

**Upgrade control is load-bearing here too, and for a sharper reason.** A
controller who can upgrade the auction canister can add a derive-now path,
read the bids, and run the exact phantom-bid attack this design exists to
prevent -- against a mechanism whose entire pitch is that the attack is
impossible. Governance or blackhole before any auction with real money, and
the verifier should show the controller set next to the module hash. Same
residual as REPRODUCIBLE_BUILD.md's temporal-trust item, higher stakes.

**Non-payment.** The winner can walk. Collateral and forfeiture handle it, and
that is ordinary escrow design rather than anything novel -- but it is the
part that makes this a product instead of a demo, so budget for it.

## 6. Rungs

Deliberately parallel to ROADMAP.md, and reusing the same components.

**A0 -- attested client, commit-reveal.** Bidders publish `H(bid, nonce)` with
a deposit, then reveal after close. No vetKD, no new cryptography, ships on
exactly the V0 stack. Its known flaw is selective non-reveal: a bidder who
watches others reveal can refuse to open their own commitment, which is a
last-mover advantage that deposit forfeiture discourages but does not remove.
Worth building only as a stepping stone.

**A1 -- vetKD timelock.** Bids encrypted to the auction identity; at close a
single derivation opens all of them at once. There is no reveal phase, so the
non-reveal grief vector disappears entirely rather than being priced. This is
the real product, and it is a strictly smaller build than ic-vote V1 because
it needs no anonymity.

**A2 -- bidder privacy.** Option (B) or (C) from section 5, chosen per
deployment. (B) is nearly free once ic-vote V1 exists.

## 7. What DFINITY's timelock example actually does

Read on 2026-07-26 at `dfinity/examples`,
`rust/vetkeys/basic_timelock_ibe/backend/src/lib.rs`. Worth knowing that
DFINITY's canonical vetKD timelock example *is itself a sealed-bid auction*,
which is some evidence that this is the natural first application of the
primitive. It is also instructive about what the primitive does not give you.

**There is no timelock.** The IBE identity is `lot_id.to_le_bytes()` and the
context is a constant domain separator. No time enters the derivation
anywhere. The key for a lot is derivable from the instant the lot exists --
indeed before it exists, since the identity is just an integer. What holds the
bids closed is an `ic_cdk_timers` job that checks `deadline <= time()` and only
then calls `vetkd_derive_key`. The release condition is **an if-statement in
canister code**, not a cryptographic property.

So the name is aspirational. Real timelock encryption (drand's `tlock`, say)
binds the identity to a beacon round that no single party can accelerate.
This binds it to a branch that the canister's controller can rewrite.

That distinction is the entire question I flagged, and the answer is the
uncomfortable one:

> A controller who can upgrade the auction canister adds a `derive_now`
> method, upgrades, calls it, and reads every sealed bid. The subnet complies,
> because the canister is the one asking. Nothing is detectable from outside.

Which is to say **the example's core security property is a claim about which
code the canister is running, and the IC gives a bidder no way to check that
claim.** ic-git's backend attestation is exactly the missing piece. This is
the strongest validation of the stack's thesis I have found in someone else's
code, and it should be cited as such.

Three ways to get a release condition not held by one controller, in
increasing order of honesty:

1. **Blackhole the canister.** No controllers, code frozen, the timer branch
   is the only path to a key. Combined with an attested module hash this is a
   genuinely checkable timelock, and it is cheap. The cost is that the
   contract can never be fixed.
2. **A dedicated blackholed beacon canister** that derives and publishes keys
   for round numbers on a schedule, used by many auctions. Same guarantee,
   amortized, and a reusable public good.
3. **An external beacon** (drand / League of Entropy) via HTTPS outcalls.
   Removes the IC-controller dependency entirely at the cost of a new trust
   root outside the IC.

### Other things the example will teach you if you copy it

- **The client trusts the canister for the IBE public key.** The frontend does
  `DerivedPublicKey.deserialize(await backend.get_ibe_public_key())` and
  encrypts to whatever comes back. Since `vetkd_public_key` is not callable
  from ingress, a bidder cannot ask the IC directly -- but derivation is
  public, so the client can pin the master key and recompute the expected
  value offline. See ROADMAP.md. **Do this. The example does not.**
- **It is a first-price auction.** `close_lot` takes `max_by(amount)` and the
  winner pays their own bid. There is no second price anywhere in it, so the
  Vickrey mechanics in this document are ours to build, not to copy.
- **Undecryptable bids are silently dropped.** `filter_map` discards them with
  only an `ic_cdk::println!`. For money that is a silent-loss path; ported to
  voting it is silent disenfranchisement. Any ic-vote design must record
  undecryptable ballots *publicly* rather than filtering them out.
- **The transport secret key is seeded from 32 zero bytes.** Defensible
  inside the subnet trust boundary (T1), since the derived key never leaves
  the canister -- but it is not a pattern to carry anywhere else.
- **Shill bidding is unaddressed.** The creator cannot bid on their own lot,
  which a second principal defeats in ten seconds. There is no collateral. The
  example is a demo of the primitive, not of the mechanism.
- **`duration_seconds: u16`** caps a lot at ~18.2 hours.
- **Re-bidding is supported** -- a new bid removes the bidder's previous one
  and takes a fresh counter, moving them to the back of the tie-break queue.
  A useful precedent for ic-vote's re-voting.
- **Probable bug:** `BIDS_ON_LOTS` and `KEY_NAME` are both initialized on
  `MemoryId::new(1)`. Two stable structures sharing one virtual memory region
  is not something to inherit; check it before reusing the skeleton, and
  consider reporting it upstream.

## 8. Open questions

- Second-price is one mechanism. Do the same properties carry to
  multi-unit/combinatorial auctions, where the winner-determination problem is
  itself NP-hard and public recomputation stops being cheap? Probably not for
  free, and the honest answer may be that verifiability caps the mechanism
  complexity.
- Is the right first customer a DAO treasury sale (crypto-native, collateral
  already understood, small) or a procurement tender (bigger trust gap,
  slower, wants option C)? The first is a demo; the second is a business.

## 9. Sources

- Rothkopf, Teisberg & Kahn, "Why Are Vickrey Auctions Rare?", *Journal of
  Political Economy* 98(1), 1990. Cited from general knowledge; get the page
  reference before publishing this externally.
- vetKD costs, API, key ids, and the 10s timeout: see ROADMAP.md "Verified IC
  primitives", re-verified 2026-07-26, with links there.
- Timelock example read directly (2026-07-26):
  https://github.com/dfinity/examples/tree/master/rust/vetkeys/basic_timelock_ibe
- vetKeys libraries: https://github.com/dfinity/vetkeys
- The 2019 advertising shift to first-price is stated here as industry
  context, not as a verified claim. Source it before it appears in a pitch.
