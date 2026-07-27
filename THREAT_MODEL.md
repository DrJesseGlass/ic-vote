# Threat model

What ic-vote trusts, what it does not, and where it is honestly weak. Written
before the code so the code cannot quietly widen the trust set.

Rule for this document: **a mechanism may only ever be described as closing
the specific attack it closes.** ic-git's attestation doctrine ("a check may
add warnings, never falsely upgrade a verdict") applies here too.

## 1. The trust set, enumerated

Anything on this list can break the election. Nothing off this list should be
able to, and any change that adds a row is a design regression.

| # | Trusted | Why it is here | Can we remove it? |
|---|---|---|---|
| T1 | The IC subnet (supermajority honest) | Executes the canister, certifies state, holds vetKD shares; sees every submission's arrival time and ordering (2.7) | No -- it is the platform |
| T2 | The voter's browser and OS | Sees the plaintext choice before encryption | **No** -- hard floor of remote voting |
| T3 | K independent build reviewers (not all colluding) | Bridge from certified module hash to auditable source | No, but it amortizes -- one review covers every election |
| T4 | The eligibility issuer (whoever defines the roll) | Decides who is a voter | No -- this is a political question, not a cryptographic one |
| T5 | The HTTP gateway | For *non-verifying users*: delivers the bundle and can lie about it. For **everyone**: sees the source IP and timing of every request, including ballot submissions (2.7) | Integrity: yes, per-user, by running the verifier. Metadata: no |
| T6 | The election administrator, for *availability* only | Can stop or delay an election | Partially (open bulletin board makes censorship evident) |
| T7 | The controllers of the poll and site canisters, *bounded by the pin* | A controller can upgrade a canister, replacing the code that counts ballots or the page that collects them | Not removable, but contained: the election pins both module hashes for the window (see 2.5), so a mid-window change is a RED verdict rather than a silent one |

Deliberately **not** on the list, and this is the point of the project:

- the server operator's honesty about what code is running (T3 replaces it);
- the CI pipeline, its secrets, and everyone with commit access to it
  (no standing deploy credential exists);
- the DNS registrar and CDN (no mutable hosting layer);
- the tallier's honesty (E2E-V proofs replace it);
- the canister's ability to read ballots (vetKD replaces it -- V1 onward).

## 2. Attacks, and what stops them

### 2.1 Malicious ballot client (the project's reason to exist)

*Attack:* the server serves modified JavaScript to all voters, or to a
targeted subset, that encrypts a different choice than displayed and proves
the wrong thing correctly.

*Status quo:* undetectable. Every downstream E2E-V proof still verifies. This
is the open problem described in VISION.md section 2.

*Here:* the served bundle's sha256 is bound on-chain to a commit; the serving
canister's module hash is attested by K reviewers; the client-side verifier
checks both before the voter marks a ballot. Targeted delivery is *worse* for
the attacker than blanket delivery, because a single verifying voter's
mismatch is evidence.

*Residual:* a bug in the reviewed code. Reviewers are humans reading source.
Attestation proves identity of code, not correctness of code -- hence the
Benaloh challenge is retained as defense-in-depth.

### 2.2 Compromised voter endpoint

*Attack:* malware on the voter's own machine reads the choice pre-encryption,
or manipulates the UI.

*Status:* **not mitigated.** Cannot be, on user-owned hardware. Cast-or-audit
gives partial detection if the audit is performed on a *different* device.

We state this plainly wherever the system is described. A system whose
marketing implies otherwise is worse than one that admits it, because voters
calibrate on the claim.

### 2.3 Ballot secrecy against the infrastructure

*Attack:* whoever can read canister state reads how each voter voted. Canister
memory is not secret from the replicas executing it, so "it's on a blockchain"
is an argument *against* naive secrecy, not for it.

*V0:* not mitigated -- V0 is deliberately a public-ballot system (see
ROADMAP.md). Suitable only where votes are already public (many board and
shareholder votes are).

*V1 onward:* ballots encrypted under a vetKD-derived key. The canister holds
no decryption key; threshold shares live across the subnet and derivation is
gated by the canister's own audited logic. Tally either homomorphically or
after a threshold decrypt at close.

### 2.4 Tally manipulation

*Attack:* the authority reports a result inconsistent with the ballots.

*Mitigation:* standard E2E-V. Public bulletin board, published proofs, anyone
recomputes. We invent nothing here and should resist the temptation to.

### 2.5 Silent code change mid-election

*Attack:* the canister is upgraded partway through voting to malicious code.

*Mitigation:* ic-git's change detection -- cache the certified module hash,
re-read on every load and on a timer; a changed hash with no matching trusted
attestation is RED, and a changed hash *with* matching attestations still
clamps the verdict to YELLOW pending re-verification. For an election
specifically, we should additionally **pin the expected module hash for the
duration of the voting window** and treat any change as a spoiling event
requiring administrator disclosure.

*Which canisters:* **both**, and this needs saying because the first
implementation only did one. The canister serving the ballot page and the
canister holding the ballots are separate, separately controlled, and
separately able to break the election -- one by changing what the voter sees,
the other by changing what their vote means. An election pins a module hash for
each (`Pin.module_sha256`, `Pin.poll_module_sha256`). Pinning only the serving
canister leaves "upgrade the thing that counts" entirely unobserved, which is
the state this project shipped in until a review caught it.

*Limit:* the pin makes a *change* visible; it does not establish that the
pinned value was ever the right one. Only the K-of-N attestation on that hash
does that, and it is unbuilt (T3, ROADMAP.md dependency 2). A pin whose
starting value the administrator chose freely is a tripwire, not a proof.

### 2.6 Eligibility fraud / Sybil

*Attack:* votes cast by non-members, or one member voting many times.

*V0:* roll-based. The organization supplies a member list; ballots are signed
by roll-listed identities; double-voting prevented by identity. Trust lands
squarely on T4, which is honest -- the organization already decides who its
members are.

*V1:* anonymous but eligible, via ZK set membership over a Merkle root of the
roll plus a nullifier that makes a second vote from the same member
detectable without linking either vote to them. (This was V2 until 2026-07-26;
it moved into V1 because encrypting a ballot that is still signed by a named
identity only defers the disclosure to close. See ROADMAP.md, "Why the rungs
merged.") *V2* is now the eligibility-issuance ladder above rung 1 -- the same
mechanism, different signer on the leaves.

*Never solved by us:* "one human, one vote" at population scale. That requires
an issuer -- a government, a passport authority, a biometric registry -- and
choosing one is a political act, not an engineering decision. Internet
Identity supplies per-origin pseudonyms, which is unlinkability, **not**
uniqueness. Any claim otherwise is false.

### 2.7 Ballot-submission linkability (V1)

*Attack:* the membership proof unlinks the ballot from the roll, but the
submission carries identifiers of its own: the ingress message's caller
principal, the gateway's view of the source IP, and the replica's view of
arrival time and ordering. At close, the vetKey opens every ciphertext for
the election at once. Any identifier that survived next to a ciphertext is
the voter-to-choice link reconstituted -- the ZK circuit removed the
cryptographic link, not the transport's.

*Mitigation (mechanism, built at V0):* a cast is submitted from a
single-use self-authenticating principal generated in the browser for that
one message -- never the voter's Internet Identity or any roll-linked
principal. Eligibility rides entirely on an in-ballot credential, so the
canister accepts a cast from any caller, never reads `msg_caller` in the
cast path, and stores nothing caller-derived (`state.rs::cast` does not
even take a caller parameter). V0's original design was the opposite --
the caller principal *was* the ballot signature -- and it was replaced
rather than kept until V1, for two reasons. First, the transport must
already be caller-blind when V1's encryption arrives, or every "encrypted"
ballot is attributable the moment the vetKey opens (2.3). Second, the V0
replacement is itself an upgrade to the public board: the credential (an
Ed25519 key on the roll) and its signature over (poll canister, manifest
hash, choice) are published in the log and bound into the entry hash, so
the franchise check is recomputable from published data instead of resting
on this canister's word about who called `cast`. In V1 the credential
column becomes a ZK membership proof and a nullifier; the transport does
not change.

*Residual (not absorbed by "we have ZK"):* the gateway sees source IP and
timing for every submission -- T5's trust scope for metadata covers all
users, not only non-verifying ones -- and the replicas see arrival order
(T1). An observer holding those logs can correlate ciphertexts to network
identities regardless of the circuit. This project cannot remove that.
User-level mitigations (submitting over Tor or a VPN) are real but are the
voter's to perform, and client-side submit-time jitter blunts only coarse
correlation, not the infrastructure's own logs. Per the rule at the top of
this document: the circuit closes the cryptographic link and is described
as closing exactly that.

*Re-voting disclosure:* recasts reuse the nullifier, so the public record
shows that *some* anonymous member revoted and how many times, without
identifying them. This is inherent to last-ballot-counts (section 3) and is
stated rather than hidden.

## 3. Coercion resistance, stated honestly

**We do not solve it.** Neither does mail-in voting, and mail-in voting is
used at enormous scale.

This symmetry matters and earlier drafts of our thinking got it wrong by
treating coercion as disqualifying for remote voting while ignoring that the
same exposure is tolerated in paper absentee systems. There is no cryptography
in an envelope. A spouse, a union boss, or an employer can watch you fill in a
mail ballot exactly as they can watch you fill in a web form.

The honest distinction is **attack economics**, not the presence or absence of
the vulnerability:

| | Mail ballot | Naive online voting |
|---|---|---|
| Granularity | Retail -- one voter at a time | Wholesale -- one compromise, everyone |
| Physical presence | Required | Not required |
| Jurisdiction | Local | Possibly foreign |
| Evidence trail | Paper; prosecutable (e.g. the 2018 NC-09 congressional race was overturned for absentee ballot harvesting) | Possibly none |

So the design question is not "is it coercion-resistant" -- nothing remote is
-- but "does it make coercion *scale*." That is a system-compromise question,
and it is the one this project's client attestation actually addresses.

**What a digital system can do that paper cannot:** re-voting. Estonia allows
a voter to cast repeatedly during the voting window with only the last ballot
counted, so a ballot cast under observation can be silently overridden later
in private. It is a partial mitigation, it is real, and mail has no
equivalent. ic-vote should support it from V1 (it interacts with the tally
design, so it cannot be bolted on later).

**What we will not do:** claim JCJ/Civitas-style fake-credential coercion
resistance. It is theoretically sound and has never been made usable; shipping
a checkbox labelled "coercion resistant" that voters cannot operate is worse
than shipping nothing.

## 4. Verdicts shown to the voter

Mirroring ic-git's GREEN/YELLOW/RED doctrine, computed before any change-
detection clamp is applied:

- **GREEN** -- served bundle matches the attested commit; the serving
  canister's certified module hash has K trusted attestations agreeing on one
  commit and recipeHash; the election's pinned module hash matches.
- **YELLOW** -- bundle matches, but the backend has fewer than K attestations,
  or the module hash changed and is awaiting re-verification.
- **RED** -- bundle mismatch, no trusted attestation matches the live module
  hash, or the pinned election hash changed.

A RED verdict during an open voting window is an incident, not a warning
banner, and the UI should treat it that way.
