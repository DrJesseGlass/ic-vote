# Vision: the voting client is the unverified part

This document argues what ic-vote is for. Companion to THREAT_MODEL.md (what
we trust) and ROADMAP.md (what we build, in order). State of the world as of
July 2026.

## 1. What end-to-end verifiable voting already solved

E2E-verifiable (E2E-V) voting wants two properties:

- **counted-as-cast** -- the published tally correctly includes your recorded
  ballot.
- **cast-as-intended** -- the recorded ballot encodes the choice you actually
  made.

**Counted-as-cast is solved, and solved beautifully.** Homomorphic tallying or
verifiable mixnets, plus zero-knowledge proofs published to a public bulletin
board, let *anyone* recompute the result and check the proofs without trusting
the election authority at all. This is mature work -- Chaum's Punchscan (2004),
Prêt à Voter (2005), Helios (2008), Scantegrity, ElectionGuard -- and it does
what it says.

We should reuse it wholesale. ic-vote invents no tallying cryptography.

## 2. What it did not solve, and has not for ~20 years

**Cast-as-intended is the hole in every *remote* E2E-V system.**

Your browser encrypts your vote. If that JavaScript is malicious, it encrypts
*candidate B* while displaying *candidate A* -- and then emits a perfectly
valid zero-knowledge proof that it correctly encrypted candidate B. Walk the
chain:

- the bulletin board is internally consistent;
- the tally proof verifies;
- every auditor's check passes;
- the election is wrong.

The cryptography is not broken. It is answering a different question than the
one the voter cares about. All of it is downstream of an input the voter never
got to inspect.

### The standard mitigation, and why it is not enough

The **Benaloh challenge** (2006), a.k.a. cast-or-audit: after your ballot is
encrypted, you may *spoil* it and demand the client open the encryption and
prove it correct, then start over with a fresh ballot. Because the client
cannot know in advance whether a given ballot will be audited or cast,
cheating on a fraction `p` of ballots is caught with probability `p` per audit.
Elegant, and genuinely the best available answer.

Its two documented weaknesses are both fatal in practice:

1. **Voters do not do it.** Usability studies consistently find that most
   voters either skip the audit or do not understand what it proved. A defense
   whose security depends on mass comprehension of a probabilistic protocol is
   not a defense you can size.
2. **It needs a second, independent device.** Verifying the opened ballot on
   the *same* client that may be lying is circular -- a malicious client
   simply reports "audit passed." So the mitigation's own threat model
   requires hardware most voters do not have and will not use.

This is why Helios's own paper declines to recommend it for high-stakes
national elections, and why ElectionGuard is deployed alongside *paper* and
physically controlled in-person scanners: the "client" becomes a machine in a
polling place, and paper is the ground truth. The remote case was left open.

So the standing state of the art, for about two decades, is: **assume the
voting client is honest, or hope enough voters audit.**

## 3. What ic-git changes

ic-git makes the client itself checkable. Not "trust the client," not
"statistically audit the client," but:

> the bytes running in your browser hash to a bundle attested at a commit
> that K independent reviewers reproduced, served by a canister whose
> certified module hash those same reviewers attested.

It converts the load-bearing assumption into a check. Concretely, the ic-git
stack supplies:

- **F0/F2** -- the ballot page is served from a committed bundle by the
  canister itself, with IC response certification, and a client-side verifier
  compares served bytes against the on-chain `(commit, bundleHash)` record.
- **Backend attestation** (`docs/ATTESTATION.md`) -- the serving canister's
  *own* wasm is reproducible-built and attested on-chain by K independent
  verifiers, so "the canister serving the ballot runs the reviewed code" is
  itself checkable.
- **No standing credentials** -- there is no deploy key for an attacker to
  steal, because the deployer is a program whose EOA exists only as threshold
  shares across a subnet.

This is not a new cryptographic result. It is supply-chain provenance applied
to the exact place the voting literature had to punt.

And it is not hypothetical: BadgerDAO, the Curve DNS hijack, and Ledger
connect-kit were all *this* attack -- malicious JavaScript served against
intact backends -- executed against money instead of votes. The attack class
is real, it is commodity, and it has a body count.

### Benaloh's new role

Given an attested client, the Benaloh challenge moves from **load-bearing** to
**defense-in-depth**, and that is the right place for it. Attestation proves
*this is the reviewed code*; it does not prove *the reviewed code is correct*.
Cast-or-audit tests behavior rather than provenance, so it still catches:

- an honest-but-buggy client that passed review;
- a compromised endpoint (see THREAT_MODEL.md), which no provenance touches.

Two mechanisms covering different failure modes. We keep both, but the system
no longer *depends* on voters performing a ritual they demonstrably skip.

## 4. What this explicitly does not fix

Stated here so it is never quietly dropped from a pitch:

- **A compromised browser or OS** reads your plaintext choice before any
  encryption happens. No amount of bundle provenance touches this. It is the
  hard floor of remote voting on user-owned devices.
- **The HTTP gateway** (`icp0.io`) remains a trusted party for any user who
  does not verify IC response certification locally -- ic-git's VISION.md
  already concedes this, and it applies here unchanged.
- **A voter who never runs the verifier** gets none of this. Provenance that
  is not checked is documentation.
- **Coercion.** See THREAT_MODEL.md; it is not solved, it is not solved by
  mail ballots either, and pretending otherwise would be dishonest.

The claim is bounded and should always be stated bounded: ic-vote closes
*malicious-server-serves-malicious-client*. It does not close
*compromised-endpoint*.

## 5. Why organizational votes, not government elections

The security community's rejection of remote voting for binding public
elections is well-founded and we are not going to argue with it. But the
argument that applies there does not obviously apply to a union local
electing officers, a housing co-op amending bylaws, a professional
association seating a board, or a DAO with a treasury.

In those settings:

- **A roll already exists.** Eligibility is a membership list the organization
  maintains, which sidesteps the hardest open problem (see ROADMAP.md V2).
- **The incumbent is worse.** Today it is a SaaS ballot box with no
  verifiability of any kind, or a spreadsheet and an email thread. The bar is
  not "better than paper in a polling place with risk-limiting audits"; it is
  "better than a vendor's word."
- **The trade is already made.** These organizations overwhelmingly vote by
  mail or proxy today, which has the same coercion exposure and none of the
  verifiability.

That is a real market with a real trust gap, and it is where a system whose
distinguishing feature is *a verifiable client* has the clearest argument.

## 6. The long dream, and the honest distance to it

"Trustless voting machines on the IC that anyone can use, on any device, at
any time" is the destination. The distance is not mostly cryptographic:

- tallying: solved (section 1);
- client integrity: this project's contribution (section 3);
- ballot secrecy: a solved primitive on the IC as of 2025 (vetKD -- see
  ROADMAP.md V1);
- eligibility at population scale: unsolved as a *trust* question, not a math
  one -- somebody must issue the credential, and who that is, is politics;
- coercion resistance on uncontrolled devices: genuinely open.

The first three are buildable now. The last two are why V0 aims at a co-op
board election and not a national one.
