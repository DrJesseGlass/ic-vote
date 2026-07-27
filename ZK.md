# ZK voting on the IC, and whether a custom language helps

Written 2026-07-26. Answers two questions: can ic-vote's V1 anonymity actually
run on the IC, and is there a case for a purpose-built language in the way
ic-git's DSL work suggests. Short answers: **yes, comfortably** -- and **yes,
but not for the reason the question implies.** Efficiency is not the argument.
Reviewability is.

## 1. Feasibility: not the hard part

The V1 circuit is Semaphore-shaped -- prove membership of a leaf in a Merkle
root, emit a nullifier bound to the election id. That is a small circuit: a
depth-20 Poseidon Merkle path plus a nullifier hash lands in the low thousands
of constraints. This is the most well-trodden circuit in the entire ZK
ecosystem, and it runs in browsers today.

**Verification on chain is cheap by two orders of magnitude.** Groth16
verification is three pairings and a small multi-scalar multiplication over
the public inputs, with a constant 128-byte proof. The IC's per-message limit
is 40 billion Wasm instructions for update calls, timers, and heartbeats
(doubled from 20B, made practical by deterministic time slicing). Groth16
verification is milliseconds of native work; even allowing a large Wasm
penalty it does not approach that ceiling. Groth16 verifiers have been run in
canisters for years.

**Unmeasured, and it should be measured before it is depended on:** the actual
instruction count for one Groth16 verification in a canister. The number that
matters is not one proof, it is the aggregate. At a plausible ~10^8
instructions per verification, a 5,000-voter election spends ~5x10^11
instructions on proof checking -- more than ten full messages' worth of
budget. That is fine, because the natural design verifies **one proof per
ingress message at submission time**, so the work is spread across as many
messages as there are voters and no single message goes near the limit. But it
does mean batch re-verification at close is not free, and any "recount"
endpoint has to be paginated. Measure with `canbench` before committing.

**Proving runs client-side in Wasm** and is unremarkable at this circuit size
-- a second or two in a browser. The constraint is not speed, it is that the
prover is a large Wasm blob, which is the actual problem (section 3).

So: the cryptography is not the obstacle, the IC is not the obstacle, and the
performance is not the obstacle. ROADMAP.md V1's claim that "Groth16
verification in a canister is cheap" survives checking.

## 2. The real obstacle is the trusted setup, and it is our own problem again

Groth16 needs a per-circuit structured reference string. Whoever generates it
holds "toxic waste" that lets them **forge proofs**. In V1, a forged proof is
a forged membership claim: unlimited valid-looking ballots from voters who do
not exist, each with a fresh nullifier, indistinguishable from real ones.

Look at the shape of that:

- the circuit source is public and reviewable;
- the proofs verify;
- the nullifiers are unique;
- the bulletin board is internally consistent;
- the election is wrong.

That is the *same* structure as the malicious ballot-marking device in
VISION.md section 2, and the same structure as Thompson's compiler in
`ic-git/REPRODUCIBLE_BUILD.md`. A clean-looking source artifact, a compromised
build/setup artifact, and a downstream verification that passes perfectly
while answering the wrong question. Three occurrences of one pattern is not a
coincidence; it is the thesis of this project.

Three responses, and the third is the interesting one:

1. **Use a system with no per-circuit setup.** PLONK/Halo2 need only a
   universal setup that already exists from large public ceremonies; STARKs
   and Bulletproofs need none at all. Cost: bigger proofs and slower
   verification, though still far inside the IC's budget. **This is the safe
   default and should be the starting assumption for V1**, with Groth16 as an
   optimization to justify later rather than the baseline.
2. **Run the ceremony as a public multi-party computation** -- secure if one
   participant is honest, which is the standard practice.
3. **Attest the ceremony artifacts in the ProvenanceRegistry.** The CRS is a
   file with a hash. K independent participants reproducing and attesting the
   transcript is *the identical machinery* ic-git already specifies for build
   reviewers, pointed at a different artifact. The verifier client then checks
   the CRS hash the way it checks the bundle hash, and the GREEN/YELLOW/RED
   gate covers the setup as well as the code.

Nobody else can do 3, because nobody else has the registry and the reviewer
set. It is the same argument as the ballot-marking device, one layer down.

## 3. Where a custom language does and does not help

**It does not help with efficiency.** A new circuit language will not beat
Circom or Noir on constraint count without years of compiler work that is not
this project's business. If the goal is fewer constraints, use Noir and move
on.

**It helps with the thing that is actually broken: the toolchain is
unattested.** Count what a voter must trust in a conventional ZK voting
deployment:

| Artifact | Reviewable? | Attested today? |
|---|---|---|
| Circuit source | yes, if small | no |
| Circuit compiler (circom/nargo) | in principle, large | no |
| The compiled R1CS/ACIR | not by a human | no |
| Setup ceremony transcript / CRS | by reproduction | no |
| Prover Wasm blob in the browser | no | ic-git F0/F2 handles this |
| Verifier code in the canister | yes | ic-git attestation handles this |

ic-git covers the last two rows. The middle four are wide open, and the
compiler row is the worst of them: a backdoored circuit compiler emits an
R1CS that does not match the reviewed circuit source, and nothing downstream
notices. It is the ballot-marking-device attack relocated into the build.

**This is where a minimal circuit DSL becomes a serious idea.** Not because it
compiles faster, but because a circuit language is *dramatically smaller than
a general-purpose one*: arithmetic constraints over a field, bounded loops, no
heap, no dynamic dispatch, no memory model, no FFI. That is a compiler small
enough to (a) be read end to end by a reviewer and (b) plausibly run **on
chain** as ic-git's `compile_lang`. If circuit source goes in on chain and
R1CS comes out on chain, the compiler row and the compiled-artifact row both
close, and they close by the same mechanism as everything else in the stack.

**Two corrections to how this was first framed here, after reading ic-git's
Track B.**

First, the on-chain compiler is not a future project. `ic-git/ROADMAP.md`
records R0-R4 as DONE and verified on a live replica: a real language
compiler in a canister (lexer, recursive-descent parser, wasm-encoder
codegen, no LLVM), ~42,000 instructions per function so the binding limit is
the 10 MiB code section rather than the instruction budget, separate
compilation across module interfaces with a symbolic-relocation linker, and
distributed compilation across a worker fleet producing byte-identical output
to a local build. The infrastructure this argument needs already exists.

Second, and more importantly: **circuits do not give self-hosting, and saying
so conflated two goals.** A circuit compiler emits a constraint system, not
wasm, so it can never compile itself. Self-hosting needs the wasm-emitting
language -- ic-git's R5 path -- and nothing here changes that.

The accurate claim is better than the one it replaces. `compile_lang` has been
looking for its first real customer; `ic-git/REPRODUCIBLE_BUILD.md` R2 is
literally "the first app built on ic-git, on-chain, in the project's own DSL."
**The ZK circuit is that customer, and it is a better one than a generic app,
because here on-chain compilation is not a demonstration of the pipeline -- it
is the only thing that closes the compiler row of the table above.** For every
other application, "compiled on chain" is a nice property. For this one it is
load-bearing.

The fit is closer than it looks. R1's language is i32 functions over
`+ - * /` with variables and cross-function calls and no control flow. A
Semaphore circuit is field arithmetic over `+` and `*`, in named sub-circuits
that call each other, with no control flow -- Poseidon and a Merkle path are
*nothing but* that, which is exactly why Poseidon is the hash ZK systems use.
Swap i32 for a 255-bit field element and swap the wasm-encoder backend for an
R1CS emitter, and the lexer, parser, module-interface system, relocation
linker, and fleet distribution all carry over unchanged. Constraint systems
concatenate more cleanly than wasm function bodies do, and renumbering signal
indices at link time is the same move the existing linker already makes for
function indices.

And it escapes the problem that makes R5 open-ended. "R5 and the rustc
question" concludes, correctly, that this compiler can never match rustc
exactly, so the wasm language has no natural finish line. **The circuit target
has no incumbent to match.** A constraint system has to be *sound*, not
byte-identical to Circom's output, so the rung has an actual completion
criterion: does it compile the Semaphore circuit to a constraint system that
accepts exactly the valid witnesses. That is testable and it terminates.

The caveats deserve equal weight:

- A hand-rolled circuit DSL is a **new unreviewed compiler**, which is
  precisely what REPRODUCIBLE_BUILD.md warns against. It is only a net gain
  if it is small enough to be reviewed end to end *and* it is on chain and
  attested. A custom compiler that lives on someone's laptop is strictly
  worse than Circom, which at least has had eyes on it.
- Soundness bugs in circuit compilers are subtle and vicious -- an
  under-constrained circuit accepts proofs of false statements, and it looks
  fine. Circom and Noir have absorbed years of adversarial attention. A new
  one has not. **Correction to what this document first said:** the fix is
  not "differential testing on random witnesses." Random witnesses fail the
  first constraint almost surely, so both systems reject and the agreement
  rate measures nothing; and differential testing structurally cannot catch
  under-constraining, because an under-constrained circuit still yields
  honest outputs on honest inputs. Two compilers can be broken differently
  and agree on every test. See `ic-git/docs/CIRCUIT_TESTING.md` for the
  three-axis design that replaces it -- differential testing on random
  *inputs* and random *circuits* for semantic divergence, a determinism
  analysis for under-constraining, and structural invariants in CI. The
  determinism screen (`ic-git/tools/r1cs-check`) needs no compiler and
  already exists.
- Field arithmetic is the first non-i32 type this compiler would carry, and
  signals-versus-constants is a distinction the current language has no
  notion of. Bounded work, not zero work.
- None of this is on V1's critical path. V1 should ship with an existing
  toolchain and honest documentation of the unattested rows above.

## 4. Recommendation

- **V1:** existing toolchain (Noir, or Circom if the Groth16 tooling is worth
  it), universal or transparent setup by default, and the table in section 3
  published as-is so the unattested rows are visible rather than implied.
- **V1.5:** attest the setup and circuit artifacts in the ProvenanceRegistry.
  Cheap -- it is hashes and the existing K-of-N flow -- and it closes two of
  the four open rows with no new cryptography.
- **Later, and worth wanting:** a minimal circuit DSL as ic-git's first
  on-chain-compiled language, which closes the remaining two. Pitch it as
  provenance, never as performance.

## 5. Sources and status

- IC instruction limit (40B per update/timer/heartbeat, DTS): IC docs on
  canister resource limits and execution layer.
- Groth16 on ICP has prior art:
  https://forum.dfinity.org/t/zk-starks-proving-on-icp-groth16-verifier/24881
- `ark-groth16`: https://docs.rs/ark-groth16/
- **Unmeasured:** per-verification instruction count in a canister, and the
  Noir-vs-Circom decision. Both need a `canbench` run, not a search. Treat
  every number in section 1 as an estimate until then, per the discipline in
  ROADMAP.md.
- Semaphore, Poseidon constraint counts, and browser proving times are cited
  from general knowledge and should be pinned to sources before this appears
  anywhere external.
