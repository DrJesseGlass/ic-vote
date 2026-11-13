# Security

## Reporting a vulnerability

Report it privately, not in a public issue or pull request:

    https://github.com/DrJesseGlass/ic-vote/security/advisories/new

That form opens a draft advisory only the maintainer and you can see. Say
what you found, how to reproduce it, and which piece it is in (below).
Expect an acknowledgement within a week.

A bug that is not a security problem is an ordinary issue:
https://github.com/DrJesseGlass/ic-vote/issues/new/choose

## What counts

ic-vote's promise is that a voter can check the page they vote on, and
that anyone can recompute the election from what the canister published.
THREAT_MODEL.md lists what is trusted; anything that breaks an election
from outside that list is in scope, in particular:

- the ballot page's verdict (`site/lib/verifier.js`, `site/lib/provenance.js`,
  `site/config.js`): a page that shows GREEN, or lets a ballot through,
  when a check it names did not hold. That is the worst case. So is any
  way to move a trust anchor in `config.js` from outside the bundle (a URL
  parameter honoured off this machine, a value taken from the election's
  pin);
- the poll canister (`canisters/poll`): a ballot counted without a
  credential on the roll, or twice for one credential; a signed ballot
  replayed outside its expiry; a roll, pin, manifest or trustee set changed
  after open; opening or closing without K of N trustees; a log or
  certified root that does not commit to what was cast;
- the independent verifier (`tools/verify-election.mjs`) and the browser's
  recomputation (`site/lib/election-hash.js`): a tampered election that
  either one accepts;
- the hand-written primitives in `site/lib/` (sha256, keccak, CBOR, candid,
  the agent, the certificate reader): they are ours to be wrong about;
- staging and push (`tools/stage-site.mjs`, `tools/stage-ic-git.sh`,
  `tools/push-ic-git.sh`): staged bytes that are not the reviewed source,
  a page byte the integrity hash does not cover, a push that goes out
  unsigned.

## What does not

- What THREAT_MODEL.md already states as unmitigated: V0 ballots are
  public and attributable (2.3), a compromised voter device (2.2), what
  the gateway and the replicas see of a submission (2.7), coercion (3).
- The gaps docs/V0_STATUS.md lists under "Stubbed", behaving as it says
  they do. A stub that fails open instead is a report.
- ic-git itself: its canister, its governor, its registry, and its
  verification core, which is vendored here byte for byte as
  `site/lib/ic-git-core.js`. Those go to ic-git
  (https://github.com/DrJesseGlass/ic-git/security/advisories/new). A copy
  here that differs from what its header names is ours.
- The registry is on Sepolia. Testnet reorganisations and testnet ether
  are not vulnerabilities.
- A dependency advisory with no reachable path in this code. Dependabot
  files those (`.github/dependabot.yml`) and `cargo deny` refuses them in
  CI (`deny.toml`); if you believe a path exists, that is a report.

## Supported versions

Only `main` and what is deployed from it: the page ic-git serves from
this repo and the repo's app canister, as the `ic-vote#site` and
`ic-vote#app` records name them. Older commits are not patched.

## How a fix ships

A fix is a push like any other: staged from `main`, pushed to ic-git
signed, held until the repo's voters approve it, installed by ic-git's
deploy queue, and recorded on chain (README). An election pins both
module hashes for its voting window, so a fix that lands while one is
open turns its verdict RED, and that is disclosed rather than avoided
(THREAT_MODEL.md 2.5). The advisory is published, with credit to the
reporter if wanted, once the fixed build is the recorded one.
