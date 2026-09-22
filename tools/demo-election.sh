#!/usr/bin/env bash
# End-to-end V0 exercise against a local replica: create an election, enrol a
# roll of Ed25519 credentials, pin a release, open, cast three ballots the way
# the page does (in-ballot signature, single-use transport key), refuse four
# illegitimate ones, close, then hand the result to the independent verifier.
#
# The point of the last step is that this script's own output is not evidence.
# `dfx canister call` reports whatever the canister says. Only
# tools/verify-election.mjs re-derives it.
#
#   dfx start --background --clean && dfx deploy poll && tools/demo-election.sh
#
# Every call passes `--identity` explicitly rather than calling
# `dfx identity use`, so this script never changes which identity the user has
# selected. The demo identities are namespaced and created with plaintext
# storage: a keyring-backed identity blocks on an OS keychain prompt, which in
# a non-interactive run looks exactly like a hang.
set -euo pipefail

NETWORK="${NETWORK:-local}"
# Voters are Ed25519 credentials, not dfx identities: a ballot is credentialed
# by an in-ballot signature and submitted from a single-use transport key
# (THREAT_MODEL.md 2.7), which dfx's secp256k1 envelope signing cannot do.
# tools/cast-ballot.mjs drives the same site/lib code the page ships, so every
# cast below is a live test of the voter's real path. Keys are throwaways in a
# temp dir, gone when this script exits.
KEYDIR="$(mktemp -d)"
trap 'rm -rf "$KEYDIR"' EXIT
# A throwaway identity by default, rather than whatever the user has selected:
# the demo must not depend on -- or implicate -- an operator identity. The
# `icvote-localtest-` prefix is deliberate: a name an operator might plausibly
# have created for a real deployment must never be one this script auto-creates
# as an unencrypted key.
#
# This is also NOT the deployer. tools/check.sh gives the controller its own
# identity, because an administrator who can also upgrade the canister is not
# the "availability only" party THREAT_MODEL.md T6 describes.
ADMIN="${ADMIN_IDENTITY:-icvote-localtest-admin}"
# The trustee is a third party, distinct from both: the point of the trustee
# gate is that the administrator cannot open the window or publish the count
# alone. A trustee that is the admin under another name demonstrates nothing.
TRUSTEE="${TRUSTEE_IDENTITY:-icvote-localtest-trustee}"

say() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
call() { dfx canister call --network "$NETWORK" --identity "$1" poll "${@:2}"; }
HERE="$(cd "$(dirname "$0")" && pwd)"

# cast-ballot.mjs speaks HTTP to a replica, not dfx, so NETWORK alone cannot
# steer it. Without this, admin calls follow $NETWORK while every ballot goes
# to the hardcoded local default -- on any non-default network the script
# would open a real election and then die casting into 127.0.0.1.
if [ -z "${HOST:-}" ]; then
  case "$NETWORK" in
    local) HOST="http://127.0.0.1:4943" ;;
    ic) HOST="https://icp0.io" ;;
    *)
      echo "NETWORK='$NETWORK' has no known replica URL; set HOST=<url> explicitly." >&2
      exit 2
      ;;
  esac
fi
cast() { node "$HERE/cast-ballot.mjs" cast --canister "$CID" --host "$HOST" "$@"; }

# The admin stays a dfx identity: administration is envelope-authenticated,
# and that is correct -- it is the ballots that must not be.
for who in "$ADMIN" "$TRUSTEE"; do
  if ! dfx identity get-principal --identity "$who" </dev/null >/dev/null 2>&1; then
    dfx identity new --storage-mode plaintext "$who" </dev/null >/dev/null 2>&1
  fi
done
CID="$(dfx canister id --network "$NETWORK" --identity "$ADMIN" poll)"
TRUSTEE_P="$(dfx identity get-principal --identity "$TRUSTEE" </dev/null)"

say "participants"
echo "  admin    $ADMIN"
echo "  trustee  $TRUSTEE  $TRUSTEE_P"
declare -a P
# voter-3 is enrolled but casts only the deliberately-mismatched ballot at the
# end: every earlier refusal (NotEligible, AlreadyVoted, InvalidChoice) fires
# before the signature check, so proving InvalidSignature needs an eligible
# voter with an unspent ballot.
for i in 0 1 2 3; do
  P[$i]="$(node "$HERE/cast-ballot.mjs" keygen --key "$KEYDIR/voter-$i.key")"
  echo "  voter-$i  ${P[$i]}"
done
node "$HERE/cast-ballot.mjs" keygen --key "$KEYDIR/outsider.key" >/dev/null

say "create election"
ID=$(call "$ADMIN" create_election \
  '(record {
      title = "ic-git roadmap: next rung";
      question = "Which rung does ic-git build next?";
      options = vec {
        "Certified module-hash reader";
        "Registry attest() + K-of-N tooling";
        "Multi-chain EVM config"
      };
   })' | grep -oE '[0-9_]+ : nat64' | head -1 | tr -d '_' | cut -d' ' -f1)
echo "  election id $ID"

say "enrol roll"
call "$ADMIN" set_roll \
  "($ID:nat64, vec { principal \"${P[0]}\"; principal \"${P[1]}\"; principal \"${P[2]}\"; principal \"${P[3]}\" })"

say "pin the release voters must be running"
# Placeholder values: this repo has not been pushed to ic-git yet, so there is
# no real (commit, bundleHash) record to point at. They are structurally valid
# and the manifest commits to them -- which is the V0 mechanism being
# demonstrated -- but they are not an attestation, and the frontend verifier
# says so rather than rendering green on a placeholder.
ZERO40=$(printf '0%.0s' {1..40})
ZERO64=$(printf '0%.0s' {1..64})
call "$ADMIN" pin_release \
  "($ID:nat64, record {
      repo = \"ic-vote\";
      commit = \"$ZERO40\";
      bundle_sha256 = \"$ZERO64\";
      site_canister = \"umobs-yiaaa-aaaab-agyrq-cai\";
      module_sha256 = \"$ZERO64\";
      poll_module_sha256 = \"$ZERO64\";
      registry_chain_id = 11155111:nat64;
      registry_address = \"0xa1362DAda583c56a395D305a8C7A458E0B62A209\";
   })"

say "name the trustee who must approve the opening and the count"
# One trustee, threshold one: the smallest policy that is not "admin alone".
# The list and the threshold go into the manifest hash, so a voter's client
# checks the same commitment the trustee approved.
call "$ADMIN" set_trustees "($ID:nat64, vec { principal \"$TRUSTEE_P\" }, 1:nat32)"

say "the administrator tries to open without the trustee (must be refused)"
call "$ADMIN" open_election "($ID:nat64)" || true

say "the trustee approves the manifest hash"
call "$TRUSTEE" approve "($ID:nat64, variant { Open }, true)"

say "open the voting window"
call "$ADMIN" open_election "($ID:nat64)"

say "cast ballots (in-ballot signature, single-use transport key)"
for pair in "0 0" "1 0" "2 1"; do
  set -- $pair
  echo "  voter-$1 -> option $2"
  cast --key "$KEYDIR/voter-$1.key" --election "$ID" --choice "$2"
done

say "a non-member tries to vote (must be refused)"
cast --key "$KEYDIR/outsider.key" --election "$ID" --choice 0 || true

say "a member tries to vote twice (must be refused)"
cast --key "$KEYDIR/voter-0.key" --election "$ID" --choice 1 || true

say "an out-of-range choice (must be refused)"
cast --key "$KEYDIR/voter-1.key" --election "$ID" --choice 99 || true

say "a signature over a different choice than submitted (must be refused)"
cast --key "$KEYDIR/voter-3.key" --election "$ID" --choice 0 --sign-choice 1 || true

say "the administrator tries to close without the trustee (must be refused)"
call "$ADMIN" close_election "($ID:nat64)" || true

say "the trustee approves the tally hash, attesting the count"
call "$TRUSTEE" approve "($ID:nat64, variant { Close }, true)"

say "close"
call "$ADMIN" close_election "($ID:nat64)"

say "independent verification"
# --identity passed explicitly for the same reason every other call here does:
# verify-election.mjs shells out to dfx, and without it the reads would be
# signed by whatever identity the operator happens to have selected -- which
# can block on a keychain prompt or fail outright if that identity was removed.
node "$(dirname "$0")/verify-election.mjs" --fetch "$ID" --network "$NETWORK" \
  --identity "$ADMIN" \
  --canister "$(dfx canister id --network "$NETWORK" --identity "$ADMIN" poll)"
