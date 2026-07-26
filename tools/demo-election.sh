#!/usr/bin/env bash
# End-to-end V0 exercise against a local replica: create an election, enrol a
# roll, pin a release, open, cast three ballots, refuse two illegitimate ones,
# close, then hand the result to the independent verifier.
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
VOTERS=(icvote-localtest-a icvote-localtest-b icvote-localtest-c)
OUTSIDER=icvote-localtest-outsider
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

say() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
call() { dfx canister call --network "$NETWORK" --identity "$1" poll "${@:2}"; }

# Create only what is missing, so this never writes a plaintext key over -- or
# silently reuses -- an identity someone else made.
for who in "$ADMIN" "${VOTERS[@]}" "$OUTSIDER"; do
  if ! dfx identity get-principal --identity "$who" </dev/null >/dev/null 2>&1; then
    dfx identity new --storage-mode plaintext "$who" </dev/null >/dev/null 2>&1
  fi
done

say "participants"
echo "  admin    $ADMIN"
declare -a P
for i in 0 1 2; do
  P[$i]="$(dfx identity get-principal --identity "${VOTERS[$i]}")"
  echo "  ${VOTERS[$i]}  ${P[$i]}"
done

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
  "($ID:nat64, vec { principal \"${P[0]}\"; principal \"${P[1]}\"; principal \"${P[2]}\" })"

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

say "open the voting window"
call "$ADMIN" open_election "($ID:nat64)"

say "cast ballots"
for pair in "0 0" "1 0" "2 1"; do
  set -- $pair
  echo "  ${VOTERS[$1]} -> option $2"
  call "${VOTERS[$1]}" cast "($ID:nat64, $2:nat32)"
done

say "a non-member tries to vote (must be refused)"
call "$OUTSIDER" cast "($ID:nat64, 0:nat32)" || true

say "a member tries to vote twice (must be refused)"
call "${VOTERS[0]}" cast "($ID:nat64, 1:nat32)" || true

say "an out-of-range choice (must be refused)"
call "${VOTERS[1]}" cast "($ID:nat64, 99:nat32)" || true

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
