#!/usr/bin/env bash
# Everything, in one command.
#
#   tools/check.sh          offline only
#   tools/check.sh --live   also deploy to a local replica and exercise it
#
# The --live path is the one that matters: the canister tests prove the rules,
# but only a live run proves the hand-written agent, the candid decoder and the
# certificate reader against bytes the IC actually produced.
set -euo pipefail
cd "$(dirname "$0")/.."

say() { printf '\n\033[1m== %s\033[0m\n' "$1"; }

say "canister tests"
cargo test -p ic_vote_poll

say "canister builds for wasm32"
cargo build -p ic_vote_poll --release --target wasm32-unknown-unknown

say "frontend library tests (offline)"
node tools/test-site-lib.mjs

if [ "${1:-}" != "--live" ]; then
  echo ""
  echo "Offline checks passed. Re-run with --live for the replica tests."
  exit 0
fi

say "local replica"
dfx stop >/dev/null 2>&1 || true
dfx start --background --clean >/dev/null 2>&1
trap 'dfx stop >/dev/null 2>&1 || true' EXIT

# The deploy identity becomes the canister's CONTROLLER, and a controller can
# upgrade the canister -- which is THREAT_MODEL.md 2.5, silent code change
# mid-election. That is the one privilege here that must never be picked up
# implicitly from whatever `dfx identity use` happened to run last, so it is
# named. Override with DEPLOY_IDENTITY for a real deployment.
DEPLOY_IDENTITY="${DEPLOY_IDENTITY:-icvote-admin}"
dfx identity new --storage-mode plaintext "$DEPLOY_IDENTITY" </dev/null >/dev/null 2>&1 || true
echo "  deploying as $DEPLOY_IDENTITY ($(dfx identity get-principal --identity "$DEPLOY_IDENTITY"))"
dfx deploy --identity "$DEPLOY_IDENTITY" poll >/dev/null
dfx deploy --identity "$DEPLOY_IDENTITY" site >/dev/null
CID="$(dfx canister id poll)"

say "controllers of the deployed canisters"
# Printed rather than assumed: if this ever lists an identity nobody intended,
# that is a finding, and it should be visible in the check output.
dfx canister status --identity "$DEPLOY_IDENTITY" poll 2>&1 | grep -i "controllers" || true

say "end-to-end election"
tools/demo-election.sh

say "tamper detection"
tools/tamper-test.sh 0

say "frontend library tests (live)"
node tools/test-site-lib.mjs --live "$CID"

say "served bundle is byte-identical to source"
served="$(curl -sS "http://127.0.0.1:4943/index.html?canisterId=$(dfx canister id site)" | shasum -a 256 | cut -d' ' -f1)"
source_hash="$(shasum -a 256 site/index.html | cut -d' ' -f1)"
if [ "$served" != "$source_hash" ]; then
  echo "MISMATCH: served $served, source $source_hash"
  exit 1
fi
echo "  ok    $served"

echo ""
echo "All checks passed."
