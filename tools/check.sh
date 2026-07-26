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

# Two identities, deliberately distinct.
#
# The DEPLOYER becomes the canisters' CONTROLLER, and a controller can upgrade
# a canister -- THREAT_MODEL.md 2.5, silent code change mid-election. The ADMIN
# opens and closes elections and uploads the roll (T6, plus T4). Collapsing
# them into one key, as an earlier version of this script did, means whoever
# holds the administrator's key can also replace the code that counts the
# ballots, which is exactly the separation docs/V0_STATUS.md claims exists.
#
# Both are throwaway identities scoped to this local test run, and both names
# are prefixed `icvote-localtest-` so they cannot collide with an identity an
# operator created for a real deployment. This script deploys ONLY to a local
# replica it wipes (see `dfx start --clean` above and the EXIT trap); it is not
# a deployment tool, and the overrides below exist for running the checks under
# names of your choosing, not for shipping to mainnet.
DEPLOY_IDENTITY="${DEPLOY_IDENTITY:-icvote-localtest-deployer}"
ADMIN_IDENTITY="${ADMIN_IDENTITY:-icvote-localtest-admin}"
export ADMIN_IDENTITY

# `dfx identity new` cannot tell us whether it created the identity or found
# one already there, and deploying under key material this script did not
# create -- possibly an operator's real key that happens to share the name --
# is exactly the "controller nobody chose" failure the separation above is for.
# So: create only when absent, and say which happened.
ensure_identity() {
  local name="$1" role="$2"
  if dfx identity get-principal --identity "$name" </dev/null >/dev/null 2>&1; then
    echo "  $role: reusing existing identity '$name'"
  else
    # plaintext because this is a throwaway for a local replica and an
    # encrypted key would block on a passphrase prompt in a non-interactive
    # run. Never use --storage-mode plaintext for a key that controls anything
    # real.
    dfx identity new --storage-mode plaintext "$name" </dev/null >/dev/null 2>&1
    echo "  $role: created throwaway identity '$name'"
  fi
  # Assigned on its own line, not inside an argument to `echo`: a command
  # substitution that fails as an argument has its exit status discarded, so
  # `set -e` would not fire and the audit line would print an empty principal.
  local principal
  principal="$(dfx identity get-principal --identity "$name" </dev/null)"
  if [ -z "$principal" ]; then
    echo "FAILED: could not resolve a principal for '$name'"
    exit 1
  fi
  echo "         $principal"
}

ensure_identity "$DEPLOY_IDENTITY" "deployer (controller)"
ensure_identity "$ADMIN_IDENTITY" "administrator"

dfx deploy --identity "$DEPLOY_IDENTITY" poll >/dev/null
dfx deploy --identity "$DEPLOY_IDENTITY" site >/dev/null
CID="$(dfx canister id poll)"

say "controller audit"
# Asserted, not printed. An earlier version of this step piped `dfx canister
# status` into grep and swallowed the pipeline with `|| true`, so an unintended
# controller could never fail the run -- and an empty section was
# indistinguishable from a healthy one while the script still printed
# "All checks passed".
#
# Both canisters are audited. The site canister is if anything the more
# security-relevant of the two, since its controller can replace the ballot
# page itself, and the previous version queried only `poll`.
expected_controller="$(dfx identity get-principal --identity "$DEPLOY_IDENTITY" </dev/null)"
audit_controllers() {
  # Not named `status`: that is a read-only special variable in zsh, so a
  # reader who runs this under zsh instead of bash gets an assignment error
  # from the middle of a security check.
  local canister="$1" report controllers
  # stderr kept separate: folded into stdout, a dfx rejection message can
  # contain the word "controllers" and masquerade as a controller list.
  if ! report="$(dfx canister status --identity "$DEPLOY_IDENTITY" "$canister" 2>/dev/null)"; then
    echo "FAILED: could not read status for canister '$canister'"
    exit 1
  fi
  # Match "Controllers:" and "Controller:" -- dfx has used both spellings, and
  # a grep that silently matches neither is the fail-open case again.
  controllers="$(printf '%s\n' "$report" | sed -n 's/^ *Controllers\{0,1\}: *//p')"
  if [ -z "$controllers" ]; then
    echo "FAILED: no controller line in 'dfx canister status $canister'"
    exit 1
  fi
  echo "  $canister: $controllers"
  for got in $controllers; do
    # The local cycles wallet dfx creates for the deployer is itself a
    # controller; it is derived from the deployer and is expected.
    if [ "$got" = "$expected_controller" ]; then continue; fi
    if [ "$got" = "$(dfx identity get-wallet --identity "$DEPLOY_IDENTITY" 2>/dev/null)" ]; then continue; fi
    echo "FAILED: '$canister' has unexpected controller $got"
    echo "        expected only $expected_controller (and its cycles wallet)"
    exit 1
  done
}
audit_controllers poll
audit_controllers site
echo "  ok    every controller accounted for"

say "end-to-end election"
ADMIN_IDENTITY="$ADMIN_IDENTITY" tools/demo-election.sh

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
