#!/usr/bin/env bash
# Negative tests for tools/verify-election.mjs.
#
# A verifier that agrees with the canister proves nothing on its own -- a
# verifier that always prints PASS would look identical on a healthy election.
# This script takes a real bulletin, corrupts it one way at a time, and
# requires a RED verdict for each corruption. It is the test that gives the
# PASS lines meaning.
#
# Run after tools/demo-election.sh:
#   tools/tamper-test.sh [election-id]
set -euo pipefail

ID="${1:-0}"
NETWORK="${NETWORK:-local}"
# Named, not ambient, for the same reason as everywhere else in tools/: an
# encrypted operator identity turns these reads into a keychain prompt that
# looks exactly like a hang.
ADMIN="${ADMIN_IDENTITY:-icvote-localtest-admin}"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

CID="$(dfx canister id --network "$NETWORK" --identity "$ADMIN" poll)"
node "$HERE/verify-election.mjs" --fetch "$ID" --network "$NETWORK" \
  --identity "$ADMIN" --canister "$CID" --save "$WORK/bulletin.json" >/dev/null

# A principal that is deliberately NOT on the roll. Any valid principal that
# cannot be a voter works; the management canister's is stable and cannot be
# the sha224-derived principal of any Ed25519 credential.
OUTSIDER="aaaaa-aa"

failures=0
expect_red() {
  local label="$1" mutation="$2"
  node -e "
    const fs = require('fs');
    const b = JSON.parse(fs.readFileSync('$WORK/bulletin.json', 'utf8'));
    const OUTSIDER = '$OUTSIDER';
    // Flip the low bit of the first hex byte: minimal, always-valid-hex
    // corruption that never needs a second ballot to exist.
    const flipHex = (s) => (parseInt(s.slice(0, 2), 16) ^ 1).toString(16).padStart(2, '0') + s.slice(2);
    $mutation;
    fs.writeFileSync('$WORK/tampered.json', JSON.stringify(b));
  "
  if node "$HERE/verify-election.mjs" --file "$WORK/tampered.json" >"$WORK/out" 2>&1; then
    printf 'MISSED  %s -- verifier did NOT go RED\n' "$label"
    sed 's/^/        /' "$WORK/out"
    failures=$((failures + 1))
  else
    printf 'CAUGHT  %s\n' "$label"
    grep '^FAIL' "$WORK/out" | head -2 | sed 's/^/        /'
  fi
}

echo "tamper tests against election $ID on $CID"
echo ""

expect_red "flip a recorded vote"                    "b.log[0].choice = (b.log[0].choice + 1) % b.manifest.options.length"
expect_red "stuff a ballot from a non-member"        "b.log.push({...b.log[0], seq: String(b.log.length), voter: OUTSIDER})"
expect_red "silently drop a ballot"                  "b.log.pop()"
expect_red "reorder the log"                         "b.log.reverse()"
expect_red "backdate a ballot's timestamp"           "b.log[0].at = String(BigInt(b.log[0].at) - 1n)"
# The credential mutations index only b.log[0]: an earlier version swapped
# fields with b.log[1], which crashed the whole suite (set -e) on any
# election with a single ballot instead of testing it.
expect_red "corrupt a ballot's signature"            "b.log[0].sig = flipHex(b.log[0].sig)"
expect_red "substitute a ballot's credential key"    "b.log[0].voter_pubkey = b.log[0].voter_pubkey.slice(0, -2) + flipHex(b.log[0].voter_pubkey.slice(-2))"
expect_red "point a ballot at a different voter"     "b.log[0].voter = OUTSIDER"
expect_red "extend a signature's expiry after the fact" "b.log[0].sig_expires_at = String(BigInt(b.log[0].sig_expires_at) + 1n)"
# Verifier robustness, not just detection: these two used to kill the process
# (BigInt-on-undefined in check E; lenient Buffer.from hex accepting what the
# browser rejects), which reads as a verifier bug instead of a RED verdict.
expect_red "out-of-range choice in the log"          "b.log[0].choice = 99"
expect_red "uppercase-hex credential"                "b.log[0].voter_pubkey = b.log[0].voter_pubkey.toUpperCase()"
expect_red "enrol a voter after the fact"            "b.roll.push(OUTSIDER)"
expect_red "drop a voter from the published roll"    "b.roll.pop()"
expect_red "repoint the election at another bundle"  "b.manifest.pin.bundle_sha256 = 'f'.repeat(64)"
expect_red "swap the pinned module hash"             "b.manifest.pin.module_sha256 = 'e'.repeat(64)"
expect_red "reword the question after the fact"      "b.manifest.question = 'Which rung is easiest?'"
expect_red "rename an option after the fact"         "b.manifest.options[0] = 'Something else entirely'"
# The trustee policy is inside the manifest hash: neither the list nor the
# threshold can be edited after the trustees approved it.
expect_red "add a trustee after the fact"            "b.manifest.trustees.push(OUTSIDER)"
expect_red "lower the trustee threshold after the fact" "b.manifest.threshold = 0"
# And the attestation itself: an approval must come from a listed trustee
# and be on the tally hash the verifier recomputes, not on some other bytes.
# These need an election that required trustees; demo-election.sh does.
expect_red "forge a trustee approval from an outsider" "b.approvals.ballots[0].trustee = OUTSIDER"
expect_red "point the trustee approvals at another tally" "b.approvals.subject = flipHex(b.approvals.subject)"
expect_red "forge the head to match a forged log"    "b.log.pop(); b.certified_head.log_head = b.log[b.log.length-1].entry_hash; b.certified_head.ballot_count = String(b.log.length)"

echo ""
if [ "$failures" -gt 0 ]; then
  echo "TAMPER TESTS FAILED: $failures corruption(s) went undetected."
  exit 1
fi
echo "All corruptions detected."
