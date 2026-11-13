#!/usr/bin/env bash
# Is the hold on sha2 0.10 and ed25519-dalek 2 still needed?
#
#   tools/check-digest-hold.sh
#
# sha2 0.11 and ed25519-dalek 3 are out, and Dependabot is told not to
# propose them (.github/dependabot.yml). The reason is not this repo's
# code, which builds and passes on both: it is that other crates in the
# graph still require sha2 0.10, so taking the bump puts two copies of
# sha2, digest, block-buffer and crypto-common in the module, which the
# dependency gate refuses (deny.toml, bans). ed25519-dalek 3 needs sha2
# 0.11, so the two move together or not at all.
#
# What is in the way is not always reachable by a compatible update: today
# it is ic_principal, which comes in through candid, and it has been a
# direct dependency held on an older line (ic-multisig, until 0.2.1 took
# either sha2). So the question asked here is the widest one: with EVERY direct dependency at its latest release, is there
# one sha2 in the graph? This makes that bump in a throwaway copy of the
# workspace, resolves it, and reads the result:
#
#   exit 0   still held. Even at the latest of everything, something
#            requires the old sha2; the crates that do are named. Nothing
#            to do.
#   exit 1   the hold can be lifted: one sha2 in the graph. The
#            requirements that had to move are printed, with whether the
#            canister tests pass on them as they are. This is the exit the
#            scheduled workflow (digest-hold-watch.yml) turns into a red
#            run and an email, in the manner of ic-git's module-hash-watch:
#            the failure is the news.
#   exit 2   the check itself could not run. Read the output.
#
# Needs the network (cargo asks crates.io for the latest versions and
# resolves against it). Touches nothing in this tree: the copy, its
# lockfile and its target directory are under a temporary directory that is
# removed on exit.
set -euo pipefail
cd "$(dirname "$0")/.."

# The crate whose duplication is the question. digest, block-buffer and
# crypto-common follow it.
probe=sha2
package=ic_vote_poll

say() { printf '\n== %s\n' "$*"; }
broken() { echo "CHECK BROKEN: $*" >&2; exit 2; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
export CARGO_TARGET_DIR="$tmp/target"
ws="$tmp/ws"

# Versions of a crate in the graph the module is built from: the wasm32
# target, no dev-dependencies -- the graph deny.toml looks at.
versions_of() {
  (cd "$ws" && cargo tree --locked --target wasm32-unknown-unknown \
      -e normal,build --prefix none --format '{p}') \
    | awk -v c="$1" '$1 == c { print $2 }' | sort -u
}

say "copy the workspace"
git ls-files -z Cargo.toml Cargo.lock rust-toolchain.toml canisters \
  | while IFS= read -r -d '' f; do
      mkdir -p "$ws/$(dirname "$f")"
      cp "$f" "$ws/$f"
    done
[ -f "$ws/canisters/poll/Cargo.toml" ] || broken "no canisters/poll/Cargo.toml in the copy"

# The hold only means something while the committed graph is on one sha2.
before="$(versions_of "$probe")"
[ -n "$before" ] || broken "no $probe in the committed graph"
[ "$(printf '%s\n' "$before" | wc -l | tr -d ' ')" = 1 ] \
  || broken "the committed graph already carries more than one $probe: $(printf '%s' "$before" | tr '\n' ' ')"

say "every direct dependency to its latest release"
# Direct dependencies and their requirements, from the manifest as cargo
# reads it. Fields are tab-separated: name, requirement.
deps="$(cd "$ws" && cargo metadata --locked --no-deps --format-version 1 \
  | node -e '
      const m = JSON.parse(require("fs").readFileSync(0, "utf8"));
      const p = m.packages.find((p) => p.name === process.argv[1]);
      if (!p) process.exit(3);
      for (const d of p.dependencies) if (d.kind === null) console.log(d.name + "\t" + d.req);
    ' "$package")" || broken "could not read $package's dependencies"
[ -n "$deps" ] || broken "$package has no dependencies, which is not this repo"

moved=""
while IFS=$'\t' read -r name req; do
  # `cargo search` prints `name = "version"    # description` for each match;
  # the exact name is picked out, since the first match can be a neighbour.
  latest="$(cargo search --limit 20 "$name" 2>/dev/null \
    | awk -v n="$name" '$1 == n && $2 == "=" { gsub(/"/, "", $3); print $3; exit }')"
  [ -n "$latest" ] || broken "crates.io named no latest version for $name"
  (cd "$ws" && cargo add -q -p "$package" "$name@$latest" 2>"$tmp/add.err") \
    || { cat "$tmp/add.err" >&2; broken "cargo add $name@$latest failed"; }
  printf '  %-16s %-8s -> %s\n' "$name" "$req" "$latest"
  moved="$moved$name $req $latest"$'\n'
done <<EOF
$deps
EOF

say "resolve"
(cd "$ws" && cargo update -q 2>"$tmp/resolve.err") \
  || { cat "$tmp/resolve.err" >&2; broken "cargo could not resolve the bumped manifest"; }
after="$(versions_of "$probe")"
[ -n "$after" ] || broken "no $probe in the resolved graph"
count="$(printf '%s\n' "$after" | wc -l | tr -d ' ')"
echo "  $probe in the module's graph: $(printf '%s' "$after" | tr '\n' ' ')"

if [ "$count" -gt 1 ]; then
  say "still held"
  old="$(printf '%s\n' "$after" | head -1)"
  echo "With everything at its latest release, these are still on $probe ${old#v}:"
  (cd "$ws" && cargo tree --locked --target wasm32-unknown-unknown \
      -e normal,build -i "$probe@${old#v}" --depth 1 --prefix none --format '{p}') \
    | sed 's/ (.*//' | awk -v c="$probe" 'NF && $1 != c' | sort -u | sed 's/^/  /'
  echo ""
  echo "The hold stays until each of them has a release on the new $probe."
  echo "Nothing to do."
  exit 0
fi

say "one $probe in the graph; canister tests on it"
if (cd "$ws" && cargo test --locked -q -p "$package" >"$tmp/test.log" 2>&1); then
  tests="pass as the code stands"
else
  tail -40 "$tmp/test.log"
  tests="FAIL as the code stands (above): the migration needs code changes"
fi

say "THE HOLD CAN BE LIFTED"
cat <<MSG
With every direct dependency at its latest release, one $probe is left in
the graph (${after}). The canister tests $tests.

To lift it:

  1. canisters/poll/Cargo.toml: move the requirements listed above under
     "every direct dependency" (not all of them need to move; find the
     smallest set that leaves one $probe).
  2. cargo update, then tools/check.sh --live and cargo deny check.
  3. .github/dependabot.yml: remove the sha2 and ed25519-dalek entries
     from \`ignore\`.
  4. Delete tools/check-digest-hold.sh and
     .github/workflows/digest-hold-watch.yml, and the rough edge in
     docs/V0_STATUS.md.

It is a new Cargo.lock, so a new module hash: a push to ic-git, a vote,
and a new ic-vote#app record. Coordinate with ic-git, which holds the
same crates for the same reason.
MSG
exit 1
