#!/usr/bin/env bash
# Stage ic-vote as the repo that gets pushed to ic-git.
#
#   tools/stage-ic-git.sh --poll-canister ID [--git-canister ID] [--out DIR]
#
# ic-vote is deployed by pushing to ic-git, not by hand (README, "Why this is
# a separate repo"), and its two canisters ride two different ic-git
# mechanisms: the poll canister is installed by the deploy queue from
# app.wasm in the pushed commit (set_wasm_deploy), and the ballot page is
# served straight out of the commit tree (set_site). This stages one tree
# that satisfies both:
#
#   DIR/app.wasm            the poll canister, built --locked from this tree
#   DIR/site/               the page, rendered for this deployment
#                           (tools/stage-site.mjs: canister id in, SRI on)
#   DIR/Cargo.toml, Cargo.lock, canisters/poll/
#                           what reproduces app.wasm, so the repo browser
#                           shows the source of what was installed
#
# The poll canister id is an input, not something this script creates: it
# exists once ic-git has created the repo's app canister, and the page must
# be rendered against it. The ic-git calls that consume the tree are printed
# at the end. Nothing here touches a network.
set -euo pipefail
cd "$(dirname "$0")/.."

out=dist
poll=""
git_id=""
while [ $# -gt 0 ]; do
  case "$1" in
    --poll-canister) poll=$2; shift 2 ;;
    --git-canister)  git_id=$2; shift 2 ;;
    --out)           out=$2; shift 2 ;;
    -h|--help)       sed -n '2,22p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
if [ -z "$poll" ]; then
  echo "usage: tools/stage-ic-git.sh --poll-canister ID [--git-canister ID] [--out DIR]" >&2
  exit 2
fi

say() { printf '\n== %s\n' "$*"; }

say "poll canister, built --locked"
cargo build -p ic_vote_poll --release --target wasm32-unknown-unknown --locked
wasm=target/wasm32-unknown-unknown/release/ic_vote_poll.wasm

say "stage $out"
rm -rf "$out"
mkdir -p "$out/canisters/poll"
cp "$wasm" "$out/app.wasm"
cp Cargo.toml Cargo.lock "$out/"
cp canisters/poll/Cargo.toml canisters/poll/poll.did "$out/canisters/poll/"
cp -R canisters/poll/src "$out/canisters/poll/src"

site_args=(--src site --out "$out/site" --poll-canister "$poll")
[ -n "$git_id" ] && site_args+=(--git-canister "$git_id")
node tools/stage-site.mjs "${site_args[@]}"

wasm_sha=$(shasum -a 256 "$out/app.wasm" | cut -d' ' -f1)
# The source this rendering came from. "-dirty" means the working tree had
# uncommitted edits, so no commit reproduces it exactly; fine for a local
# run, not for anything a pin will point at.
src=$(git rev-parse HEAD 2>/dev/null || echo unknown)
[ -z "$(git status --porcelain 2>/dev/null)" ] || src="$src-dirty"
printf '%s\n' "$src" > "$out/SOURCE_COMMIT"
cat > "$out/README.md" <<README
# ic-vote, staged for ic-git

This tree was produced by \`tools/stage-ic-git.sh\` in the ic-vote repository
at commit \`$src\` (also in \`SOURCE_COMMIT\`) and is what gets pushed to the
ic-git canister. It is not the development tree; the page under \`site/\`
has been rendered for one deployment, and \`tools/stage-site.mjs\` at that
commit reproduces the rendering from \`site/\` there, given the two ids
below.

- \`app.wasm\`: the poll canister. sha256 \`$wasm_sha\`. Reproduce it from
  the sources here with \`cargo build -p ic_vote_poll --release --target
  wasm32-unknown-unknown --locked\` (rust-toolchain and profile as in
  \`Cargo.toml\`).
- \`site/\`: the ballot page. \`config.js\` names the poll canister
  (\`$poll\`); \`index.html\` carries an \`integrity\` hash for each file it
  loads, which ic-git requires before it will serve the page.
- \`Cargo.toml\`, \`Cargo.lock\`, \`canisters/poll/\`: the source of \`app.wasm\`.

ic-git configuration this tree expects, on the repo it is pushed to:

    set_wasm_deploy(repo, "app", "app.wasm")   installs app.wasm on push
    set_site(repo, "site")                     serves site/ at /site/<repo>/
README

say "staged"
echo "app.wasm   $(wc -c < "$out/app.wasm" | tr -d ' ') bytes  sha256 $wasm_sha"
echo "site/      $(find "$out/site" -type f | wc -l | tr -d ' ') files"
echo
echo "ic-git calls that consume this tree (repo REPO, from an owner or operator):"
echo "  set_wasm_deploy(\"REPO\", \"app\", \"app.wasm\")"
echo "  set_site(\"REPO\", \"site\")"
