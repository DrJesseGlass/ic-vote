#!/usr/bin/env bash
# Push ic-vote to ic-git and watch it deploy. No dfx and no identity here:
# everything a wallet can do is done in the ic-git console, and this does
# only the rest -- stage, commit, push with the token, read the public
# /api routes to see it land.
#
#   tools/push-ic-git.sh --repo NAME [--git-canister ID] [--network ic|local] [--port N]
#
# Before running, in the console, signed in as the wallet that owns NAME:
# create the repo, create its app canister, set "deploy on push" to
# app.wasm, set "serve as site" to site, and mint a push token. Give the
# token as IC_GIT_TOKEN in the environment or type it at the prompt; it
# never goes on a command line and is never printed.
#
# What happens, in order, and what is checked before anything is pushed:
#   1. /api/NAME/info must name an app canister: the page is rendered
#      against it, so there is nothing to stage without one.
#   2. /api/NAME/deploys must say app.wasm deploys into that canister;
#      otherwise the push would land and install nothing, silently.
#   3. tools/stage-ic-git.sh produces dist/.
#   4. dist/ is committed on top of the repo's current tip and pushed.
#      ic-git refuses anything but a fast-forward, so a stale local copy
#      is refused rather than merged.
#   5. /api/NAME/deploys is polled until the deploy of that commit reports,
#      and /site/NAME/ is checked to be serving it.
set -euo pipefail
cd "$(dirname "$0")/.."

repo=""; git_id=""; network=ic; port=4943; out=dist
while [ $# -gt 0 ]; do
  case "$1" in
    --repo)         repo=$2; shift 2 ;;
    --git-canister) git_id=$2; shift 2 ;;
    --network)      network=$2; shift 2 ;;
    --port)         port=$2; shift 2 ;;
    -h|--help)      sed -n '2,25p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
[ -n "$repo" ] || { echo "usage: tools/push-ic-git.sh --repo NAME [--git-canister ID] [--network ic|local] [--port N]" >&2; exit 2; }
case "$network" in
  ic)    git_id=${git_id:-umobs-yiaaa-aaaab-agyrq-cai}; scheme=https; host="$git_id.raw.icp0.io" ;;
  local) [ -n "$git_id" ] || { echo "--git-canister is required with --network local" >&2; exit 2; }
         scheme=http; host="$git_id.raw.localhost:$port" ;;
  *) echo "--network must be ic or local" >&2; exit 2 ;;
esac
origin="$scheme://$host"

say() { printf '\n== %s\n' "$*"; }
api() { curl -sS -f -A ic-vote-push "$origin/api/$1"; }
# One field of a JSON document on stdin, by dotted path; empty when absent.
# node is already required by the staging step.
jget() {
  node -e 'const d = JSON.parse(require("fs").readFileSync(0, "utf8"));
    const v = process.argv[1].split(".").reduce((o, k) => (o == null ? o : o[k]), d);
    process.stdout.write(v == null ? "" : String(v));' "$1"
}

say "repo '$repo' on $git_id ($network)"
if ! info=$(api "$repo/info" 2>/dev/null); then
  echo "no such repo on ic-git: $repo. Create it in the console first." >&2; exit 1
fi
app=$(printf '%s' "$info" | jget app_canister)
if [ -z "$app" ]; then
  echo "repo '$repo' has no app canister. In the console, on the repo page, create one; the page is rendered against its id." >&2; exit 1
fi
echo "app canister    : $app"
deploys=$(api "$repo/deploys")
cfg_path=$(printf '%s' "$deploys" | jget config.source_path)
cfg_target=$(printf '%s' "$deploys" | jget config.target)
if [ "$cfg_path" != "app.wasm" ] || [ "$cfg_target" != "$app" ]; then
  echo "deploy on push is not set to app.wasm into the app canister (found path '${cfg_path:-none}', target '${cfg_target:-none}')." >&2
  echo "Set it in the console before pushing, or the push lands and installs nothing." >&2; exit 1
fi
echo "deploy on push  : app.wasm -> $app"

say "push token"
if [ -z "${IC_GIT_TOKEN:-}" ]; then
  read -rs -p "token for '$repo', minted in the console (not echoed): " IC_GIT_TOKEN; echo
fi
[ -n "$IC_GIT_TOKEN" ] || { echo "no token given" >&2; exit 1; }
case "$IC_GIT_TOKEN" in
  *[!0-9a-f]*) echo "that is not a push token (lowercase hex)" >&2; exit 1 ;;
esac
echo "ok"

say "stage"
tools/stage-ic-git.sh --poll-canister "$app" --git-canister "$git_id" --out "$out" >/dev/null
wasm_sha=$(shasum -a 256 "$out/app.wasm" | cut -d' ' -f1)
src=$(cat "$out/SOURCE_COMMIT")
echo "source          : ic-vote $src"
case "$src" in *-dirty) echo "                  (uncommitted edits: no ic-vote commit reproduces this push; commit first before pinning an election to it)" ;; esac
echo "app.wasm sha256 : $wasm_sha"
echo "site            : $(find "$out/site" -type f | wc -l | tr -d ' ') files, rendered for $app"

say "push"
# Each run commits on top of whatever ic-git already holds: dist/ is staged
# fresh, then HEAD is moved to the remote tip (if there is one) before the
# commit, so the new commit's parent is the remote's and its tree is
# exactly dist/. ic-git refuses non-fast-forward pushes.
rm -rf "$out/.git"
git -C "$out" init -q -b main
git -C "$out" add -A
if git -C "$out" fetch -q "$origin/$repo.git" main 2>/dev/null; then
  git -C "$out" reset -q --soft FETCH_HEAD
fi
if git -C "$out" -c user.name="ic-vote" -c user.email="ic-vote@ic-git.invalid" \
    commit -q -m "ic-vote, staged for ic-git

source   ic-vote $src
poll     $app
app.wasm sha256 $wasm_sha" >/dev/null 2>&1; then
  commit=$(git -C "$out" rev-parse HEAD)
  # The token is the credential: it goes in the URL git is handed and
  # nowhere else. git prints the remote without it.
  git -C "$out" push -q "$scheme://ic:$IC_GIT_TOKEN@$host/$repo.git" main
  echo "pushed $commit"
else
  commit=$(git -C "$out" rev-parse HEAD)
  echo "nothing new: $commit is already the tip on ic-git"
fi

say "deploy"
# Success is a status for the commit just pushed, not any ok: a previous
# run's result would otherwise pass while this push is still queued.
st_commit=""; st_ok=""; st_msg=""
for _ in $(seq 1 60); do
  d=$(api "$repo/deploys" 2>/dev/null || echo '{}')
  st_commit=$(printf '%s' "$d" | jget status.commit)
  st_ok=$(printf '%s' "$d" | jget status.ok)
  st_msg=$(printf '%s' "$d" | jget status.message)
  if [ "$st_commit" = "$commit" ]; then
    if [ "$st_ok" = "true" ]; then break; fi
    if [ "$st_msg" != "deploying" ]; then echo "deploy failed: $st_msg" >&2; exit 1; fi
  fi
  sleep 2
done
if [ "$st_commit" != "$commit" ] || [ "$st_ok" != "true" ]; then
  echo "timed out waiting for the deploy of $commit; last status: '${st_msg:-none}' for '${st_commit:-none}'" >&2; exit 1
fi
echo "installed       : $st_msg"
echo "wasm on chain   : $(printf '%s' "$d" | jget status.wasm_sha256)"

say "site"
served=$(curl -sS -A ic-vote-push -D - -o /dev/null "$origin/site/$repo/" 2>/dev/null | sed -n 's/^x-ic-git-commit: *//Ip' | tr -d '\r' || true)
if [ "$served" = "$commit" ]; then
  echo "serving         : $origin/site/$repo/  (commit $commit)"
else
  echo "NOT SERVED: /site/$repo/ is ${served:+at $served}${served:-not configured}. Set 'serve as site' to site in the console; the deploy above is done regardless." >&2
fi

say "done"
echo "ballot page : $origin/site/$repo/"
echo "poll        : $app"
echo "commit      : $commit"
echo "app.wasm    : $wasm_sha"
