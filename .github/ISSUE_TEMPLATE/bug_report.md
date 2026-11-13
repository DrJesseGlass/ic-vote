---
name: Bug report
about: Something ic-vote does wrong. Security problems go to the private form instead (SECURITY.md).
title: ''
labels: bug
assignees: ''
---

<!-- If this is a security problem, stop: report it privately at
     https://github.com/DrJesseGlass/ic-vote/security/advisories/new -->

## Where

Which piece: the poll canister (its id, on mainnet or a local replica), the
ballot page (the URL it was served from), the CLI verifier
(`tools/verify-election.mjs`), the staging and push tools
(`tools/stage-ic-git.sh`, `tools/push-ic-git.sh`), or `tools/check.sh`. The
commit you are on, or the pinned release the page shows.

## What you did

The exact commands, URL, or clicks. For `tools/check.sh`, whether it was
run with `--live`.

## What happened

Output, error text, or a screenshot. Paste text as text. For the ballot
page, the verdict it showed (GREEN, YELLOW or RED) and the checks listed
under it.

## What you expected

## Anything else

Election id, browser and version, dfx version for a local replica. A
principal or a public key is fine; never a push token or a private key.
