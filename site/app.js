// The voter-facing app.
//
// Order of operations is the security property, not a UI preference: the
// provenance verdict is computed and rendered BEFORE the ballot exists in the
// DOM, and the ballot's enabled state is derived from that verdict rather than
// set alongside it. A layout where the ballot is present and later disabled
// has a window in which it is present and enabled.

import { configFromLocation } from "./config.js";
import { Agent, Ed25519Identity } from "./lib/agent.js";
import { toHex, fromHex } from "./lib/sha256.js";
import * as prov from "./lib/provenance.js";
import * as eh from "./lib/election-hash.js";
import { computeVerdict, GREEN, YELLOW, RED } from "./lib/verifier.js";

const $ = (id) => document.getElementById(id);
const el = (tag, props = {}, children = []) => {
  const node = Object.assign(document.createElement(tag), props);
  for (const c of [].concat(children)) node.append(c);
  return node;
};

const LAST_MODULE_HASH_KEY = "ic-vote.last-module-hash";
const IDENTITY_KEY = "ic-vote.identity.pkcs8";

const state = {
  config: null,
  agent: null,
  identity: null,
  elections: [],
  current: null, // { view, manifest, roll, log, head, board }
  verdict: null,
  acknowledged: false,
};

// --- boot -----------------------------------------------------------------

async function boot() {
  state.config = configFromLocation(typeof location !== "undefined" ? location : null);
  if (!state.config.pollCanisterId) {
    $("setup").classList.remove("hidden");
    $("setup-detail").textContent =
      "No poll canister configured. Set pollCanisterId in config.js, or append " +
      "?canister=<id>&host=<replica> for local development.";
    renderVerdict({ verdict: RED, checks: [], warnings: [], ballot: "blocked" },
      "No canister configured, so there is nothing to verify.");
    return;
  }

  state.agent = new Agent({ host: state.config.host, canisterId: state.config.pollCanisterId });
  state.identity = await loadOrCreateIdentity();

  try {
    state.elections = await state.agent.query("list_elections");
  } catch (e) {
    renderVerdict({ verdict: RED, checks: [], warnings: [], ballot: "blocked" },
      `Could not reach the poll canister: ${e.message}`);
    return;
  }
  renderElectionList();

  const openOnes = state.elections.filter((e) => "Open" in e.phase);
  if (openOnes.length === 1) await selectElection(openOnes[0].id);
  else if (state.elections.length === 1) await selectElection(state.elections[0].id);
  else {
    renderVerdict({ verdict: YELLOW, checks: [], warnings: [], ballot: "blocked" },
      "Pick an election. Provenance is verified per election, because the pinned " +
      "release is part of the election, not of this page.");
  }
}

// --- identity -------------------------------------------------------------

async function loadOrCreateIdentity() {
  const stored = localStorage.getItem(IDENTITY_KEY);
  if (stored) {
    try {
      return await Ed25519Identity.fromPkcs8(fromHex(stored));
    } catch {
      // A key we cannot load is a key we cannot vote with; replacing it is
      // better than a page that silently falls back to anonymous and then
      // reports NotEligible for reasons the voter cannot see.
      localStorage.removeItem(IDENTITY_KEY);
    }
  }
  const identity = await Ed25519Identity.generate();
  localStorage.setItem(IDENTITY_KEY, toHex(await identity.exportPkcs8()));
  return identity;
}

// --- election loading -----------------------------------------------------

async function selectElection(id) {
  const anon = new Agent({ host: state.config.host, canisterId: state.config.pollCanisterId });
  const view = unwrap(await anon.query("get_election", [["nat64", id]]));
  const head = unwrap(await anon.query("certified_head", [["nat64", id]]));
  const roll = await pageAll(anon, "get_roll", id, 10000n);
  const log = await pageAll(anon, "get_log", id, 1000n);
  let manifest = null;
  try {
    manifest = unwrap(await anon.query("get_manifest", [["nat64", id]]));
  } catch {
    // Draft elections have no frozen manifest yet.
  }

  state.current = { view, manifest, roll, log, head };
  state.acknowledged = false;
  renderElection();

  // Recompute the board before verifying provenance: the two are independent,
  // and a voter should see a recomputed tally even on a page that fails its
  // own provenance check. Failing provenance means "do not trust this page to
  // take your vote", not "hide the public record".
  if (manifest) {
    state.current.board = eh.recomputeBoard({ manifest, roll, log });
    renderBoard();
  }

  await verifyProvenance();
}

async function pageAll(agent, method, id, pageSize) {
  const out = [];
  for (let offset = 0n; ; offset += pageSize) {
    const page = unwrap(
      await agent.query(method, [["nat64", id], ["nat64", offset], ["nat64", pageSize]])
    );
    out.push(...page);
    if (BigInt(page.length) < pageSize) return out;
  }
}

function unwrap(result) {
  if (result && typeof result === "object" && "Ok" in result) return result.Ok;
  const err = result?.Err ?? result;
  throw new Error(describeError(err));
}

function describeError(err) {
  if (!err || typeof err !== "object") return String(err);
  const [key, value] = Object.entries(err)[0] ?? ["Unknown", null];
  switch (key) {
    case "NotEligible":
      return "You are not on this election's roll.";
    case "AlreadyVoted":
      return "This identity has already cast a ballot in this election.";
    case "WrongPhase":
      return `The election is ${value.actual}, not ${value.expected}.`;
    case "AnonymousCaller":
      return "An anonymous identity cannot vote.";
    case "InvalidChoice":
      return "That option does not exist on this ballot.";
    case "InvalidInput":
      return value;
    default:
      return key;
  }
}

// --- provenance -----------------------------------------------------------

async function verifyProvenance() {
  const pin = state.current?.manifest?.pin ?? null;

  const served = await attempt(() => prov.servedBundle(new URL("./index.html", location.href).href));
  const registryRecord = pin
    ? await attempt(async () => {
        const rpc = state.config.rpc[Number(pin.registry_chain_id)];
        if (!rpc) throw new Error(`no RPC endpoint configured for chain ${pin.registry_chain_id}`);
        // ic-git namespaces the served-site record; reading the bare repo name
        // would fetch the deploy-artifact record, whose bundleHash is the
        // sha256 of contract bytecode and would never match a page.
        return prov.registrySite(rpc, pin.registry_address, `${pin.repo}#site`);
      })
    : null;

  // Both canisters, not just the one serving this page. The poll canister is
  // the one that counts the ballots, so its code is at least as load-bearing
  // as the page's; reading only the site canister left an upgrade of the
  // tallying code invisible to every voter.
  const liveModuleHash = pin
    ? await attempt(() => prov.canisterModuleHash(state.agent, pin.site_canister))
    : null;
  const livePollModuleHash = pin
    ? await attempt(() => prov.canisterModuleHash(state.agent, state.config.pollCanisterId))
    : null;

  const attestations = [];
  if (pin && state.config.trusted.verifiers.length) {
    const rpc = state.config.rpc[Number(pin.registry_chain_id)];
    for (const verifier of state.config.trusted.verifiers) {
      const a = await attempt(() =>
        prov.registryAttestation(rpc, pin.registry_address, pin.site_canister, verifier)
      );
      if (a && !a.error) attestations.push(a);
    }
  }

  const verdict = computeVerdict({
    pin,
    served,
    registryRecord,
    liveModuleHash,
    livePollModuleHash,
    attestations,
    trusted: state.config.trusted,
    lastSeenModuleHash: localStorage.getItem(LAST_MODULE_HASH_KEY),
  });

  // Cache AFTER computing, so this load's own read cannot suppress the change
  // warning it should have raised.
  if (liveModuleHash?.hash) localStorage.setItem(LAST_MODULE_HASH_KEY, liveModuleHash.hash);

  state.verdict = verdict;
  renderVerdict(verdict);
  renderBallot();
}

/// Runs a reader and turns a throw into `{ error }` rather than letting it
/// abort the verdict. A check that could not run must reach the verdict as
/// UNKNOWN; an exception that skips the whole computation would leave the
/// page with no verdict at all, which reads as "fine" to a voter.
async function attempt(fn) {
  try {
    return await fn();
  } catch (e) {
    return { error: e.message };
  }
}

// --- rendering ------------------------------------------------------------

function renderVerdict(verdict, overrideSummary) {
  const badge = $("verdict-badge");
  badge.className = `badge ${verdict.verdict}`;
  badge.textContent = verdict.verdict;

  $("verdict-summary").textContent =
    overrideSummary ??
    {
      [GREEN]: "This page is the reviewed page. Everything checked, checked out.",
      [YELLOW]: "Some checks could not be completed. Read them before voting.",
      [RED]: "This page failed a provenance check. Do not vote on it.",
    }[verdict.verdict];

  const list = $("verdict-checks");
  list.replaceChildren(
    ...verdict.checks.map((c) =>
      el("li", {}, [
        // ASCII markers rather than check/cross glyphs: the whole bundle is
        // ASCII by policy (tools/check.sh asserts it), so its sha256 cannot
        // shift on an encoding difference between what a reviewer reads and
        // what the canister serves.
        el("span", {
          className: `state ${c.state}`,
          textContent: { OK: "OK", UNKNOWN: "??", BAD: "!!" }[c.state],
        }),
        el("span", {}, [c.label, el("span", { className: "detail", textContent: c.detail ?? "" })]),
      ])
    )
  );

  $("verdict-warnings").replaceChildren(
    ...verdict.warnings.map((w) => el("div", { className: "warning", textContent: w }))
  );
}

function renderElectionList() {
  if (state.elections.length <= 1) return;
  $("elections").classList.remove("hidden");
  $("election-list").replaceChildren(
    ...state.elections.map((e) =>
      el("li", {}, [
        el("button", {
          type: "button",
          onclick: () => selectElection(e.id),
        }, [
          el("div", { textContent: e.title }),
          el("div", {
            className: "meta",
            textContent: `${phaseName(e.phase)} - ${e.ballot_count}/${e.roll_size} voted`,
          }),
        ]),
      ])
    )
  );
}

const phaseName = (phase) => Object.keys(phase)[0];

function renderElection() {
  const { view, manifest, head } = state.current;
  $("election").classList.remove("hidden");
  $("election-title").textContent = view.title;
  $("election-question").textContent = view.question;

  const facts = [
    ["Phase", phaseName(view.phase)],
    ["Eligible", String(view.roll_size)],
    ["Ballots cast", String(view.ballot_count)],
    ["Log head", head.log_head],
  ];
  if (manifest) {
    facts.push(
      ["Manifest hash", manifest.manifest_hash],
      ["Pinned release", `${manifest.pin.repo} @ ${manifest.pin.commit}`],
      ["Pinned bundle", manifest.pin.bundle_sha256],
      ["Pinned module", manifest.pin.module_sha256]
    );
  }
  $("election-facts").replaceChildren(
    ...facts.flatMap(([k, v]) => [el("dt", { textContent: k }), el("dd", { textContent: v })])
  );

  $("identity-principal").textContent = state.identity.principalText;
  const onRoll = state.current.roll.includes(state.identity.principalText);
  const voted = state.current.log.some((b) => b.voter === state.identity.principalText);
  $("identity-status").textContent = voted
    ? "You have already voted in this election."
    : onRoll
      ? "You are on this election's roll."
      : "You are not on this election's roll, so this canister will refuse your ballot.";
}

function renderBallot() {
  const { view, manifest } = state.current ?? {};
  const form = $("ballot");
  const gate = $("ballot-gate");
  if (!view || !manifest) {
    gate.replaceChildren(el("div", { className: "blocked", textContent: "This election has not opened yet." }));
    form.replaceChildren();
    return;
  }

  const v = state.verdict ?? { ballot: "blocked" };
  const open = "Open" in view.phase;
  const alreadyVoted = state.current.log.some((b) => b.voter === state.identity.principalText);

  if (!open) {
    gate.replaceChildren(
      el("div", { className: "blocked", textContent: `Voting is ${phaseName(view.phase)}.` })
    );
  } else if (v.ballot === "blocked") {
    // THREAT_MODEL.md 4: a RED verdict during an open voting window is an
    // incident, not a warning banner.
    gate.replaceChildren(
      el("div", {
        className: "blocked",
        textContent:
          "The ballot is disabled because this page failed a provenance check. " +
          "This is not a warning to click past: report it to the election administrator.",
      })
    );
  } else if (v.ballot === "requires-acknowledgement" && !state.acknowledged) {
    const box = el("input", { type: "checkbox", onchange: (e) => { state.acknowledged = e.target.checked; renderBallot(); } });
    gate.replaceChildren(
      el("div", { className: "acknowledge" }, [
        el("label", {}, [
          box,
          el("span", {
            textContent:
              "Some provenance checks above could not be completed. I have read them and " +
              "accept that this page's integrity is not fully established.",
          }),
        ]),
      ])
    );
  } else {
    gate.replaceChildren();
  }

  const votable = open && !alreadyVoted &&
    (v.ballot === "allowed" || (v.ballot === "requires-acknowledgement" && state.acknowledged));

  const fieldset = el("fieldset", { disabled: !votable });
  view.options.forEach((option, i) => {
    fieldset.append(
      el("label", {}, [
        el("input", { type: "radio", name: "choice", value: String(i) }),
        el("span", { textContent: option }),
      ])
    );
  });
  const submit = el("button", { type: "submit", textContent: "Cast ballot", disabled: !votable });
  form.replaceChildren(fieldset, submit);
  form.onsubmit = onCast;
}

async function onCast(event) {
  event.preventDefault();
  const chosen = event.target.querySelector('input[name="choice"]:checked');
  if (!chosen) return;
  const button = event.target.querySelector('button[type="submit"]');
  button.disabled = true;
  button.textContent = "Casting...";
  try {
    const signing = new Agent({
      host: state.config.host,
      canisterId: state.config.pollCanisterId,
      identity: state.identity,
    });
    const { value } = await signing.call("cast", [
      ["nat64", state.current.view.id],
      ["nat32", Number(chosen.value)],
    ]);
    const receipt = unwrap(value);
    $("receipt").classList.remove("hidden");
    $("receipt-body").textContent = [
      `election   ${receipt.election_id}`,
      `voter      ${receipt.voter}`,
      `choice     ${state.current.view.options[receipt.choice]} (#${receipt.choice})`,
      `sequence   ${receipt.seq}`,
      `entry hash ${receipt.entry_hash}`,
    ].join("\n");
    await selectElection(state.current.view.id);
  } catch (e) {
    button.textContent = "Cast ballot";
    button.disabled = false;
    $("ballot-gate").replaceChildren(el("div", { className: "blocked", textContent: e.message }));
  }
}

function renderBoard() {
  const { board, manifest, head } = state.current;
  const rows = manifest.options.map((option, i) =>
    el("tr", {}, [
      el("td", { textContent: option }),
      el("td", { className: "count", textContent: String(board.counts[i]) }),
    ])
  );
  const problems = board.problems.length
    ? [el("div", { className: "blocked", textContent: `Board does not verify: ${board.problems[0]}` })]
    : [];

  // The certified head is a separate claim from the recomputed board: the
  // board says "these ballots produce this head", the certificate says "the
  // canister's state commits to this head". Both, or neither is worth much.
  const leaf = eh.merkleLeaf(manifest.id, board.manifestHash, board.logHead, head.ballot_count);
  const root = eh.merkleRecompute(leaf, head.witness);

  $("board").replaceChildren(
    ...problems,
    el("table", {}, [el("tbody", {}, rows)]),
    el("dl", { className: "facts" }, [
      el("dt", { textContent: "Recomputed head" }), el("dd", { textContent: board.logHead }),
      el("dt", { textContent: "Recomputed tally hash" }), el("dd", { textContent: board.tallyHash }),
      el("dt", { textContent: "Merkle root from witness" }), el("dd", { textContent: root }),
    ])
  );

  $("export").onclick = () => {
    const bulletin = {
      canister: state.config.pollCanisterId,
      election: state.current.view,
      manifest,
      roll: state.current.roll,
      log: state.current.log,
      certified_head: head,
    };
    const json = JSON.stringify(bulletin, (_k, v) => (typeof v === "bigint" ? String(v) : v), 2);
    const url = URL.createObjectURL(new Blob([json], { type: "application/json" }));
    const a = el("a", { href: url, download: `ic-vote-election-${manifest.id}.json` });
    a.click();
    URL.revokeObjectURL(url);
  };
}

boot().catch((e) => {
  renderVerdict({ verdict: RED, checks: [], warnings: [], ballot: "blocked" },
    `The page failed to start: ${e.message}. Nothing has been verified.`);
});
