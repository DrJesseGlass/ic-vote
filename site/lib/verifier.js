// The verdict: GREEN / YELLOW / RED, per THREAT_MODEL.md section 4.
//
// Pure. Every input is passed in, nothing is fetched here, so the whole rule
// set is exercised by tools/test-site-lib.mjs without a network. The rules are
// the product; they should be readable in one sitting and testable without a
// replica.
//
// Two invariants, both inherited from ic-git's verification doctrine, and both
// enforced structurally rather than by care:
//
//   1. A check may add warnings and lower the verdict. Nothing may raise it.
//      `worse()` is the only way the verdict moves, and it is monotone.
//   2. "Could not check" is never "checked and fine". A check whose input is
//      missing, unreachable, or not certified resolves to UNKNOWN, and UNKNOWN
//      caps the verdict below GREEN. A certificate that fails ic-git's
//      signature chain reaches this file as `certified: false` -- not read,
//      rather than read and believed -- and this rule is what keeps it from
//      producing a GREEN page.

export const GREEN = "GREEN";
export const YELLOW = "YELLOW";
export const RED = "RED";

export const OK = "OK";
export const UNKNOWN = "UNKNOWN";
export const BAD = "BAD";

const RANK = { [GREEN]: 0, [YELLOW]: 1, [RED]: 2 };
const worse = (a, b) => (RANK[b] > RANK[a] ? b : a);

const short = (h) => (h ? `${String(h).slice(0, 16)}...` : "none");
const who = (controllers, icGit) =>
  controllers.length === 0
    ? "nobody"
    : controllers.map((c) => (c === icGit ? "ic-git" : `${c.slice(0, 5)}...`)).join(", ");

/// One canister's certified state, as ic-git's core reports it:
/// `{ certified, moduleHash, controllers, stale, time, checks }`, or
/// `{ error }` when the read could not be attempted. Records the read as a
/// check and returns the state when the certificate was accepted, else null.
///
/// Note the asymmetry between the two failure modes, because it is the
/// weakest point in the current design and should be visible in the code
/// rather than only in the docs: a hash that MISMATCHES is BAD (RED, ballot
/// blocked), but a state that cannot be READ is UNKNOWN (YELLOW, which the UI
/// lets a voter click past). An attacker who can make the read fail therefore
/// gets a softer outcome than one who lets it succeed and mismatch. Closing
/// that means deciding a voting window should hard-block on an unreachable
/// canister, which is a change to the verdict ladder in THREAT_MODEL.md
/// section 4, not a change to this function.
function certifiedState(c, id, label, st) {
  const name = `${label}'s certified state`;
  if (!st || st.error) {
    c.add(`${id}-read`, name, UNKNOWN, st?.error ?? "not read");
    return null;
  }
  if (!st.certified) {
    // ic-git's core refused the certificate: no reply, a signing key not
    // delegated by the NNS root key, a signature that does not verify, no
    // date, or a tree that hides the paths asked for. Nothing in it is read.
    const bad = (st.checks ?? []).find((k) => !k.ok);
    c.add(`${id}-read`, name, UNKNOWN, `certificate not accepted: ${bad ? `${bad.label} (${bad.detail})` : "unknown"}`);
    return null;
  }
  const n = st.controllers.length;
  const summary = `module ${short(st.moduleHash)}, ${n} controller${n === 1 ? "" : "s"}`;
  if (st.stale) {
    // Genuine, but about an earlier moment: a module since replaced would
    // not show. The values are still compared below -- a mismatch in an old
    // certificate is still a mismatch -- but the read cannot be GREEN.
    c.add(`${id}-read`, name, UNKNOWN, `${summary}; the certificate is stale`);
  } else {
    c.add(`${id}-read`, name, OK, summary);
  }
  return st;
}

/// The pin: the module hash the election froze for this canister, against
/// its certified one.
function checkPin(c, id, label, st, pinned) {
  const name = `${label} matches the election's pin`;
  if (!st) {
    c.add(`${id}-pin`, name, UNKNOWN, "no certified hash to compare");
  } else if (st.moduleHash === pinned) {
    c.add(`${id}-pin`, name, OK, short(st.moduleHash));
  } else {
    // THREAT_MODEL.md 2.5: for an election specifically, a module hash that
    // differs from the one pinned for the window is a spoiling event, not a
    // notice -- even if the new hash is itself a voted one.
    c.add(`${id}-pin`, name, BAD, `live ${short(st.moduleHash)} but the election pinned ${short(pinned)}`);
  }
}

class Checks {
  constructor() {
    this.list = [];
    this.verdict = GREEN;
  }
  add(id, label, state, detail) {
    this.list.push({ id, label, state, detail });
    if (state === BAD) this.verdict = worse(this.verdict, RED);
    else if (state === UNKNOWN) this.verdict = worse(this.verdict, YELLOW);
    return state === OK;
  }
}

/// `input`:
///   pin               the election's Pin record (from get_manifest)
///   served            { sha256, commitHeader, repoHeader } or { error }
///   registryRecord    `<repo>#site`: { commit, bundleHash, updatedAt } | null | { error }
///   site              certified state of the serving canister, ic-git
///                     (anchors.icGit), as provenance.canisterState reports it:
///                     { certified, moduleHash, controllers, stale, checks }
///                     or { error }
///   poll              the same for the poll canister
///   governor          the same for anchors.governor.id
///   appRecord         `<repo>#app`: the build ic-git installed in the poll
///                     canister, { commit, bundleHash, updatedAt } | null | { error }
///   canisterRecord    `ic-git#canister`: the build ic-git itself runs, same shape
///   anchors           { icGit, registries, governor: { id, module } }, from
///                     config.js: the canister that served this bundle, the
///                     registry contract per chain id, and ic-git's governor
///   lastSeenModuleHash  previously cached hash for the site canister, or null
export function computeVerdict(input) {
  const c = new Checks();
  const {
    pin,
    served,
    registryRecord,
    site: siteState,
    poll: pollState,
    governor: governorState,
    appRecord,
    canisterRecord,
    anchors,
    lastSeenModuleHash = null,
  } = input;

  // --- 1. the bytes running in this browser ------------------------------

  if (!pin) {
    c.add("pin", "Election pins a release", BAD, "this election has no pinned release");
    return finish(c, { live: null, lastSeenModuleHash });
  }
  c.add("pin", "Election pins a release", OK, `${pin.repo} @ ${pin.commit.slice(0, 12)}`);

  // The pin names a serving canister, but the pin is the election's word and
  // the administrator writes it. Which canister served this page is known
  // from the bundle (config.js), and section 4 treats that canister as
  // ic-git. Taking ic-git from the pin instead would let a pin name any
  // canister running ic-git's module -- an instance with approvers of the
  // administrator's choosing, handed to the pinned governor as its only
  // controller -- and the governance checks would pass against it while this
  // page was served by the real one.
  const icGit = anchors?.icGit ?? null;
  if (!icGit) {
    c.add("site-id", "Election names the serving canister", BAD, "no serving canister in config.js");
  } else if (pin.site_canister === icGit) {
    c.add("site-id", "Election names the serving canister", OK, icGit);
  } else {
    c.add("site-id", "Election names the serving canister", BAD, `the election names ${pin.site_canister}; this page was served by ${icGit}`);
  }

  if (!served || served.error) {
    c.add("served", "Served bundle re-read", UNKNOWN, served?.error ?? "not attempted");
  } else if (served.sha256 === pin.bundle_sha256) {
    c.add("served", "Served bundle matches the election's pin", OK, served.sha256);
  } else {
    c.add(
      "served",
      "Served bundle matches the election's pin",
      BAD,
      `this page hashes to ${served.sha256}; the election pinned ${pin.bundle_sha256}`
    );
  }

  // --- 2. the chain's copy of the same claim ------------------------------
  //
  // The pin and the registry are independent statements about the same bundle:
  // the pin is what the election committed to when it opened, the registry is
  // what the serving canister published. Comparing served bytes against only
  // one of them leaves the other free to drift, so all three must agree.
  //
  // Independent only if the registry is not the pin's to choose. The pin
  // names a chain and a contract; the contract read is the one config.js pins
  // for that chain, and the pin must name the same one. A pin naming a
  // contract of the administrator's would otherwise make the records agree
  // with the pin by construction.

  const registry = anchors?.registries?.[Number(pin.registry_chain_id)];
  const sameAddress = (a, b) => typeof a === "string" && typeof b === "string" && a.toLowerCase() === b.toLowerCase();
  if (!registry) {
    c.add("registry-id", "Election names the configured registry", BAD, `no registry configured for chain ${pin.registry_chain_id}`);
  } else if (sameAddress(pin.registry_address, registry.address)) {
    c.add("registry-id", "Election names the configured registry", OK, `${registry.address} on chain ${pin.registry_chain_id}`);
  } else {
    c.add("registry-id", "Election names the configured registry", BAD, `the election names ${pin.registry_address} on chain ${pin.registry_chain_id}; this page reads ${registry.address}`);
  }

  if (!registryRecord || registryRecord.error) {
    c.add(
      "registry",
      "ProvenanceRegistry record",
      UNKNOWN,
      registryRecord?.error ?? "no record for this repo on the configured chain"
    );
  } else {
    const commitOk = registryRecord.commit === pin.commit;
    const bundleOk = registryRecord.bundleHash === pin.bundle_sha256;
    if (commitOk && bundleOk) {
      c.add("registry", "Registry agrees with the election's pin", OK, `commit ${pin.commit.slice(0, 12)}`);
    } else {
      c.add(
        "registry",
        "Registry agrees with the election's pin",
        BAD,
        `registry has commit ${registryRecord.commit.slice(0, 12)} / bundle ` +
          `${registryRecord.bundleHash.slice(0, 12)}; the election pinned ` +
          `${pin.commit.slice(0, 12)} / ${pin.bundle_sha256.slice(0, 12)}`
      );
    }
    if (served && !served.error && served.commitHeader && served.commitHeader !== registryRecord.commit) {
      c.add(
        "commit-header",
        "Served response is bound to the registry's commit",
        BAD,
        `X-Ic-Git-Commit was ${served.commitHeader}`
      );
    }
  }

  // --- 3. the two canisters -----------------------------------------------
  //
  // There are two, with different controllers and different powers, and they
  // must both be checked. The SITE canister serves the ballot page: its
  // controller can change what the voter sees. The POLL canister holds the
  // roll, the log and the tally: its controller can change what the ballots
  // mean. An earlier version of this file checked only the first, which left
  // "upgrade the canister that counts" entirely unobserved.

  const site = certifiedState(c, "site", "Serving canister", siteState);
  checkPin(c, "site", "Serving canister", site, pin.module_sha256);
  const poll = certifiedState(c, "poll", "Poll canister", pollState);
  checkPin(c, "poll", "Poll canister", poll, pin.poll_module_sha256);

  // --- 4. who can change the code, and whether a vote did -----------------
  //
  // The pin makes a mid-window change visible. This is what establishes that
  // the pinned value was ever the right one: not reviewers attesting a hash
  // after the fact, but the controller structure itself, read from the same
  // certificates, plus the record ic-git published when it deployed.
  //
  //   The poll canister is governed when ic-git is its only controller: its
  //   code then changes only when the repo's approvers vote a commit through
  //   and ic-git's deploy queue installs it, and ic-git records what it
  //   installed on chain as `<repo>#app`. The module it runs must be that one.
  //
  //   ic-git is governed when its only controller is the governor pinned in
  //   config.js: a canister with no controllers, running the pinned module,
  //   that installs ic-git's code only when ic-git's approvers vote it
  //   through (ic-git docs/GOVERNOR.md). It records what it runs as
  //   `ic-git#canister`.
  //
  // The governor pin is the trust anchor, where the verifier set used to be:
  // a successor governor is a Handover vote in ic-git and a new pin here,
  // which changes this bundle's hash. The rule is ic-git's own (its core,
  // `judge`): what ic-git blocks is BAD here, what it allows with a warning
  // is UNKNOWN, and what it approves is OK. `icGit` is the bundle's serving
  // canister (section 1), not the pin's.

  const pollGoverned = poll && poll.controllers.length === 1 && poll.controllers[0] === icGit;
  if (!poll) {
    c.add("poll-governed", "Poll canister is governed by ic-git", UNKNOWN, "no certified controllers");
  } else if (pollGoverned) {
    c.add("poll-governed", "Poll canister is governed by ic-git", OK, "ic-git is its only controller; its code changes only by an approved commit's deploy");
  } else {
    c.add(
      "poll-governed",
      "Poll canister is governed by ic-git",
      BAD,
      `controlled by ${who(poll.controllers, icGit)}, who can change the code that counts without a vote`
    );
  }
  if (pollGoverned) {
    const name = "Poll canister runs the build ic-git recorded";
    if (!appRecord) {
      // Not an error: the record was read and is absent. ic-git publishes
      // one with every install into a governed canister, so a governed
      // canister with none has no approved build on record, and ic-git's
      // own rule blocks it.
      c.add("poll-record", name, appRecord === null ? BAD : UNKNOWN, appRecord === null ? `the registry holds no "${pin.repo}#app" record: no approved build is on record` : "not read");
    } else if (appRecord.error) {
      c.add("poll-record", name, UNKNOWN, appRecord.error);
    } else if (poll.moduleHash === appRecord.bundleHash) {
      c.add("poll-record", name, OK, `the approved build of commit ${appRecord.commit.slice(0, 12)}`);
    } else {
      c.add("poll-record", name, BAD, `runs ${short(poll.moduleHash)} where the record approves ${short(appRecord.bundleHash)} (commit ${appRecord.commit.slice(0, 12)})`);
    }
  }

  const gov = anchors?.governor;
  const siteGoverned = site && gov && site.controllers.length === 1 && site.controllers[0] === gov.id;
  if (!gov) {
    c.add("site-governed", "Serving canister is governed", BAD, "no governor pinned in config.js");
  } else if (!site) {
    c.add("site-governed", "Serving canister is governed", UNKNOWN, "no certified controllers");
  } else if (siteGoverned) {
    c.add("site-governed", "Serving canister is governed", OK, `its only controller is the pinned governor ${gov.id.slice(0, 5)}...`);
  } else {
    c.add(
      "site-governed",
      "Serving canister is governed",
      BAD,
      `controlled by ${who(site.controllers, icGit)}, not the governor pinned in config.js`
    );
  }
  if (gov) {
    const name = "The governor is the recorded one";
    const g = certifiedStateQuiet(governorState);
    if (!g) {
      c.add("governor", name, UNKNOWN, governorState?.error ?? "its state could not be certified");
    } else if (g.controllers.length) {
      c.add("governor", name, BAD, `the governor is itself controlled by ${who(g.controllers, icGit)}`);
    } else if (g.moduleHash !== gov.module) {
      c.add("governor", name, BAD, `the governor runs module ${short(g.moduleHash)}, not the pinned ${short(gov.module)}`);
    } else {
      c.add("governor", name, OK, "no controllers; runs the pinned module, so its rules cannot change");
    }
  }
  if (siteGoverned) {
    // Under the governor every module ic-git runs was installed by a vote,
    // so the record is corroboration, not the claim: a record that lags an
    // upgrade, or was never written, is a warning, as in ic-git's own rule.
    const name = "Serving canister runs the build it recorded";
    if (!canisterRecord) {
      c.add("site-record", name, UNKNOWN, canisterRecord === null ? "the registry holds no ic-git#canister record" : "not read");
    } else if (canisterRecord.error) {
      c.add("site-record", name, UNKNOWN, canisterRecord.error);
    } else if (site.moduleHash === canisterRecord.bundleHash) {
      c.add("site-record", name, OK, `the recorded build of commit ${canisterRecord.commit.slice(0, 12)}`);
    } else {
      c.add("site-record", name, UNKNOWN, `runs ${short(site.moduleHash)} where the record names ${short(canisterRecord.bundleHash)}: an upgrade the record does not name yet`);
    }
  }

  return finish(c, { live: site?.moduleHash ?? null, lastSeenModuleHash });
}

/// A certified state without the check entry: for the governor, whose read
/// is reported as part of one judgment rather than as a read of its own.
function certifiedStateQuiet(st) {
  return st && !st.error && st.certified ? st : null;
}

function finish(c, { live, lastSeenModuleHash }) {
  let verdict = c.verdict;
  const warnings = [];

  // --- 5. change detection, applied LAST and only downward ----------------
  //
  // The ordering is the whole point: a controller who upgrades the canister
  // to malicious code produces a hash the pin does not name, which the checks
  // above already made RED. Assigning YELLOW here would RAISE that verdict
  // and present the exact attack this system exists to catch as a soft
  // caution.
  if (live && lastSeenModuleHash && live !== lastSeenModuleHash) {
    warnings.push(
      `The serving canister's code changed since this browser last looked ` +
        `(${lastSeenModuleHash.slice(0, 12)}... -> ${live.slice(0, 12)}...). ` +
        `During an open voting window this requires administrator disclosure.`
    );
    verdict = worse(verdict, YELLOW);
  }

  return {
    verdict,
    checks: c.list,
    warnings,
    // RED during an open window is an incident, not a banner: the ballot is
    // not markable at all. YELLOW is markable only after the voter is shown
    // what could not be checked and says so explicitly.
    ballot: verdict === GREEN ? "allowed" : verdict === YELLOW ? "requires-acknowledgement" : "blocked",
  };
}
