// The verdict: GREEN / YELLOW / RED, per THREAT_MODEL.md section 4.
//
// Pure. Every input is passed in, nothing is fetched here, so the whole rule
// set is exercised by tools/test-site-lib.mjs without a network. The rules are
// the product; they should be readable in one sitting and testable without a
// replica.
//
// Two invariants, both inherited from ic-git's attestation doctrine, and both
// enforced structurally rather than by care:
//
//   1. A check may add warnings and lower the verdict. Nothing may raise it.
//      `worse()` is the only way the verdict moves, and it is monotone.
//   2. "Could not check" is never "checked and fine". A check whose input is
//      missing, unreachable, or unverifiable resolves to UNKNOWN, and UNKNOWN
//      caps the verdict below GREEN. This is the rule that keeps the unbuilt
//      BLS certificate verification from silently producing a GREEN page.

export const GREEN = "GREEN";
export const YELLOW = "YELLOW";
export const RED = "RED";

export const OK = "OK";
export const UNKNOWN = "UNKNOWN";
export const BAD = "BAD";

const RANK = { [GREEN]: 0, [YELLOW]: 1, [RED]: 2 };
const worse = (a, b) => (RANK[b] > RANK[a] ? b : a);

/// One canister's module hash: read it, and compare it against what the
/// election pinned. Returns the live hash, or null if it could not be
/// established.
///
/// Note the asymmetry between the two failure modes, because it is the
/// weakest point in the current design and should be visible in the code
/// rather than only in the docs: a hash that MISMATCHES is BAD (RED, ballot
/// blocked), but a hash that cannot be READ is UNKNOWN (YELLOW, which the UI
/// lets a voter click past). An attacker who can make the read fail therefore
/// gets a softer outcome than one who lets it succeed and mismatch. Closing
/// that means deciding a voting window should hard-block on an unreachable
/// canister, which is a change to the verdict ladder in THREAT_MODEL.md
/// section 4, not a change to this function.
function checkCanister(c, id, label, reading, pinned) {
  const live = reading && !reading.error ? reading.hash : null;

  if (!live) {
    c.add(
      `${id}-module-read`,
      `${label}'s module hash read`,
      UNKNOWN,
      reading?.error ?? "could not read module_hash"
    );
  } else if (reading.signature?.status !== OK) {
    // The read succeeded and the value is structurally present, but nothing
    // has authenticated it. This is the ic-git dependency-1 hole, and it is
    // the single reason this app cannot currently reach GREEN.
    c.add(
      `${id}-module-read`,
      `${label}'s module hash read`,
      UNKNOWN,
      `${live.slice(0, 16)}... read from an UNAUTHENTICATED certificate: ` +
        (reading.signature?.reason ?? "signature not verified")
    );
  } else {
    c.add(`${id}-module-read`, `${label}'s module hash read`, OK, live);
  }

  if (!live) {
    c.add(`${id}-module-pin`, `${label} matches the election's pin`, UNKNOWN, "no live hash to compare");
  } else if (live === pinned) {
    c.add(`${id}-module-pin`, `${label} matches the election's pin`, OK, live.slice(0, 16) + "...");
  } else {
    // THREAT_MODEL.md 2.5: for an election specifically, a module hash that
    // differs from the one pinned for the window is a spoiling event, not a
    // notice -- even if the new hash is itself well attested.
    c.add(
      `${id}-module-pin`,
      `${label} matches the election's pin`,
      BAD,
      `live ${live.slice(0, 16)}... but the election pinned ${String(pinned).slice(0, 16)}...`
    );
  }

  return live;
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
///   registryRecord    { commit, bundleHash, updatedAt } | null | { error }
///   liveModuleHash      { hash, signature: { status } } | { error } -- site
///   livePollModuleHash  { hash, signature: { status } } | { error } -- poll
///   attestations      array of { verifier, moduleHash, commit, recipeHash, at }
///                     ALREADY filtered to the trusted set, one per verifier
///   trusted           { verifiers: [...], K }
///   lastSeenModuleHash  previously cached hash for this canister, or null
export function computeVerdict(input) {
  const c = new Checks();
  const {
    pin,
    served,
    registryRecord,
    liveModuleHash,
    livePollModuleHash,
    attestations = [],
    trusted,
    lastSeenModuleHash = null,
  } = input;

  // --- 1. the bytes running in this browser ------------------------------

  if (!pin) {
    c.add("pin", "Election pins a release", BAD, "this election has no pinned release");
    return finish(c, input);
  }
  c.add("pin", "Election pins a release", OK, `${pin.repo} @ ${pin.commit.slice(0, 12)}`);

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

  const live = checkCanister(c, "site", "Serving canister", liveModuleHash, pin.module_sha256);
  checkCanister(c, "poll", "Poll canister", livePollModuleHash, pin.poll_module_sha256);

  // --- 4. K-of-N backend attestation --------------------------------------

  const K = trusted?.K ?? 0;
  if (!K) {
    c.add("attestations", "Trusted verifier threshold configured", BAD, "K is zero; no threshold to meet");
  } else if (!live) {
    c.add("attestations", `${K} independent verifiers attest this wasm`, UNKNOWN, "no live hash to match against");
  } else {
    // Dedupe by verifier before counting. ic-git's contract sorts and requires
    // strictly ascending addresses for exactly this reason: a duplicate in the
    // trusted set would turn one attestation into a threshold.
    const byVerifier = new Map();
    for (const a of attestations) {
      if (a && a.moduleHash === live) byVerifier.set(a.verifier.toLowerCase(), a);
    }
    const agreeing = [...byVerifier.values()];
    const recipes = new Set(agreeing.map((a) => `${a.commit}/${a.recipeHash}`));

    if (agreeing.length === 0) {
      c.add(
        "attestations",
        `${K} independent verifiers attest this wasm`,
        BAD,
        "no trusted verifier has attested the module hash this canister is running"
      );
    } else if (agreeing.length < K) {
      c.add(
        "attestations",
        `${K} independent verifiers attest this wasm`,
        UNKNOWN,
        `only ${agreeing.length} of ${K} trusted verifiers have attested it`
      );
    } else if (recipes.size !== 1) {
      // Same wasm, different claimed source or build recipe. That is a
      // disagreement about what the canister IS, and ic-git's step 4 requires
      // agreement on one (commit, recipeHash).
      c.add(
        "attestations",
        `${K} independent verifiers attest this wasm`,
        BAD,
        `${agreeing.length} verifiers agree on the module hash but disagree about ` +
          `(commit, recipeHash): ${[...recipes].join(" vs ")}`
      );
    } else {
      c.add(
        "attestations",
        `${K} independent verifiers attest this wasm`,
        OK,
        `${agreeing.length} of ${trusted.verifiers.length} trusted verifiers agree`
      );
    }
  }

  return finish(c, { ...input, live, lastSeenModuleHash });
}

function finish(c, { live, lastSeenModuleHash }) {
  let verdict = c.verdict;
  const warnings = [];

  // --- 5. change detection, applied LAST and only downward ----------------
  //
  // The ordering is the whole point (ic-git docs/ATTESTATION.md step 7): a
  // controller who upgrades the canister to malicious code produces a hash no
  // trusted verifier has attested, which the checks above already made RED.
  // Assigning YELLOW here would RAISE that verdict and present the exact
  // attack this system exists to catch as a soft caution.
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
