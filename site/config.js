// Deployment configuration, and the trust anchors that go with it.
//
// This file is INSIDE the verified bundle, deliberately. The governor pin
// below, the registry endpoints and the serving canister are the web of trust
// this page applies (ic-git docs/GOVERNANCE.md: the client decides whom it
// trusts; the chain only records). If they lived in a fetched config, an
// attacker who could serve a config could name a governor of their own, and
// the bundle hash would not change. Editing this file changes the bundle
// hash, which breaks the page's record, which is exactly the alarm you want.
//
// Reviewers: the addresses below are as load-bearing as any line of code here.

export const config = {
  /// Where to talk to the IC: mainnet when the page came from an icp0.io
  /// gateway, the local replica otherwise. See pageURL for "came from".
  host: hostFor(pageURL()),

  /// The poll canister holding elections. Set at deploy time.
  pollCanisterId: null,

  /// The ic-git canister serving this bundle, set at deploy time with the
  /// poll canister. A trust anchor, not a fallback: the verdict reads this
  /// canister's state and treats it as ic-git, and the election's pin must
  /// name it. The pin is the administrator's word; if the page took ic-git
  /// from the pin, a pin could name another instance of ic-git's module with
  /// approvers of the administrator's choosing, and the governance checks
  /// would be made against that instead of the canister that served the page.
  siteCanisterId: "umobs-yiaaa-aaaab-agyrq-cai",

  /// EVM JSON-RPC endpoints by chain id. The election's pin names the chain.
  rpc: {
    11155111: "https://ethereum-sepolia-rpc.publicnode.com",
    100: "https://rpc.gnosischain.com",
  },

  /// ic-git's governor: the canister that alone controls the serving
  /// canister, has no controllers of its own, and installs ic-git's code only
  /// when ic-git's approvers vote it through (ic-git docs/GOVERNOR.md). Pinned
  /// here by id AND module hash, as ic-git's own core pins it (its DEFAULTS;
  /// tools/test-site-lib.mjs checks the two agree): "a canister nobody
  /// controls" would not do, since an immutable controller is only as good
  /// as the code it runs. A successor governor is a Handover vote in ic-git
  /// and a new pin here, which changes this bundle's hash -- the alarm above.
  ///
  /// This replaces the trusted verifier set of the first design. What vouches
  /// for the code the canisters run is no longer reviewers attesting a hash
  /// after the fact but the controller structure itself: who can install
  /// code, read from the IC's certificates, and the record ic-git publishes
  /// when it does (site/lib/verifier.js, section 4).
  governor: {
    id: "7kkwl-baaaa-aaaab-ag6rq-cai",
    module: "a71ff65df07a3d3b79e383f7bf8b7bf912fd0bac5135936ed2c4cd90b68a641f",
  },
};

/// The URL this page was served from. document.baseURI rather than location:
/// the two are the same when the page is served directly, but a verifier
/// that runs the checked bytes on its own origin (ic-git's loader) sets
/// <base> to the served URL, and location is then the verifier's page.
export function pageURL() {
  if (typeof document !== "undefined" && typeof document.baseURI === "string") return document.baseURI;
  return typeof location !== "undefined" ? location.href : null;
}

/// The IC API for a page served from `url` (null, or not a URL: local).
export function hostFor(url) {
  try {
    const h = new URL(url).hostname;
    if (h === "icp0.io" || h.endsWith(".icp0.io")) return "https://icp-api.io";
  } catch {
    // not a URL: fall through to the replica
  }
  return "http://127.0.0.1:4943";
}

/// True for a page served from this machine: localhost, a *.localhost
/// gateway (a dfx replica), or a loopback address. Anything else, including
/// a page with no URL, is not local.
export function isLocal(url) {
  try {
    const h = new URL(url).hostname;
    return h === "localhost" || h.endsWith(".localhost") || /^127\.\d+\.\d+\.\d+$/.test(h) || h === "[::1]";
  } catch {
    return false;
  }
}

/// Overridable from the page URL for local development ONLY, and so honored
/// only on a page served locally. Both the check and the parameters come from
/// the one URL, pageURL by default: a page a verifier runs under <base> is
/// judged by, and configured from, where it was served, not the verifier's
/// own page.
///
/// Note what is and is not overridable: the canister and host can be pointed
/// at a local replica, but the governor pin cannot, because a URL parameter
/// that could weaken the trust anchors would be a phishing primitive -- send
/// a voter a link naming a governor of your own and the page renders confident.
/// The same holds for the canister and host on a deployed page: a link with
/// ?canister=<theirs> would hand a voter's page to someone else's poll
/// canister, so off this machine the parameters are ignored.
export function configFromURL(url = pageURL()) {
  if (!isLocal(url)) return { ...config };
  const params = new URL(url).searchParams;
  return {
    ...config,
    host: params.get("host") ?? config.host,
    pollCanisterId: params.get("canister") ?? config.pollCanisterId,
  };
}
