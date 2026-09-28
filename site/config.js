// Deployment configuration, and the trust anchors that go with it.
//
// This file is INSIDE the attested bundle, deliberately. The trusted verifier
// set and the threshold K are the web of trust this page applies (ic-git
// docs/ATTESTATION.md: "the web of trust lives in the client, not the chain").
// If they lived in a fetched config, an attacker who could serve a config
// could set K = 0 or name themselves a verifier, and the bundle hash would not
// change. Editing this file changes the bundle hash, which invalidates the
// attestation, which is exactly the alarm you want.
//
// Reviewers: the addresses below are as load-bearing as any line of code here.

export const config = {
  /// Where to talk to the IC: mainnet when the page came from an icp0.io
  /// gateway, the local replica otherwise. See pageURL for "came from".
  host: hostFor(pageURL()),

  /// The poll canister holding elections. Set at deploy time.
  pollCanisterId: null,

  /// The ic-git canister serving this bundle. Read from the election's pin at
  /// runtime; this is only a fallback for the pre-election screen.
  siteCanisterId: "umobs-yiaaa-aaaab-agyrq-cai",

  /// EVM JSON-RPC endpoints by chain id. The election's pin names the chain.
  rpc: {
    11155111: "https://ethereum-sepolia-rpc.publicnode.com",
    100: "https://rpc.gnosischain.com",
  },

  /// Trusted build verifiers, and how many must agree.
  ///
  /// EMPTY ON PURPOSE. ic-git's registry `attest()` and its K-of-N verifier
  /// tooling are specified but unbuilt (ROADMAP.md dependency 2), so there is
  /// nobody to list yet. Inventing placeholder addresses here would produce a
  /// page that looks configured and verifies nothing -- the exact failure this
  /// project is about. With an empty set, the attestation check reports that
  /// no trusted verifier has attested the running wasm, and the verdict is
  /// correspondingly not GREEN.
  trusted: {
    verifiers: [],
    K: 2,
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
/// at a local replica, but the trusted verifier set and K cannot, because a
/// URL parameter that could weaken the trust anchors would be a phishing
/// primitive -- send a voter a link with K=0 and the page renders confident.
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
