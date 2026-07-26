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
  /// Where to talk to the IC. On a deployed frontend this is the origin the
  /// page came from; locally it is the replica.
  host:
    typeof location !== "undefined" && location.hostname.endsWith("icp0.io")
      ? "https://icp-api.io"
      : "http://127.0.0.1:4943",

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

/// Overridable from the page URL for local development ONLY.
///
/// Note what is and is not overridable: the canister and host can be pointed
/// at a local replica, but the trusted verifier set and K cannot, because a
/// URL parameter that could weaken the trust anchors would be a phishing
/// primitive -- send a voter a link with K=0 and the page renders confident.
export function configFromLocation(loc) {
  const params = new URLSearchParams(loc?.search ?? "");
  return {
    ...config,
    host: params.get("host") ?? config.host,
    pollCanisterId: params.get("canister") ?? config.pollCanisterId,
  };
}
