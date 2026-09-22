//! ic-vote V0 poll canister -- verifiable client, public ballots.
//!
//! V0 has **no ballot secrecy and this is deliberate** (ROADMAP.md V0,
//! THREAT_MODEL.md 2.3). Every ballot is public, attributable, and readable by
//! anyone including the replicas. It is suitable only for votes that are
//! already public: recorded board votes, most shareholder votes, recorded-vote
//! union motions, DAO governance. Deploying it for a secret ballot is a
//! misuse, not a configuration choice; secrecy arrives in V1 via vetKD.
//!
//! What V0 does provide, and what nothing else in the remote-voting literature
//! provides, is that the page which took the vote is checkable against an
//! on-chain attestation (VISION.md 3). This canister's job is to hold the pin
//! that makes that check possible, and to publish a ballot log whose integrity
//! does not rest on believing this canister.
//!
//! Everything in `state.rs` is pure and unit-tested. This file is the thin
//! shell that supplies environment values -- `caller` for administration,
//! `time`, the canister's own principal for `cast` -- and certified data.
//!
//! `cast` deliberately does NOT read `msg_caller` (THREAT_MODEL.md 2.7):
//! eligibility rides on an in-ballot Ed25519 credential, and the client
//! submits from a single-use transport key so the envelope links the ballot
//! to nobody. In V1 the credential column is replaced by a ZK membership
//! proof; the transport stays exactly like this.

mod credential;
mod hashing;
mod state;
mod types;

use candid::Principal;
use ic_cdk::api::{canister_self, certified_data_set, data_certificate, msg_caller, time};
use std::cell::RefCell;

use state::Store;
use types::*;

thread_local! {
    static STORE: RefCell<Store> = RefCell::new(Store::default());
}

/// Recompute and publish the Merkle root over all elections.
///
/// Must be called after every state mutation, including ones that only look
/// like metadata. `certified_data` is the only value in a reply a client can
/// verify without trusting the replica it talked to, so a root that lags the
/// state certifies an election that no longer exists.
fn recertify(store: &Store) {
    certified_data_set(store.certified_root());
}

fn with_mut<T>(f: impl FnOnce(&mut Store) -> Result<T, VoteError>) -> Result<T, VoteError> {
    STORE.with(|s| {
        let mut store = s.borrow_mut();
        let out = f(&mut store)?;
        recertify(&store);
        Ok(out)
    })
}

// --- administration -------------------------------------------------------

#[ic_cdk::update]
fn create_election(spec: NewElection) -> Result<u64, VoteError> {
    let (caller, now) = (msg_caller(), time());
    with_mut(|s| s.create(caller, now, spec))
}

/// Replace the eligibility roll. Draft only. Returns the deduplicated size.
///
/// This is the T4 trust boundary in THREAT_MODEL.md: whoever calls this
/// decides who is a voter, and no cryptography here constrains that choice.
/// The roll is published (`get_roll`) and committed to by the manifest hash
/// precisely so the organization's members can audit the list they were
/// enrolled in.
#[ic_cdk::update]
fn set_roll(election_id: u64, members: Vec<Principal>) -> Result<u64, VoteError> {
    let caller = msg_caller();
    with_mut(|s| s.set_roll(caller, election_id, members))
}

/// Pin the frontend release voters must be running. Draft only.
#[ic_cdk::update]
fn pin_release(election_id: u64, pin: Pin) -> Result<(), VoteError> {
    let caller = msg_caller();
    with_mut(|s| s.pin_release(caller, election_id, pin))
}

/// Name the trustees and how many must approve each stage. Draft only.
/// Returns the deduplicated size. Threshold zero (the default for every
/// election) keeps the administrator-only behaviour.
#[ic_cdk::update]
fn set_trustees(election_id: u64, trustees: Vec<Principal>, threshold: u32) -> Result<u64, VoteError> {
    let caller = msg_caller();
    with_mut(|s| s.set_trustees(caller, election_id, trustees, threshold))
}

/// Refused with `NotApproved` until `threshold` trustees have approved the
/// manifest hash the draft would freeze.
#[ic_cdk::update]
fn open_election(election_id: u64) -> Result<ElectionView, VoteError> {
    let (caller, now) = (msg_caller(), time());
    with_mut(|s| s.open(caller, election_id, now))
}

/// Refused with `NotApproved` until `threshold` trustees have approved the
/// tally hash as it stands. A ballot landing after their approval moves the
/// hash and voids the approvals, so a closed election's count is one its
/// trustees actually saw.
#[ic_cdk::update]
fn close_election(election_id: u64) -> Result<ElectionView, VoteError> {
    let (caller, now) = (msg_caller(), time());
    with_mut(|s| s.close(caller, election_id, now))
}

// --- trustees -------------------------------------------------------------

/// A trustee's decision on a stage: approve (or reject) the manifest hash
/// (`Open`) or the tally hash (`Close`) as it stands right now.
///
/// The caller is the trustee. That is the whole credential: the IC has
/// authenticated the envelope, the caller's principal is looked up in the
/// manifest's trustee list, and no signature travels inside the call. This
/// is ic-multisig's authenticated flavour, the same one ic-git's voters use.
/// The signed flavour is reserved for the other K-of-N in this design --
/// independent verifiers attesting `Pin.poll_module_sha256`, whose approvals
/// must be checkable by a browser that never talks to this canister.
///
/// A later call by the same trustee replaces their earlier ballot. Returns
/// the stage's approvals after recording.
#[ic_cdk::update]
fn approve(election_id: u64, stage: Stage, approve: bool) -> Result<Approvals, VoteError> {
    let (caller, now) = (msg_caller(), time());
    with_mut(|s| s.approve(caller, election_id, stage, approve, now))
}

/// The trustee ballots on each stage's current subject, and whether the
/// threshold is met. Public, like the ballot log: a trustee's attestation of
/// the count is only worth something if the count's readers can see it.
/// A stage whose subject does not exist yet (`Close` before the manifest is
/// frozen; both before the draft has a roll and a pin) is simply absent.
#[ic_cdk::query]
fn get_approvals(election_id: u64) -> Result<Vec<Approvals>, VoteError> {
    STORE.with(|s| Ok(s.borrow().election(election_id)?.approvals_all()))
}

// --- voting ---------------------------------------------------------------

/// Cast one ballot, credentialed by an in-ballot signature rather than by the
/// message envelope.
///
/// An earlier version read `msg_caller` here and documented it as "the IC has
/// already authenticated the envelope". True, and exactly the problem: it
/// bound every ballot to the transport identity, which V1's encrypted ballots
/// would have republished as voter-to-choice at close (THREAT_MODEL.md 2.7).
/// Now the envelope caller is never read -- any caller, including the
/// anonymous principal, may deliver a ballot -- and eligibility is decided by
/// `credential::principal_of(voter_pubkey)` against the roll plus a signature
/// over `hashing::ballot_sig_message(self, manifest, choice)`. The credential
/// and signature are published in the log, so the franchise check no longer
/// rests on believing this canister recorded callers honestly.
/// `sig_expires_at` (ns since epoch) is signed into the ballot message and
/// bounds how long the signature authorizes anything: past it the cast is
/// refused, and it may not lie more than `state::MAX_SIG_TTL_NS` ahead of
/// subnet time. This is the freshness bound the ingress envelope used to
/// provide, relocated into the ballot itself.
#[ic_cdk::update]
fn cast(
    election_id: u64,
    choice: u32,
    voter_pubkey: Vec<u8>,
    sig: Vec<u8>,
    sig_expires_at: u64,
) -> Result<Receipt, VoteError> {
    let (self_id, now) = (canister_self(), time());
    with_mut(|s| {
        s.cast(
            self_id.as_slice(),
            election_id,
            choice,
            voter_pubkey,
            sig,
            sig_expires_at,
            now,
        )
    })
}

// --- the public bulletin board -------------------------------------------

#[ic_cdk::query]
fn get_election(election_id: u64) -> Result<ElectionView, VoteError> {
    STORE.with(|s| s.borrow().election(election_id).map(|e| e.view()))
}

#[ic_cdk::query]
fn list_elections() -> Vec<ElectionView> {
    STORE.with(|s| s.borrow().elections.iter().map(|e| e.view()).collect())
}

/// The exact preimage of `manifest_hash`. Returned so a client can recompute
/// the hash instead of accepting the canister's word for it. Available as
/// soon as a draft has a roll and a pin, so trustees can read what they are
/// asked to approve; `EmptyRoll` or `NoPin` before that.
#[ic_cdk::query]
fn get_manifest(election_id: u64) -> Result<Manifest, VoteError> {
    STORE.with(|s| s.borrow().election(election_id)?.manifest())
}

#[ic_cdk::query]
fn get_roll(election_id: u64, offset: u64, limit: u64) -> Result<Vec<Principal>, VoteError> {
    STORE.with(|s| s.borrow().roll_page(election_id, offset, limit))
}

#[ic_cdk::query]
fn get_log(election_id: u64, offset: u64, limit: u64) -> Result<Vec<BallotView>, VoteError> {
    STORE.with(|s| s.borrow().log_page(election_id, offset, limit))
}

/// Convenience only. The tally that matters is the one a verifier recomputes
/// from `get_log` (see `tools/verify-election.mjs`); this endpoint exists so a
/// UI can render a number, and a client that displays it without recomputing
/// it is trusting exactly the party E2E-V exists to distrust.
#[ic_cdk::query]
fn get_tally(election_id: u64) -> Result<Tally, VoteError> {
    STORE.with(|s| s.borrow().election(election_id).map(|e| e.tally()))
}

/// The log head, its Merkle witness, and the IC state certificate.
///
/// This is the one read that does not require trusting the replying replica:
/// verify the certificate against the NNS root key, extract `certified_data`,
/// and check that recomputing the witness from this election's leaf yields it.
///
/// `certificate` is `None` when called as an update -- `data_certificate` is
/// only populated in query context. A client that gets `None` has an
/// unverified head and must say so; treating it as verified is the false-GREEN
/// failure ic-git's attestation doctrine forbids.
#[ic_cdk::query]
fn certified_head(election_id: u64) -> Result<CertifiedHead, VoteError> {
    STORE.with(|s| {
        let store = s.borrow();
        let e = store.election(election_id)?;
        let witness = store
            .witness(election_id)?
            .into_iter()
            .map(|st| WitnessStep {
                sibling: hex::encode(st.sibling),
                sibling_is_right: st.sibling_is_right,
            })
            .collect();
        Ok(CertifiedHead {
            election_id,
            ballot_count: e.log.len() as u64,
            log_head: hex32(&e.log_head),
            manifest_hash: e
                .manifest_hash
                .as_ref()
                .map(hex32)
                .unwrap_or_else(|| "0".repeat(64)),
            witness,
            certificate: data_certificate(),
        })
    })
}

#[ic_cdk::query]
fn whoami() -> Principal {
    msg_caller()
}

// --- lifecycle ------------------------------------------------------------

#[ic_cdk::init]
fn init() {
    STORE.with(|s| recertify(&s.borrow()));
}

/// Stable-state format version, bumped on every incompatible change to
/// `Store`'s serialization. The unversioned original format is treated as
/// v1. v2 = signed ballots (pubkey_der, sig, sig_expires_at in every log
/// entry; "ic-vote/v0/log-entry-signed" chain rule). v3 = trustees
/// (trustees, threshold and approvals on every election; the
/// "ic-vote/v0/manifest-trustees" manifest rule, which also dropped
/// `opened_at` from the preimage).
///
/// Neither step is migratable in place, DELIBERATELY. v1 -> v2: a v1 ballot
/// has no credential or signature, and inventing placeholders would publish a
/// board whose franchise check the project's own verifiers must reject.
/// v2 -> v3: a v2 election that is open or closed froze a manifest hash under
/// the old preimage, and no v3 verifier can recompute it, so every such
/// board would go RED at check B. A canister with live elections stays on the
/// code it opened them under until they close; upgrading requires
/// `--mode reinstall`, which wipes state, and the trap message below says so
/// instead of pretending the upgrade might work.
const STATE_FORMAT: u32 = 3;

#[ic_cdk::pre_upgrade]
fn pre_upgrade() {
    STORE.with(|s| {
        ic_cdk::storage::stable_save((STATE_FORMAT, s.borrow().clone()))
            .expect("failed to write state to stable memory");
    });
}

#[ic_cdk::post_upgrade]
fn post_upgrade() {
    let (version, store): (u32, Store) = ic_cdk::storage::stable_restore().expect(
        "stable state is not in the versioned trustee format (v3). Its elections \
         cannot be migrated: a pre-signature (v1) ballot carries no credential, \
         and a pre-trustee (v2) manifest hash was frozen under a preimage no v3 \
         verifier can recompute, so either would fail every verifier on a v3 \
         board. Close or abandon the old elections and redeploy with \
         `--mode reinstall` (this WIPES all elections), or keep running the old \
         module until they close.",
    );
    assert_eq!(
        version, STATE_FORMAT,
        "stable state format is v{version}, this module reads v{STATE_FORMAT}; \
         refusing to guess at a migration (see STATE_FORMAT for why none exists)"
    );
    STORE.with(|s| {
        *s.borrow_mut() = store;
        // Certified data does not survive an upgrade, so republishing it here
        // is not an optimization: without this, every `certified_head` reply
        // after an upgrade carries a certificate that does not cover the
        // state, and honest clients correctly refuse to verify the board.
        recertify(&s.borrow());
    });
}

ic_cdk::export_candid!();

#[cfg(test)]
mod candid_export {
    use super::*;

    /// The committed `poll.did` must match the interface the code actually
    /// exports. A stale .did is not cosmetic here: it is the file dfx hands to
    /// every client, so a drifted one produces clients that decode replies
    /// with the wrong field hashes.
    ///
    /// Regenerate with `UPDATE_DID=1 cargo test -p ic_vote_poll`.
    #[test]
    fn did_file_is_current() {
        let generated = __export_service();
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/poll.did");
        if std::env::var("UPDATE_DID").is_ok() {
            std::fs::write(path, &generated).unwrap();
            return;
        }
        let committed = std::fs::read_to_string(path).unwrap_or_default();
        assert_eq!(
            committed.trim(),
            generated.trim(),
            "poll.did is stale; rerun with UPDATE_DID=1"
        );
    }
}
