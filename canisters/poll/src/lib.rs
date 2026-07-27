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

#[ic_cdk::update]
fn open_election(election_id: u64) -> Result<ElectionView, VoteError> {
    let (caller, now) = (msg_caller(), time());
    with_mut(|s| s.open(caller, election_id, now))
}

#[ic_cdk::update]
fn close_election(election_id: u64) -> Result<ElectionView, VoteError> {
    let (caller, now) = (msg_caller(), time());
    with_mut(|s| s.close(caller, election_id, now))
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
#[ic_cdk::update]
fn cast(
    election_id: u64,
    choice: u32,
    voter_pubkey: Vec<u8>,
    sig: Vec<u8>,
) -> Result<Receipt, VoteError> {
    let (self_id, now) = (canister_self(), time());
    with_mut(|s| s.cast(self_id.as_slice(), election_id, choice, voter_pubkey, sig, now))
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
/// the hash instead of accepting the canister's word for it.
#[ic_cdk::query]
fn get_manifest(election_id: u64) -> Result<Manifest, VoteError> {
    STORE.with(|s| {
        s.borrow()
            .election(election_id)
            .and_then(|e| e.manifest().ok_or(VoteError::WrongPhase {
                expected: "Open or Closed".to_string(),
                actual: e.phase.name().to_string(),
            }))
    })
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

#[ic_cdk::pre_upgrade]
fn pre_upgrade() {
    STORE.with(|s| {
        ic_cdk::storage::stable_save((s.borrow().clone(),))
            .expect("failed to write state to stable memory");
    });
}

#[ic_cdk::post_upgrade]
fn post_upgrade() {
    let (store,): (Store,) =
        ic_cdk::storage::stable_restore().expect("failed to read state from stable memory");
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
