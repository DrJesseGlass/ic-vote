//! Candid surface. Types a client sees, plus the validation that keeps
//! unverifiable data out of the state in the first place.

use candid::{CandidType, Principal};
use serde::Deserialize;

#[derive(CandidType, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Being set up. Roll and pin are mutable; nothing is committed.
    Draft,
    /// Voting window. Manifest is frozen; ballots are accepted.
    Open,
    /// Window closed. Log and tally are final.
    Closed,
}

impl Phase {
    pub fn name(&self) -> &'static str {
        match self {
            Phase::Draft => "Draft",
            Phase::Open => "Open",
            Phase::Closed => "Closed",
        }
    }
}

/// The release a voter's client must be running for this election.
///
/// This is the load-bearing anti-malicious-client record (THREAT_MODEL.md
/// 2.1 and 2.5). It lives inside the manifest hash, so an administrator
/// cannot repoint an open election at a different frontend build without
/// invalidating every ballot's chain position -- pinning the expected module
/// hash "for the duration of the voting window" is a state invariant here,
/// not a deployment convention.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Pin {
    /// ic-git repo name. The registry record actually read is
    /// `<repo>#site` (ic-git docs/ATTESTATION.md, "The two record types").
    pub repo: String,
    /// 40-hex git commit the bundle was published from.
    pub commit: String,
    /// 64-hex sha256 of the served bundle entrypoint.
    pub bundle_sha256: String,
    /// Principal of the ic-git canister serving that bundle.
    pub site_canister: String,
    /// 64-hex module hash the *site* canister is expected to be running for
    /// the whole window. A certified read that differs is a spoiling event.
    pub module_sha256: String,
    /// 64-hex module hash the *poll* canister -- this one, the one holding the
    /// roll, the log and the tally -- is expected to be running for the whole
    /// window.
    ///
    /// Separate from `module_sha256` because they are different canisters with
    /// different controllers and different powers. `module_sha256` covers the
    /// party who can change the ballot *page*; this covers the party who can
    /// change the code that *counts*. An earlier version of this design had
    /// only the first and documented it as covering both, which meant a poll
    /// canister could be upgraded mid-election to code that mis-tallies or
    /// rewrites the log with no change to any verdict a voter sees.
    ///
    /// What this is: a value the administrator declares before the window
    /// opens, frozen into the manifest hash, that a client compares against a
    /// certified read. What it is not: proof the declared value was ever the
    /// right one. It makes a mid-window *change* visible, which is the attack
    /// in THREAT_MODEL.md 2.5; it does not establish the starting point. That
    /// is what the K-of-N attestation on the module hash is for.
    pub poll_module_sha256: String,
    /// EVM chain holding the ProvenanceRegistry for this election.
    pub registry_chain_id: u64,
    /// Registry contract address on that chain.
    pub registry_address: String,
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Pin {
    pub fn validate(&self) -> Result<(), VoteError> {
        let bad = |m: &str| Err(VoteError::InvalidInput(m.to_string()));
        if self.repo.is_empty() || self.repo.len() > 128 {
            return bad("pin.repo must be 1..=128 bytes");
        }
        // ic-git derives the site record key by appending "#site" to the repo
        // name. A repo name containing '#' could therefore be chosen to make
        // `<repo>#site` collide with another repo's *deploy-artifact* record,
        // whose bundleHash is the sha256 of contract bytecode rather than of
        // served bytes. The verifier would then compare the served page
        // against a hash that was never meant to describe it and report a
        // mismatch -- or, with a crafted pair, fail to report a real one.
        if self.repo.contains('#') {
            return bad("pin.repo must not contain '#' (reserved by ic-git's record namespace)");
        }
        if !is_lower_hex(&self.commit, 40) {
            return bad("pin.commit must be 40 lowercase hex chars");
        }
        if !is_lower_hex(&self.bundle_sha256, 64) {
            return bad("pin.bundle_sha256 must be 64 lowercase hex chars");
        }
        if !is_lower_hex(&self.module_sha256, 64) {
            return bad("pin.module_sha256 must be 64 lowercase hex chars");
        }
        if !is_lower_hex(&self.poll_module_sha256, 64) {
            return bad("pin.poll_module_sha256 must be 64 lowercase hex chars");
        }
        if Principal::from_text(&self.site_canister).is_err() {
            return bad("pin.site_canister must be a principal");
        }
        // Case is not normalized: EIP-55 checksummed addresses are mixed-case
        // by design and rewriting them would destroy the checksum.
        let addr = self.registry_address.strip_prefix("0x").unwrap_or("");
        if addr.len() != 40 || !addr.bytes().all(|b| b.is_ascii_hexdigit()) {
            return bad("pin.registry_address must be 0x + 40 hex chars");
        }
        if self.registry_chain_id == 0 {
            return bad("pin.registry_chain_id must be nonzero");
        }
        Ok(())
    }
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct NewElection {
    pub title: String,
    pub question: String,
    pub options: Vec<String>,
}

impl NewElection {
    pub fn validate(&self) -> Result<(), VoteError> {
        let bad = |m: &str| Err(VoteError::InvalidInput(m.to_string()));
        if self.title.trim().is_empty() || self.title.len() > 256 {
            return bad("title must be 1..=256 bytes");
        }
        if self.question.trim().is_empty() || self.question.len() > 4096 {
            return bad("question must be 1..=4096 bytes");
        }
        // Two is the minimum that makes a choice meaningful; the upper bound
        // keeps `choice: u32` indexing and the tally vector bounded.
        if self.options.len() < 2 || self.options.len() > 256 {
            return bad("options must number 2..=256");
        }
        if self.options.iter().any(|o| o.trim().is_empty() || o.len() > 256) {
            return bad("each option must be 1..=256 bytes");
        }
        // Duplicate option labels would make the published tally ambiguous to
        // a human reading it, even though the indices are distinct.
        let mut sorted: Vec<&String> = self.options.iter().collect();
        sorted.sort();
        if sorted.windows(2).any(|w| w[0] == w[1]) {
            return bad("options must be distinct");
        }
        Ok(())
    }
}

/// Summary. Excludes the roll and the log, which have their own paginated
/// endpoints because either can be large.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ElectionView {
    pub id: u64,
    pub title: String,
    pub question: String,
    pub options: Vec<String>,
    pub admin: Principal,
    pub phase: Phase,
    pub created_at: u64,
    pub opened_at: Option<u64>,
    pub closed_at: Option<u64>,
    pub pin: Option<Pin>,
    pub roll_size: u64,
    pub ballot_count: u64,
    /// 64-hex. `None` until the election opens and the manifest freezes.
    pub manifest_hash: Option<String>,
    /// 64-hex head of the ballot log.
    pub log_head: String,
}

/// Exactly the fields that go into `manifest_hash`, so a client can recompute
/// it rather than believe the canister's copy.
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct Manifest {
    pub id: u64,
    pub title: String,
    pub question: String,
    pub options: Vec<String>,
    pub admin: Principal,
    pub opened_at: u64,
    /// 64-hex over the sorted roll.
    pub roll_hash: String,
    pub pin: Pin,
    /// 64-hex. Advisory: recompute it, do not trust it.
    pub manifest_hash: String,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct BallotView {
    pub seq: u64,
    pub voter: Principal,
    pub choice: u32,
    pub at: u64,
    /// 64-hex chain head after this entry -- the voter's receipt.
    pub entry_hash: String,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub election_id: u64,
    pub seq: u64,
    pub voter: Principal,
    pub choice: u32,
    pub at: u64,
    pub entry_hash: String,
    pub log_head: String,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct Tally {
    pub election_id: u64,
    pub phase: Phase,
    pub options: Vec<String>,
    pub counts: Vec<u64>,
    pub ballot_count: u64,
    pub roll_size: u64,
    pub log_head: String,
    /// 64-hex. `None` before the manifest freezes.
    pub manifest_hash: Option<String>,
    /// 64-hex over (manifest, log head, counts). The value to checkpoint.
    /// `None` before the manifest freezes.
    pub tally_hash: Option<String>,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct WitnessStep {
    /// 64-hex.
    pub sibling: String,
    pub sibling_is_right: bool,
}

/// A log head plus everything needed to tie it to the canister's certified
/// data without trusting the reply.
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct CertifiedHead {
    pub election_id: u64,
    pub ballot_count: u64,
    /// 64-hex.
    pub log_head: String,
    /// 64-hex. Zero hash while the election is a draft.
    pub manifest_hash: String,
    /// Sibling path from this election's leaf to the Merkle root.
    pub witness: Vec<WitnessStep>,
    /// The IC state certificate, whose `certified_data` is that root.
    ///
    /// `None` outside a query call (`data_certificate` is unavailable in
    /// updates). A client that receives `None` must treat the head as
    /// UNVERIFIED, never as verified-by-absence.
    pub certificate: Option<Vec<u8>>,
}

#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum VoteError {
    NotFound,
    NotAdmin,
    WrongPhase { expected: String, actual: String },
    EmptyRoll,
    NoPin,
    NotEligible,
    AlreadyVoted,
    InvalidChoice,
    AnonymousCaller,
    InvalidInput(String),
}

pub fn hex32(h: &[u8; 32]) -> String {
    hex::encode(h)
}
