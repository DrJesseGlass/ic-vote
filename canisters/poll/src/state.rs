//! Election state and the rules that govern it.
//!
//! Deliberately free of `ic_cdk`: every entry point takes `caller` and `now`
//! as arguments. That is not stylistic. It means the entire rule set --
//! eligibility, double-voting, phase transitions, manifest freezing -- is
//! exercised by ordinary `cargo test` on the host, so a reviewer (T3) can
//! check the logic without a replica and without trusting a deployment.

use candid::{CandidType, Principal};
use ic_multisig::{Approval, Approver, Ballots, Decision, Policy, Subject};
use serde::Deserialize;
use std::collections::BTreeMap;

use crate::credential;
use crate::hashing::{self, Hash, MerkleStep};
use crate::types::*;

/// Ceiling on the trustee list. Trustees are hashed into the manifest one by
/// one, and a policy is a handful of named people, not a roll.
pub const MAX_TRUSTEES: usize = 256;

/// Ceiling on the values of a stage's subject an election remembers ballots
/// for. See `TrusteeBallots::save`: without it, a trustee re-approving after
/// every draft edit or every ballot grows unmigratable heap state one entry
/// per call, for the same reason `MAX_ROLL` exists.
pub const MAX_APPROVAL_SUBJECTS: usize = 32;

/// Ceiling on roll size. State lives on the heap and is re-serialized on every
/// upgrade, so this is a real limit, not a formality: at ~29 bytes per
/// principal a 200k roll is ~6 MB of roll plus a ballot log of similar order.
/// V0 targets organizational elections (README.md), where rolls are orders of
/// magnitude smaller. Raising this is a stable-memory redesign, not a constant
/// bump.
pub const MAX_ROLL: usize = 200_000;

/// Longest a ballot signature may be valid for (ns). The client signs
/// `now + ~5 minutes`; the cap exists so a client cannot mint itself a
/// window-long bearer token -- a harvested signature must die about as fast
/// as the ingress envelope it replaced would have (THREAT_MODEL.md 2.7).
pub const MAX_SIG_TTL_NS: u64 = 15 * 60 * 1_000_000_000;

const ZERO: Hash = [0u8; 32];

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct Ballot {
    pub seq: u64,
    /// Derived from `pubkey_der`, never from the message caller.
    pub voter: Principal,
    /// The credential: 44-byte DER Ed25519 public key.
    pub pubkey_der: Vec<u8>,
    pub choice: u32,
    pub at: u64,
    /// The expiry the voter signed (ns). Invariant: `at <= sig_expires_at`,
    /// enforced at cast and publicly checkable from the log.
    pub sig_expires_at: u64,
    /// 64-byte Ed25519 signature over `hashing::ballot_sig_message`.
    pub sig: Vec<u8>,
    pub entry_hash: Hash,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct Election {
    pub id: u64,
    pub title: String,
    pub question: String,
    pub options: Vec<String>,
    pub admin: Principal,
    /// Sorted and deduplicated, for the same reason the roll is: the manifest
    /// hashes the list in order.
    pub trustees: Vec<Principal>,
    /// How many trustees must approve a stage before the administrator may
    /// perform it. Zero is the pre-trustee behaviour: admin alone.
    pub threshold: u32,
    pub phase: Phase,
    pub created_at: u64,
    pub opened_at: Option<u64>,
    pub closed_at: Option<u64>,
    pub pin: Option<Pin>,
    /// Sorted and deduplicated. Sorted because the roll hash commits to an
    /// order and two administrators uploading the same members in different
    /// order must produce the same commitment.
    pub roll: Vec<Principal>,
    pub manifest_hash: Option<Hash>,
    pub log: Vec<Ballot>,
    pub log_head: Hash,
    /// Sorted. Derivable from `log`, kept separately so the double-vote check
    /// is a binary search rather than a scan of every ballot cast so far.
    pub voted: Vec<Principal>,
    /// Trustee ballots, keyed by `Subject::key` (`<kind>:<hex hash>`). Kept
    /// per subject rather than per stage so that when the subject moves --
    /// the draft is edited, a ballot lands -- the old approvals stay on
    /// record but stop counting, instead of quietly carrying over to bytes
    /// nobody approved. Bounded per stage by `MAX_APPROVAL_SUBJECTS`.
    pub approvals: BTreeMap<String, Vec<Approval>>,
}

/// The ic-multisig storage adapter: one election's trustee ballots. The rules
/// (who counts, one ballot per trustee, threshold reached or not) live in the
/// crate, shared with ic-git; this only supplies the map.
struct TrusteeBallots<'a>(&'a mut BTreeMap<String, Vec<Approval>>);

impl ic_multisig::Store for TrusteeBallots<'_> {
    fn load(&self, subject: &Subject) -> Vec<Approval> {
        self.0.get(&subject.key()).cloned().unwrap_or_default()
    }

    fn save(&mut self, subject: &Subject, ballots: Vec<Approval>) {
        let key = subject.key();
        self.0.insert(key.clone(), ballots);
        // The subject moves on every draft edit and every ballot cast, and a
        // trustee may approve each value it takes, so an unbounded map here
        // is one heap entry per update call -- state no endpoint can read
        // back once the subject has moved on (`approvals_on` only ever looks
        // up the current subject) and that v3 refuses to migrate away. Well
        // above any honest election's churn; past it, the superseded entries
        // for this stage go and only the current subject is kept.
        let prefix = format!("{}:", subject.kind);
        if self.0.keys().filter(|k| k.starts_with(&prefix)).count() > MAX_APPROVAL_SUBJECTS {
            self.0.retain(|k, _| !k.starts_with(&prefix) || *k == key);
        }
    }
}

#[derive(CandidType, Deserialize, Clone, Debug, Default)]
pub struct Store {
    pub next_id: u64,
    /// In ascending `id` order, which is also insertion order. The Merkle tree
    /// over elections depends on this ordering being canonical.
    pub elections: Vec<Election>,
}

impl Election {
    fn roll_hash(&self) -> Hash {
        let slices: Vec<&[u8]> = self.roll.iter().map(|p| p.as_slice()).collect();
        hashing::roll_hash(&slices)
    }

    /// The manifest hash the draft as it stands would freeze, or the one it
    /// did. Needs a roll and a pin, which are the same preconditions `open`
    /// has: a manifest with no voters or no pinned release is not a thing a
    /// trustee should be able to approve.
    fn compute_manifest_hash(&self) -> Result<Hash, VoteError> {
        if self.roll.is_empty() {
            return Err(VoteError::EmptyRoll);
        }
        let pin = self.pin.as_ref().ok_or(VoteError::NoPin)?;
        let trustees: Vec<&[u8]> = self.trustees.iter().map(|p| p.as_slice()).collect();
        Ok(hashing::manifest_hash(&hashing::ManifestFields {
            id: self.id,
            title: &self.title,
            question: &self.question,
            options: &self.options,
            admin: self.admin.as_slice(),
            trustees: &trustees,
            threshold: self.threshold,
            roll_hash: self.roll_hash(),
            pin_repo: &pin.repo,
            pin_commit: &pin.commit,
            pin_bundle_sha256: &pin.bundle_sha256,
            pin_site_canister: &pin.site_canister,
            pin_module_sha256: &pin.module_sha256,
            pin_poll_module_sha256: &pin.poll_module_sha256,
            pin_registry_chain_id: pin.registry_chain_id,
            pin_registry_address: &pin.registry_address,
        }))
    }

    fn tally_hash(&self) -> Option<Hash> {
        self.manifest_hash
            .as_ref()
            .map(|mh| hashing::tally_hash(mh, &self.log_head, &self.counts()))
    }

    // --- trustee approvals ----------------------------------------------

    fn policy(&self) -> Policy {
        Policy::new(self.trustees.iter().copied().map(Approver::from), self.threshold)
    }

    /// What a trustee approves at each stage. Both are hashes the canister
    /// already publishes and every verifier already recomputes.
    fn subject(&self, stage: Stage) -> Result<Subject, VoteError> {
        let hash = match stage {
            Stage::Open => self.compute_manifest_hash()?,
            Stage::Close => self.tally_hash().ok_or(VoteError::WrongPhase {
                expected: "Open or Closed".to_string(),
                actual: self.phase.name().to_string(),
            })?,
        };
        Ok(Subject::new(stage.kind(), hash))
    }

    fn approvals_on(&self, subject: &Subject) -> &[Approval] {
        self.approvals
            .get(&subject.key())
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// Count the trustee ballots on `subject`. They came out of the map
    /// `record` writes, and each was checked on the way in: the trustee was
    /// the authenticated caller of `approve`, and there is no signature to
    /// verify. The crate is told so, rather than asked to re-verify a list
    /// that has nothing to verify.
    fn count(&self, subject: &Subject, ballots: &[Approval]) -> ic_multisig::Tally {
        let checked = Ballots::assume_checked(subject, ballots.iter().cloned());
        ic_multisig::tally_checked(&self.policy(), subject, &checked)
    }

    pub fn approvals(&self, stage: Stage) -> Result<Approvals, VoteError> {
        let subject = self.subject(stage)?;
        let ballots = self.approvals_on(&subject);
        let t = self.count(&subject, ballots);
        Ok(Approvals {
            election_id: self.id,
            stage,
            subject: hex32(&subject.hash),
            ballots: ballots
                .iter()
                .filter_map(|a| {
                    Some(TrusteeBallot {
                        trustee: a.approver.principal()?,
                        approve: a.approves(),
                        at: a.at_ns,
                    })
                })
                .collect(),
            approvals: t.approvals,
            rejections: t.rejections,
            required: t.required,
            reached: t.reached,
        })
    }

    /// Every stage whose subject exists yet: `Open` once the draft has a
    /// roll and a pin, `Close` once the manifest is frozen. One call, no
    /// stage argument, so the ballot page can read it: its candid encoder
    /// deliberately cannot write a variant, and widening it to select a
    /// stage would also let the page reach `approve`.
    pub fn approvals_all(&self) -> Vec<Approvals> {
        [Stage::Open, Stage::Close]
            .into_iter()
            .filter_map(|stage| self.approvals(stage).ok())
            .collect()
    }

    /// May the administrator perform this stage? Yes when the manifest
    /// requires no trustees, or when enough of them have approved the
    /// subject as it stands right now.
    fn require_approved(&self, stage: Stage) -> Result<(), VoteError> {
        if self.threshold == 0 {
            return Ok(());
        }
        let subject = self.subject(stage)?;
        let t = self.count(&subject, self.approvals_on(&subject));
        if t.reached {
            Ok(())
        } else {
            Err(VoteError::NotApproved {
                approvals: t.approvals,
                required: t.required,
            })
        }
    }

    pub fn counts(&self) -> Vec<u64> {
        let mut counts = vec![0u64; self.options.len()];
        for b in &self.log {
            // `choice` was bounds-checked at cast time against this same
            // `options`, which is immutable from Open onward.
            counts[b.choice as usize] += 1;
        }
        counts
    }

    pub fn view(&self) -> ElectionView {
        ElectionView {
            id: self.id,
            title: self.title.clone(),
            question: self.question.clone(),
            options: self.options.clone(),
            admin: self.admin,
            trustees: self.trustees.clone(),
            threshold: self.threshold,
            phase: self.phase,
            created_at: self.created_at,
            opened_at: self.opened_at,
            closed_at: self.closed_at,
            pin: self.pin.clone(),
            roll_size: self.roll.len() as u64,
            ballot_count: self.log.len() as u64,
            manifest_hash: self.manifest_hash.as_ref().map(hex32),
            log_head: hex32(&self.log_head),
        }
    }

    /// The manifest preimage. Once open, the frozen hash; before that, the
    /// hash the draft would freeze -- what a trustee approving `Stage::Open`
    /// is being asked to sign off on.
    pub fn manifest(&self) -> Result<Manifest, VoteError> {
        let mh = match self.manifest_hash {
            Some(mh) => mh,
            None => self.compute_manifest_hash()?,
        };
        Ok(Manifest {
            id: self.id,
            title: self.title.clone(),
            question: self.question.clone(),
            options: self.options.clone(),
            admin: self.admin,
            trustees: self.trustees.clone(),
            threshold: self.threshold,
            roll_hash: hex32(&self.roll_hash()),
            pin: self.pin.clone().expect("a manifest hash implies a pin"),
            manifest_hash: hex32(&mh),
        })
    }

    pub fn tally(&self) -> Tally {
        Tally {
            election_id: self.id,
            phase: self.phase,
            options: self.options.clone(),
            counts: self.counts(),
            ballot_count: self.log.len() as u64,
            roll_size: self.roll.len() as u64,
            log_head: hex32(&self.log_head),
            manifest_hash: self.manifest_hash.as_ref().map(hex32),
            tally_hash: self.tally_hash().as_ref().map(hex32),
        }
    }

    fn leaf(&self) -> Hash {
        hashing::merkle_leaf(
            self.id,
            self.manifest_hash.as_ref().unwrap_or(&ZERO),
            &self.log_head,
            self.log.len() as u64,
        )
    }

    fn require_admin(&self, caller: Principal) -> Result<(), VoteError> {
        if caller == self.admin {
            Ok(())
        } else {
            Err(VoteError::NotAdmin)
        }
    }

    fn require_phase(&self, expected: Phase) -> Result<(), VoteError> {
        if self.phase == expected {
            Ok(())
        } else {
            Err(VoteError::WrongPhase {
                expected: expected.name().to_string(),
                actual: self.phase.name().to_string(),
            })
        }
    }
}

fn reject_anonymous(p: Principal) -> Result<(), VoteError> {
    if p == Principal::anonymous() {
        Err(VoteError::AnonymousCaller)
    } else {
        Ok(())
    }
}

impl Store {
    fn get(&self, id: u64) -> Result<&Election, VoteError> {
        self.elections
            .binary_search_by_key(&id, |e| e.id)
            .map(|i| &self.elections[i])
            .map_err(|_| VoteError::NotFound)
    }

    fn get_mut(&mut self, id: u64) -> Result<&mut Election, VoteError> {
        let i = self
            .elections
            .binary_search_by_key(&id, |e| e.id)
            .map_err(|_| VoteError::NotFound)?;
        Ok(&mut self.elections[i])
    }

    pub fn election(&self, id: u64) -> Result<&Election, VoteError> {
        self.get(id)
    }

    /// Root of the tree whose leaves are the elections in id order. This is
    /// what goes into `certified_data`, so it must be recomputed after every
    /// mutation -- a stale root certifies a state that no longer exists.
    pub fn certified_root(&self) -> Hash {
        let leaves: Vec<Hash> = self.elections.iter().map(|e| e.leaf()).collect();
        hashing::merkle_root(&leaves)
    }

    pub fn witness(&self, id: u64) -> Result<Vec<MerkleStep>, VoteError> {
        let idx = self
            .elections
            .binary_search_by_key(&id, |e| e.id)
            .map_err(|_| VoteError::NotFound)?;
        let leaves: Vec<Hash> = self.elections.iter().map(|e| e.leaf()).collect();
        Ok(hashing::merkle_witness(&leaves, idx))
    }

    pub fn create(
        &mut self,
        caller: Principal,
        now: u64,
        spec: NewElection,
    ) -> Result<u64, VoteError> {
        reject_anonymous(caller)?;
        spec.validate()?;
        let id = self.next_id;
        self.next_id += 1;
        self.elections.push(Election {
            id,
            title: spec.title,
            question: spec.question,
            options: spec.options,
            admin: caller,
            trustees: Vec::new(),
            threshold: 0,
            phase: Phase::Draft,
            created_at: now,
            opened_at: None,
            closed_at: None,
            pin: None,
            roll: Vec::new(),
            manifest_hash: None,
            log: Vec::new(),
            log_head: ZERO,
            voted: Vec::new(),
            approvals: BTreeMap::new(),
        });
        Ok(id)
    }

    /// Name the trustees and how many must approve. Draft only, like the
    /// roll and the pin, and for the same reason: it is part of the manifest.
    ///
    /// The threshold is checked against the list here, not left to the
    /// crate's `Policy::validate` at approval time, so a draft can never
    /// carry -- and a trustee never approve -- a policy no set of trustees
    /// could satisfy.
    pub fn set_trustees(
        &mut self,
        caller: Principal,
        id: u64,
        mut trustees: Vec<Principal>,
        threshold: u32,
    ) -> Result<u64, VoteError> {
        let e = self.get_mut(id)?;
        e.require_admin(caller)?;
        e.require_phase(Phase::Draft)?;
        if trustees.len() > MAX_TRUSTEES {
            return Err(VoteError::InvalidInput(format!(
                "trustees exceed MAX_TRUSTEES ({MAX_TRUSTEES})"
            )));
        }
        // The anonymous principal as a trustee would let any unauthenticated
        // caller cast that trustee's one ballot -- see `set_roll`.
        if trustees.iter().any(|p| *p == Principal::anonymous()) {
            return Err(VoteError::InvalidInput(
                "trustees must not include the anonymous principal".to_string(),
            ));
        }
        trustees.sort();
        let before = trustees.len();
        trustees.dedup();
        if trustees.len() != before {
            return Err(VoteError::InvalidInput(
                "trustees contains duplicate principals".to_string(),
            ));
        }
        if threshold as usize > trustees.len() {
            return Err(VoteError::InvalidInput(format!(
                "threshold {threshold} exceeds {} trustees",
                trustees.len()
            )));
        }
        e.trustees = trustees;
        e.threshold = threshold;
        Ok(e.trustees.len() as u64)
    }

    /// Record a trustee's decision on a stage's subject as it stands now.
    ///
    /// `Open` may be approved while the election is a draft, since that is
    /// when the manifest is still being decided and the only time the
    /// approval can gate anything. `Close` may be approved while the window
    /// is open -- that is what gates the close -- and also after it has
    /// closed, because a late attestation of the final count, or a public
    /// dissent from it, is still worth having on the board.
    pub fn approve(
        &mut self,
        caller: Principal,
        id: u64,
        stage: Stage,
        approve: bool,
        now: u64,
    ) -> Result<Approvals, VoteError> {
        reject_anonymous(caller)?;
        let e = self.get_mut(id)?;
        match stage {
            Stage::Open => e.require_phase(Phase::Draft)?,
            Stage::Close => {
                if e.phase == Phase::Draft {
                    return Err(VoteError::WrongPhase {
                        expected: "Open or Closed".to_string(),
                        actual: e.phase.name().to_string(),
                    });
                }
            }
        }
        let subject = e.subject(stage)?;
        let policy = e.policy();
        let decision = if approve {
            Decision::Approve
        } else {
            Decision::Reject
        };
        ic_multisig::record(
            &mut TrusteeBallots(&mut e.approvals),
            &policy,
            &subject,
            Approval::new(Approver::from(caller), decision, now),
        )
        .map_err(|err| match err {
            ic_multisig::Error::NotAnApprover => VoteError::NotTrustee,
            other => VoteError::InvalidInput(other.to_string()),
        })?;
        e.approvals(stage)
    }

    pub fn set_roll(
        &mut self,
        caller: Principal,
        id: u64,
        mut members: Vec<Principal>,
    ) -> Result<u64, VoteError> {
        let e = self.get_mut(id)?;
        e.require_admin(caller)?;
        e.require_phase(Phase::Draft)?;
        if members.len() > MAX_ROLL {
            return Err(VoteError::InvalidInput(format!(
                "roll exceeds MAX_ROLL ({MAX_ROLL})"
            )));
        }
        // An anonymous principal on the roll would be an eligibility hole
        // rather than a voter: every unauthenticated caller presents it, so
        // one entry would enfranchise the entire internet -- once, then hit
        // the double-vote check. Reject it at the door.
        if members.iter().any(|p| *p == Principal::anonymous()) {
            return Err(VoteError::InvalidInput(
                "roll must not contain the anonymous principal".to_string(),
            ));
        }
        members.sort();
        let before = members.len();
        members.dedup();
        if members.len() != before {
            return Err(VoteError::InvalidInput(
                "roll contains duplicate principals".to_string(),
            ));
        }
        if members.is_empty() {
            return Err(VoteError::EmptyRoll);
        }
        e.roll = members;
        Ok(e.roll.len() as u64)
    }

    pub fn pin_release(&mut self, caller: Principal, id: u64, pin: Pin) -> Result<(), VoteError> {
        pin.validate()?;
        let e = self.get_mut(id)?;
        e.require_admin(caller)?;
        e.require_phase(Phase::Draft)?;
        e.pin = Some(pin);
        Ok(())
    }

    /// Freeze the manifest and start the voting window.
    ///
    /// This is the only place `manifest_hash` is ever written, and it is
    /// written exactly once. Everything it commits to -- question, options,
    /// roll, pin, trustees -- becomes immutable here, because the ballot log
    /// chains from it and rewriting any of it would silently detach every
    /// cast ballot.
    ///
    /// When the manifest names a threshold, the hash frozen here is exactly
    /// the one the trustees approved: `require_approved` counts ballots on
    /// the hash of the draft as it stands, and that is the hash written.
    pub fn open(&mut self, caller: Principal, id: u64, now: u64) -> Result<ElectionView, VoteError> {
        let e = self.get_mut(id)?;
        e.require_admin(caller)?;
        e.require_phase(Phase::Draft)?;
        let mh = e.compute_manifest_hash()?;
        e.require_approved(Stage::Open)?;
        e.manifest_hash = Some(mh);
        e.log_head = hashing::log_genesis(&mh);
        e.opened_at = Some(now);
        e.phase = Phase::Open;
        Ok(e.view())
    }

    /// End the voting window. With a threshold, only once enough trustees
    /// have approved the tally hash as it stands -- which a ballot landing
    /// after their approval moves, so the approvals lapse and the trustees
    /// must look at the new count. That is the property wanted: nobody
    /// attests a count they have not seen.
    pub fn close(
        &mut self,
        caller: Principal,
        id: u64,
        now: u64,
    ) -> Result<ElectionView, VoteError> {
        let e = self.get_mut(id)?;
        e.require_admin(caller)?;
        e.require_phase(Phase::Open)?;
        e.require_approved(Stage::Close)?;
        e.closed_at = Some(now);
        e.phase = Phase::Closed;
        Ok(e.view())
    }

    /// Cast one ballot. Note what is NOT a parameter: the caller. Eligibility
    /// rides entirely on the in-ballot credential, so the shell passes the
    /// canister's own principal (`self_id`, bound into the signed message) and
    /// nothing about who sent the envelope. That absence is the mechanism of
    /// THREAT_MODEL.md 2.7: a voter submits from a single-use transport key,
    /// and this function could not bind the ballot to it even by mistake.
    pub fn cast(
        &mut self,
        self_id: &[u8],
        id: u64,
        choice: u32,
        pubkey_der: Vec<u8>,
        sig: Vec<u8>,
        sig_expires_at: u64,
        now: u64,
    ) -> Result<Receipt, VoteError> {
        let e = self.get_mut(id)?;
        e.require_phase(Phase::Open)?;
        if choice as usize >= e.options.len() {
            return Err(VoteError::InvalidChoice);
        }
        // Freshness: the signature authorizes this ballot only until its own
        // expiry, and the expiry may not be minted far into the future. This
        // is the ingress_expiry bound relocated into the ballot, now that the
        // envelope is deliberately unauthenticated.
        if now > sig_expires_at {
            return Err(VoteError::SignatureExpired);
        }
        if sig_expires_at > now.saturating_add(MAX_SIG_TTL_NS) {
            return Err(VoteError::InvalidInput(
                "sig_expires_at is further than MAX_SIG_TTL in the future".to_string(),
            ));
        }
        let voter = credential::principal_of(&pubkey_der)?;
        if e.roll.binary_search(&voter).is_err() {
            return Err(VoteError::NotEligible);
        }
        // V0 has no re-voting. That is a deliberate omission, not an oversight:
        // ROADMAP.md V1 lands re-voting together with the tally and nullifier
        // design, because a last-ballot-counts rule that is bolted onto a
        // public append-only log leaks the fact that a voter changed their
        // mind under observation -- which is the coercion case it exists to
        // help (THREAT_MODEL.md 3).
        let pos = match e.voted.binary_search(&voter) {
            Ok(_) => return Err(VoteError::AlreadyVoted),
            Err(pos) => pos,
        };
        // The signature is checked last: it is the expensive step, and every
        // rejection above is decidable from public data alone.
        let manifest = e.manifest_hash.as_ref().expect("Open implies a frozen manifest");
        let message = hashing::ballot_sig_message(self_id, manifest, choice, sig_expires_at);
        credential::verify(&pubkey_der, &message, &sig)?;
        let seq = e.log.len() as u64;
        let entry_hash =
            hashing::log_append(&e.log_head, seq, &pubkey_der, choice, now, sig_expires_at, &sig);
        e.log_head = entry_hash;
        e.log.push(Ballot {
            seq,
            voter,
            pubkey_der,
            choice,
            at: now,
            sig_expires_at,
            sig,
            entry_hash,
        });
        e.voted.insert(pos, voter);
        Ok(Receipt {
            election_id: id,
            seq,
            voter,
            choice,
            at: now,
            entry_hash: hex32(&entry_hash),
            log_head: hex32(&e.log_head),
        })
    }

    pub fn log_page(&self, id: u64, offset: u64, limit: u64) -> Result<Vec<BallotView>, VoteError> {
        let e = self.get(id)?;
        // Bounded so one query cannot exceed the response limit on a large
        // election; a client paginates and recomputes the chain incrementally.
        let limit = limit.min(1000) as usize;
        Ok(e.log
            .iter()
            .skip(offset as usize)
            .take(limit)
            .map(|b| BallotView {
                seq: b.seq,
                voter: b.voter,
                voter_pubkey: hex::encode(&b.pubkey_der),
                choice: b.choice,
                at: b.at,
                sig_expires_at: b.sig_expires_at,
                sig: hex::encode(&b.sig),
                entry_hash: hex32(&b.entry_hash),
            })
            .collect())
    }

    pub fn roll_page(&self, id: u64, offset: u64, limit: u64) -> Result<Vec<Principal>, VoteError> {
        let e = self.get(id)?;
        let limit = limit.min(10_000) as usize;
        Ok(e.roll
            .iter()
            .skip(offset as usize)
            .take(limit)
            .copied()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn p(n: u8) -> Principal {
        Principal::from_slice(&[n])
    }

    /// The canister principal the signed message binds to. Any stable bytes
    /// work: the tests that matter check that a signature bound to one value
    /// is rejected under another.
    const SELF_ID: &[u8] = b"test-poll-canister";

    /// A voter is a deterministic Ed25519 keypair; the roll holds the
    /// principal derived from its DER public key, exactly as production does.
    fn voter(seed: u8) -> (SigningKey, Vec<u8>, Principal) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let mut der = crate::credential::DER_PREFIX.to_vec();
        der.extend_from_slice(sk.verifying_key().as_bytes());
        let principal = crate::credential::principal_of(&der).unwrap();
        (sk, der, principal)
    }

    fn signed(s: &Store, id: u64, seed: u8, choice: u32, expires_at: u64) -> (Vec<u8>, Vec<u8>) {
        let (sk, der, _) = voter(seed);
        // Before open there is no manifest; sign over zeros so the phase
        // check, which fires first, is what the test exercises.
        let manifest = s
            .election(id)
            .ok()
            .and_then(|e| e.manifest_hash)
            .unwrap_or([0u8; 32]);
        let msg = hashing::ballot_sig_message(SELF_ID, &manifest, choice, expires_at);
        (der, sk.sign(&msg).to_bytes().to_vec())
    }

    fn cast(s: &mut Store, id: u64, seed: u8, choice: u32, at: u64) -> Result<Receipt, VoteError> {
        let expires_at = at + 60;
        let (der, sig) = signed(s, id, seed, choice, expires_at);
        s.cast(SELF_ID, id, choice, der, sig, expires_at, at)
    }

    fn spec() -> NewElection {
        NewElection {
            title: "Board seat".into(),
            question: "Seat Alice or Bob?".into(),
            options: vec!["Alice".into(), "Bob".into()],
        }
    }

    fn pin() -> Pin {
        Pin {
            repo: "ic-vote".into(),
            commit: "a".repeat(40),
            bundle_sha256: "b".repeat(64),
            site_canister: "umobs-yiaaa-aaaab-agyrq-cai".into(),
            module_sha256: "c".repeat(64),
            poll_module_sha256: "d".repeat(64),
            registry_chain_id: 11155111,
            registry_address: "0xa1362DAda583c56a395D305a8C7A458E0B62A209".into(),
        }
    }

    /// Draft election with voters 10 and 11 enrolled and a pin, admin = p(1).
    fn drafted() -> (Store, u64) {
        let mut s = Store::default();
        let id = s.create(p(1), 100, spec()).unwrap();
        s.set_roll(p(1), id, vec![voter(11).2, voter(10).2]).unwrap();
        s.pin_release(p(1), id, pin()).unwrap();
        (s, id)
    }

    fn opened() -> (Store, u64) {
        let (mut s, id) = drafted();
        s.open(p(1), id, 200).unwrap();
        (s, id)
    }

    #[test]
    fn happy_path_records_and_tallies() {
        let (mut s, id) = opened();
        cast(&mut s, id, 10, 0, 300).unwrap();
        cast(&mut s, id, 11, 1, 301).unwrap();
        let t = s.election(id).unwrap().tally();
        assert_eq!(t.counts, vec![1, 1]);
        assert_eq!(t.ballot_count, 2);
        assert!(t.tally_hash.is_some());
        // The receipt's voter is the principal derived from the credential.
        let e = s.election(id).unwrap();
        assert_eq!(e.log[0].voter, voter(10).2);
    }

    #[test]
    fn non_member_cannot_vote() {
        let (mut s, id) = opened();
        assert_eq!(cast(&mut s, id, 99, 0, 300), Err(VoteError::NotEligible));
    }

    #[test]
    fn anonymous_cannot_create() {
        let mut s = Store::default();
        assert_eq!(
            s.create(Principal::anonymous(), 1, spec()),
            Err(VoteError::AnonymousCaller)
        );
    }

    #[test]
    fn a_forged_signature_is_rejected_and_leaves_no_trace() {
        let (mut s, id) = opened();
        let head = s.election(id).unwrap().log_head;
        // Voter 11's signature presented with voter 10's key.
        let (der_10, _) = signed(&s, id, 10, 0, 360);
        let (_, sig_11) = signed(&s, id, 11, 0, 360);
        assert_eq!(
            s.cast(SELF_ID, id, 0, der_10.clone(), sig_11, 360, 300),
            Err(VoteError::InvalidSignature)
        );
        // A signature over a different choice than the one submitted.
        let (_, sig_other_choice) = signed(&s, id, 10, 1, 360);
        assert_eq!(
            s.cast(SELF_ID, id, 0, der_10.clone(), sig_other_choice, 360, 300),
            Err(VoteError::InvalidSignature)
        );
        // A signature over a different expiry than the one submitted.
        let (_, sig_other_expiry) = signed(&s, id, 10, 0, 361);
        assert_eq!(
            s.cast(SELF_ID, id, 0, der_10.clone(), sig_other_expiry, 360, 300),
            Err(VoteError::InvalidSignature)
        );
        assert_eq!(s.election(id).unwrap().log_head, head);
        assert!(s.election(id).unwrap().log.is_empty());
        // And the failures did not consume the voter's ballot.
        assert!(cast(&mut s, id, 10, 0, 301).is_ok());
    }

    #[test]
    fn an_expired_or_overlong_signature_is_rejected() {
        let (mut s, id) = opened();
        // Expired: now is past the signed expiry. This is the replay bound --
        // a harvested (pubkey, sig, choice, expiry) tuple dies with it.
        let (der, sig) = signed(&s, id, 10, 0, 360);
        assert_eq!(
            s.cast(SELF_ID, id, 0, der.clone(), sig.clone(), 360, 361),
            Err(VoteError::SignatureExpired)
        );
        // Overlong: a client may not mint a window-long bearer token.
        let far = 300 + MAX_SIG_TTL_NS + 1;
        let (der2, sig2) = signed(&s, id, 10, 0, far);
        assert!(matches!(
            s.cast(SELF_ID, id, 0, der2, sig2, far, 300),
            Err(VoteError::InvalidInput(_))
        ));
        // The rejections consumed nothing: the same voter still votes, and a
        // ballot at exactly its expiry instant is valid.
        assert!(s.cast(SELF_ID, id, 0, der, sig, 360, 360).is_ok());
    }

    #[test]
    fn a_ballot_does_not_replay_across_elections_or_canisters() {
        // Two elections identical in every field, on the same canister.
        let (mut s, id_a) = opened();
        let id_b = s.create(p(1), 100, spec()).unwrap();
        s.set_roll(p(1), id_b, vec![voter(11).2, voter(10).2]).unwrap();
        s.pin_release(p(1), id_b, pin()).unwrap();
        s.open(p(1), id_b, 900).unwrap();

        let (der, sig) = signed(&s, id_a, 10, 0, 960);
        // The manifests differ (by id alone: `opened_at` is not in the
        // preimage), so the signature is bound to election A and must not
        // land in election B.
        assert_eq!(
            s.cast(SELF_ID, id_b, 0, der.clone(), sig.clone(), 960, 930),
            Err(VoteError::InvalidSignature)
        );
        // Same election, different canister principal: also rejected.
        assert_eq!(
            s.cast(b"another-canister", id_a, 0, der, sig, 960, 930),
            Err(VoteError::InvalidSignature)
        );
    }

    #[test]
    fn double_voting_is_rejected_and_leaves_no_trace() {
        let (mut s, id) = opened();
        cast(&mut s, id, 10, 0, 300).unwrap();
        let head_after_first = s.election(id).unwrap().log_head;
        assert_eq!(cast(&mut s, id, 10, 1, 301), Err(VoteError::AlreadyVoted));
        // The rejected attempt must not have advanced the chain.
        assert_eq!(s.election(id).unwrap().log_head, head_after_first);
        assert_eq!(s.election(id).unwrap().log.len(), 1);
    }

    #[test]
    fn out_of_range_choice_is_rejected_before_the_log_moves() {
        let (mut s, id) = opened();
        let head = s.election(id).unwrap().log_head;
        assert_eq!(cast(&mut s, id, 10, 2, 300), Err(VoteError::InvalidChoice));
        assert_eq!(s.election(id).unwrap().log_head, head);
        // and the failed attempt did not consume the voter's one ballot
        assert!(cast(&mut s, id, 10, 1, 301).is_ok());
    }

    #[test]
    fn voting_is_confined_to_the_open_phase() {
        let (mut s, id) = drafted();
        assert!(matches!(
            cast(&mut s, id, 10, 0, 150),
            Err(VoteError::WrongPhase { .. })
        ));
        s.open(p(1), id, 200).unwrap();
        cast(&mut s, id, 10, 0, 300).unwrap();
        s.close(p(1), id, 400).unwrap();
        assert!(matches!(
            cast(&mut s, id, 11, 0, 500),
            Err(VoteError::WrongPhase { .. })
        ));
    }

    #[test]
    fn only_admin_administers() {
        let (mut s, id) = drafted();
        assert_eq!(s.set_roll(p(2), id, vec![p(10)]), Err(VoteError::NotAdmin));
        assert_eq!(s.pin_release(p(2), id, pin()), Err(VoteError::NotAdmin));
        assert_eq!(s.open(p(2), id, 200), Err(VoteError::NotAdmin));
        s.open(p(1), id, 200).unwrap();
        assert_eq!(s.close(p(2), id, 300), Err(VoteError::NotAdmin));
    }

    #[test]
    fn opening_requires_a_roll_and_a_pin() {
        let mut s = Store::default();
        let id = s.create(p(1), 100, spec()).unwrap();
        assert_eq!(s.open(p(1), id, 200), Err(VoteError::EmptyRoll));
        s.set_roll(p(1), id, vec![p(10)]).unwrap();
        assert_eq!(s.open(p(1), id, 200), Err(VoteError::NoPin));
        s.pin_release(p(1), id, pin()).unwrap();
        assert!(s.open(p(1), id, 200).is_ok());
    }

    #[test]
    fn roll_and_pin_are_frozen_once_open() {
        let (mut s, id) = opened();
        assert!(matches!(
            s.set_roll(p(1), id, vec![p(12)]),
            Err(VoteError::WrongPhase { .. })
        ));
        assert!(matches!(
            s.pin_release(p(1), id, pin()),
            Err(VoteError::WrongPhase { .. })
        ));
    }

    #[test]
    fn roll_order_does_not_change_the_manifest() {
        let mut a = Store::default();
        let ia = a.create(p(1), 100, spec()).unwrap();
        a.set_roll(p(1), ia, vec![p(10), p(11), p(12)]).unwrap();
        a.pin_release(p(1), ia, pin()).unwrap();
        a.open(p(1), ia, 200).unwrap();

        let mut b = Store::default();
        let ib = b.create(p(1), 100, spec()).unwrap();
        b.set_roll(p(1), ib, vec![p(12), p(10), p(11)]).unwrap();
        b.pin_release(p(1), ib, pin()).unwrap();
        b.open(p(1), ib, 200).unwrap();

        assert_eq!(
            a.election(ia).unwrap().manifest_hash,
            b.election(ib).unwrap().manifest_hash
        );
    }

    /// Every field of the pin must move the manifest hash. A field that is
    /// stored but not hashed is worse than a missing field: it renders in the
    /// UI as a commitment while an administrator can change it freely.
    #[test]
    fn every_pin_field_is_bound_into_the_manifest() {
        let baseline = {
            let (s, id) = opened();
            s.election(id).unwrap().manifest_hash
        };
        let mutations: Vec<(&str, Box<dyn Fn(&mut Pin)>)> = vec![
            ("repo", Box::new(|p: &mut Pin| p.repo = "other".into())),
            ("commit", Box::new(|p: &mut Pin| p.commit = "1".repeat(40))),
            ("bundle_sha256", Box::new(|p: &mut Pin| p.bundle_sha256 = "1".repeat(64))),
            (
                "site_canister",
                Box::new(|p: &mut Pin| p.site_canister = "aaaaa-aa".into()),
            ),
            ("module_sha256", Box::new(|p: &mut Pin| p.module_sha256 = "1".repeat(64))),
            (
                "poll_module_sha256",
                Box::new(|p: &mut Pin| p.poll_module_sha256 = "1".repeat(64)),
            ),
            ("registry_chain_id", Box::new(|p: &mut Pin| p.registry_chain_id = 100)),
            (
                "registry_address",
                Box::new(|p: &mut Pin| {
                    p.registry_address = "0x0000000000000000000000000000000000000009".into()
                }),
            ),
        ];
        for (field, mutate) in mutations {
            let mut s = Store::default();
            let id = s.create(p(1), 100, spec()).unwrap();
            // Same roll as `drafted()`: if it differed, every assertion below
            // would pass because of the roll, not the pin field under test.
            s.set_roll(p(1), id, vec![voter(11).2, voter(10).2]).unwrap();
            let mut changed = pin();
            mutate(&mut changed);
            s.pin_release(p(1), id, changed).unwrap();
            s.open(p(1), id, 200).unwrap();
            assert_ne!(
                baseline,
                s.election(id).unwrap().manifest_hash,
                "changing pin.{field} did not change the manifest hash"
            );
        }
    }

    #[test]
    fn duplicate_and_anonymous_rolls_are_rejected() {
        let mut s = Store::default();
        let id = s.create(p(1), 100, spec()).unwrap();
        assert!(matches!(
            s.set_roll(p(1), id, vec![p(10), p(10)]),
            Err(VoteError::InvalidInput(_))
        ));
        assert!(matches!(
            s.set_roll(p(1), id, vec![p(10), Principal::anonymous()]),
            Err(VoteError::InvalidInput(_))
        ));
    }

    #[test]
    fn log_chain_is_recomputable_from_the_published_log() {
        let (mut s, id) = opened();
        cast(&mut s, id, 10, 0, 300).unwrap();
        cast(&mut s, id, 11, 1, 301).unwrap();
        let e = s.election(id).unwrap();
        let mut head = hashing::log_genesis(&e.manifest_hash.unwrap());
        for b in &e.log {
            head = hashing::log_append(
                &head,
                b.seq,
                &b.pubkey_der,
                b.choice,
                b.at,
                b.sig_expires_at,
                &b.sig,
            );
            assert_eq!(head, b.entry_hash);
        }
        assert_eq!(head, e.log_head);
    }

    /// The franchise is recomputable from the published log alone: derive the
    /// principal from each entry's public key, verify each signature against
    /// the manifest. This is what tools/verify-election.mjs check D does, and
    /// the reason the credential is in the log at all.
    #[test]
    fn franchise_is_recomputable_from_the_published_log() {
        let (mut s, id) = opened();
        cast(&mut s, id, 10, 0, 300).unwrap();
        cast(&mut s, id, 11, 1, 301).unwrap();
        let e = s.election(id).unwrap();
        let manifest = e.manifest_hash.unwrap();
        for b in &e.log {
            assert_eq!(crate::credential::principal_of(&b.pubkey_der).unwrap(), b.voter);
            assert!(e.roll.binary_search(&b.voter).is_ok());
            // The freshness invariant is public: the recorded time never
            // exceeds the expiry the voter signed.
            assert!(b.at <= b.sig_expires_at);
            let msg = hashing::ballot_sig_message(SELF_ID, &manifest, b.choice, b.sig_expires_at);
            assert!(crate::credential::verify(&b.pubkey_der, &msg, &b.sig).is_ok());
        }
    }

    #[test]
    fn certified_root_moves_on_every_mutation() {
        let (mut s, id) = opened();
        let r0 = s.certified_root();
        cast(&mut s, id, 10, 0, 300).unwrap();
        let r1 = s.certified_root();
        assert_ne!(r0, r1);
        // A rejected ballot must not move it either.
        assert!(cast(&mut s, id, 10, 1, 301).is_err());
        assert_eq!(s.certified_root(), r1);
    }

    #[test]
    fn witness_ties_each_election_to_the_certified_root() {
        let mut s = Store::default();
        let mut ids = Vec::new();
        for _ in 0..7 {
            let id = s.create(p(1), 100, spec()).unwrap();
            s.set_roll(p(1), id, vec![voter(10).2, voter(11).2]).unwrap();
            s.pin_release(p(1), id, pin()).unwrap();
            s.open(p(1), id, 200).unwrap();
            ids.push(id);
        }
        cast(&mut s, ids[3], 10, 1, 300).unwrap();
        let root = s.certified_root();
        for id in ids {
            let e = s.election(id).unwrap();
            let leaf = hashing::merkle_leaf(
                e.id,
                &e.manifest_hash.unwrap(),
                &e.log_head,
                e.log.len() as u64,
            );
            let w = s.witness(id).unwrap();
            assert_eq!(hashing::merkle_recompute(&leaf, &w), root, "election {id}");
        }
    }

    #[test]
    fn tally_hash_tracks_the_result_it_describes() {
        let (mut s, id) = opened();
        let before = s.election(id).unwrap().tally().tally_hash;
        cast(&mut s, id, 10, 0, 300).unwrap();
        assert_ne!(before, s.election(id).unwrap().tally().tally_hash);
    }

    #[test]
    fn unknown_election_is_not_found() {
        let (s, _) = opened();
        assert!(matches!(s.election(42), Err(VoteError::NotFound)));
    }

    #[test]
    fn bad_specs_are_rejected() {
        let mut s = Store::default();
        let one = NewElection {
            options: vec!["only".into()],
            ..spec()
        };
        assert!(matches!(
            s.create(p(1), 1, one),
            Err(VoteError::InvalidInput(_))
        ));
        let dup = NewElection {
            options: vec!["a".into(), "a".into()],
            ..spec()
        };
        assert!(matches!(
            s.create(p(1), 1, dup),
            Err(VoteError::InvalidInput(_))
        ));
    }

    // --- trustees ---------------------------------------------------------

    /// Draft with trustees p(20), p(21), p(22) and threshold 2, admin p(1).
    fn drafted_with_trustees(threshold: u32) -> (Store, u64) {
        let (mut s, id) = drafted();
        s.set_trustees(p(1), id, vec![p(22), p(20), p(21)], threshold)
            .unwrap();
        (s, id)
    }

    fn approvals(s: &Store, id: u64, stage: Stage) -> (u32, u32, bool) {
        let a = s.election(id).unwrap().approvals(stage).unwrap();
        (a.approvals, a.required, a.reached)
    }

    #[test]
    fn threshold_zero_is_the_administrator_alone() {
        // Every other test in this module runs with no trustees: the default
        // is the pre-trustee behaviour, and this makes that explicit. Naming
        // trustees with threshold 0 changes nothing about who may open.
        let (mut s, id) = drafted_with_trustees(0);
        s.open(p(1), id, 200).unwrap();
        cast(&mut s, id, 10, 0, 300).unwrap();
        s.close(p(1), id, 400).unwrap();
    }

    #[test]
    fn opening_waits_for_k_trustees_to_approve_the_manifest() {
        let (mut s, id) = drafted_with_trustees(2);
        assert_eq!(
            s.open(p(1), id, 200),
            Err(VoteError::NotApproved { approvals: 0, required: 2 })
        );
        let a = s.approve(p(20), id, Stage::Open, true, 150).unwrap();
        assert_eq!((a.approvals, a.required, a.reached), (1, 2, false));
        // What they approved is exactly what the manifest endpoint shows.
        assert_eq!(a.subject, s.election(id).unwrap().manifest().unwrap().manifest_hash);
        assert_eq!(
            s.open(p(1), id, 200),
            Err(VoteError::NotApproved { approvals: 1, required: 2 })
        );
        s.approve(p(21), id, Stage::Open, true, 160).unwrap();
        let view = s.open(p(1), id, 200).unwrap();
        // The frozen hash is the one the trustees approved.
        assert_eq!(view.manifest_hash.unwrap(), a.subject);
        assert_eq!(approvals(&s, id, Stage::Open), (2, 2, true));
    }

    #[test]
    fn editing_the_draft_voids_manifest_approvals() {
        let (mut s, id) = drafted_with_trustees(1);
        s.approve(p(20), id, Stage::Open, true, 150).unwrap();
        assert_eq!(approvals(&s, id, Stage::Open), (1, 1, true));
        // The administrator changes the roll after the trustee signed off.
        s.set_roll(p(1), id, vec![voter(10).2]).unwrap();
        assert_eq!(approvals(&s, id, Stage::Open), (0, 1, false));
        assert_eq!(
            s.open(p(1), id, 200),
            Err(VoteError::NotApproved { approvals: 0, required: 1 })
        );
        // Changing the policy itself is also a manifest change.
        s.set_roll(p(1), id, vec![voter(11).2, voter(10).2]).unwrap();
        assert_eq!(approvals(&s, id, Stage::Open), (1, 1, true));
        s.set_trustees(p(1), id, vec![p(20), p(21)], 1).unwrap();
        assert_eq!(approvals(&s, id, Stage::Open), (0, 1, false));
    }

    #[test]
    fn stored_approvals_are_bounded_per_stage() {
        // The subject moves on every draft edit, and a trustee may approve
        // each value it takes. Unbounded, that is one permanent heap entry
        // per update call -- entries no endpoint can read back once the
        // subject has moved on, in state no upgrade can migrate away.
        let (mut s, id) = drafted_with_trustees(1);
        for i in 0..(MAX_APPROVAL_SUBJECTS + 5) {
            s.set_roll(p(1), id, vec![voter(10).2, voter(100 + i as u8).2])
                .unwrap();
            s.approve(p(20), id, Stage::Open, true, 150 + i as u64).unwrap();
        }
        assert!(s.election(id).unwrap().approvals.len() <= MAX_APPROVAL_SUBJECTS);
        // The subject as it stands is always the one kept, so the gate the
        // bound protects still works.
        assert_eq!(approvals(&s, id, Stage::Open), (1, 1, true));
        s.open(p(1), id, 900).unwrap();
    }

    #[test]
    fn closing_waits_for_trustees_to_attest_the_count() {
        let (mut s, id) = drafted_with_trustees(2);
        // Nothing to attest before the window opens: there is no count yet.
        assert!(matches!(
            s.approve(p(20), id, Stage::Close, true, 140),
            Err(VoteError::WrongPhase { .. })
        ));
        s.approve(p(20), id, Stage::Open, true, 150).unwrap();
        s.approve(p(21), id, Stage::Open, true, 160).unwrap();
        s.open(p(1), id, 200).unwrap();
        cast(&mut s, id, 10, 0, 300).unwrap();
        assert_eq!(
            s.close(p(1), id, 400),
            Err(VoteError::NotApproved { approvals: 0, required: 2 })
        );
        let a = s.approve(p(20), id, Stage::Close, true, 310).unwrap();
        assert_eq!(a.subject, s.election(id).unwrap().tally().tally_hash.unwrap());
        s.approve(p(22), id, Stage::Close, true, 320).unwrap();
        assert_eq!(approvals(&s, id, Stage::Close), (2, 2, true));
        // A ballot lands after both approvals: the count they attested is no
        // longer the count, so the close is refused until they look again.
        cast(&mut s, id, 11, 1, 330).unwrap();
        assert_eq!(approvals(&s, id, Stage::Close), (0, 2, false));
        assert_eq!(
            s.close(p(1), id, 400),
            Err(VoteError::NotApproved { approvals: 0, required: 2 })
        );
        s.approve(p(20), id, Stage::Close, true, 340).unwrap();
        s.approve(p(21), id, Stage::Close, true, 350).unwrap();
        s.close(p(1), id, 400).unwrap();
        // A late attestation of the final count is still recorded.
        let a = s.approve(p(22), id, Stage::Close, true, 500).unwrap();
        assert_eq!((a.approvals, a.reached), (3, true));
    }

    #[test]
    fn approvals_are_confined_to_their_stage_and_phase() {
        let (mut s, id) = drafted_with_trustees(1);
        assert!(matches!(
            s.approve(p(20), id, Stage::Close, true, 150),
            Err(VoteError::WrongPhase { .. })
        ));
        s.approve(p(20), id, Stage::Open, true, 150).unwrap();
        s.open(p(1), id, 200).unwrap();
        assert!(matches!(
            s.approve(p(20), id, Stage::Open, true, 250),
            Err(VoteError::WrongPhase { .. })
        ));
        // An approval of the manifest is not an approval of the tally, even
        // though the same trustee gave it.
        assert_eq!(approvals(&s, id, Stage::Close), (0, 1, false));
    }

    #[test]
    fn only_trustees_approve_and_each_counts_once() {
        let (mut s, id) = drafted_with_trustees(2);
        assert_eq!(
            s.approve(p(1), id, Stage::Open, true, 150),
            Err(VoteError::NotTrustee)
        );
        assert_eq!(
            s.approve(Principal::anonymous(), id, Stage::Open, true, 150),
            Err(VoteError::AnonymousCaller)
        );
        s.approve(p(20), id, Stage::Open, true, 150).unwrap();
        s.approve(p(20), id, Stage::Open, true, 151).unwrap();
        assert_eq!(approvals(&s, id, Stage::Open), (1, 2, false));
        // A trustee may change their mind, and the later ballot is the one
        // that counts.
        let a = s.approve(p(20), id, Stage::Open, false, 152).unwrap();
        assert_eq!((a.approvals, a.rejections), (0, 1));
        assert_eq!(a.ballots.len(), 1);
        assert!(!a.ballots[0].approve);
        // Nothing here moved anything a trustee should not be able to move.
        assert_eq!(s.election(id).unwrap().phase, Phase::Draft);
    }

    #[test]
    fn approvals_are_public_and_name_the_trustee() {
        let (mut s, id) = drafted_with_trustees(2);
        s.approve(p(21), id, Stage::Open, true, 150).unwrap();
        let a = s.election(id).unwrap().approvals(Stage::Open).unwrap();
        assert_eq!(
            a.ballots,
            vec![TrusteeBallot { trustee: p(21), approve: true, at: 150 }]
        );
    }

    #[test]
    fn trustees_and_threshold_are_bound_into_the_manifest() {
        let baseline = {
            let (s, id) = opened();
            s.election(id).unwrap().manifest_hash
        };
        let (mut s, id) = drafted_with_trustees(0);
        s.open(p(1), id, 200).unwrap();
        let with_trustees = s.election(id).unwrap().manifest_hash;
        assert_ne!(baseline, with_trustees);

        let (mut s, id) = drafted_with_trustees(1);
        s.approve(p(20), id, Stage::Open, true, 150).unwrap();
        s.open(p(1), id, 200).unwrap();
        assert_ne!(with_trustees, s.election(id).unwrap().manifest_hash);
    }

    #[test]
    fn trustee_order_does_not_change_the_manifest() {
        let (mut a, ia) = drafted();
        a.set_trustees(p(1), ia, vec![p(20), p(21)], 0).unwrap();
        a.open(p(1), ia, 200).unwrap();
        let (mut b, ib) = drafted();
        b.set_trustees(p(1), ib, vec![p(21), p(20)], 0).unwrap();
        b.open(p(1), ib, 200).unwrap();
        assert_eq!(
            a.election(ia).unwrap().manifest_hash,
            b.election(ib).unwrap().manifest_hash
        );
    }

    #[test]
    fn manifest_is_readable_in_draft_and_is_what_open_freezes() {
        let (mut s, id) = drafted_with_trustees(1);
        let draft = s.election(id).unwrap().manifest().unwrap();
        assert_eq!(draft.trustees, vec![p(20), p(21), p(22)]);
        assert_eq!(draft.threshold, 1);
        // Not yet frozen, and the certified leaf says so.
        assert_eq!(s.election(id).unwrap().view().manifest_hash, None);
        s.approve(p(22), id, Stage::Open, true, 150).unwrap();
        s.open(p(1), id, 200).unwrap();
        let frozen = s.election(id).unwrap().manifest().unwrap();
        assert_eq!(draft.manifest_hash, frozen.manifest_hash);
        assert_eq!(
            s.election(id).unwrap().view().manifest_hash,
            Some(frozen.manifest_hash)
        );
    }

    #[test]
    fn bad_trustee_lists_are_rejected() {
        let (mut s, id) = drafted();
        assert!(matches!(
            s.set_trustees(p(1), id, vec![p(20)], 2),
            Err(VoteError::InvalidInput(_))
        ));
        assert!(matches!(
            s.set_trustees(p(1), id, vec![p(20), p(20)], 1),
            Err(VoteError::InvalidInput(_))
        ));
        assert!(matches!(
            s.set_trustees(p(1), id, vec![p(20), Principal::anonymous()], 1),
            Err(VoteError::InvalidInput(_))
        ));
        assert_eq!(
            s.set_trustees(p(2), id, vec![p(20)], 1),
            Err(VoteError::NotAdmin)
        );
        // No trustees, threshold 0: explicitly allowed, it is the default.
        assert_eq!(s.set_trustees(p(1), id, vec![], 0), Ok(0));
        s.open(p(1), id, 200).unwrap();
        assert!(matches!(
            s.set_trustees(p(1), id, vec![p(20)], 1),
            Err(VoteError::WrongPhase { .. })
        ));
    }

    #[test]
    fn pin_validation_rejects_the_record_key_collision() {
        let mut bad = pin();
        bad.repo = "ic-vote#site".into();
        assert!(matches!(bad.validate(), Err(VoteError::InvalidInput(_))));

        let mut short = pin();
        short.commit = "abc".into();
        assert!(matches!(short.validate(), Err(VoteError::InvalidInput(_))));

        let mut upper = pin();
        upper.module_sha256 = "C".repeat(64);
        assert!(matches!(upper.validate(), Err(VoteError::InvalidInput(_))));

        // A checksummed (mixed-case) EVM address must survive validation
        // unchanged -- normalizing it would destroy the EIP-55 checksum.
        assert!(pin().validate().is_ok());
    }
}
