//! Election state and the rules that govern it.
//!
//! Deliberately free of `ic_cdk`: every entry point takes `caller` and `now`
//! as arguments. That is not stylistic. It means the entire rule set --
//! eligibility, double-voting, phase transitions, manifest freezing -- is
//! exercised by ordinary `cargo test` on the host, so a reviewer (T3) can
//! check the logic without a replica and without trusting a deployment.

use candid::{CandidType, Principal};
use serde::Deserialize;

use crate::hashing::{self, Hash, MerkleStep};
use crate::types::*;

/// Ceiling on roll size. State lives on the heap and is re-serialized on every
/// upgrade, so this is a real limit, not a formality: at ~29 bytes per
/// principal a 200k roll is ~6 MB of roll plus a ballot log of similar order.
/// V0 targets organizational elections (README.md), where rolls are orders of
/// magnitude smaller. Raising this is a stable-memory redesign, not a constant
/// bump.
pub const MAX_ROLL: usize = 200_000;

const ZERO: Hash = [0u8; 32];

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct Ballot {
    pub seq: u64,
    pub voter: Principal,
    pub choice: u32,
    pub at: u64,
    pub entry_hash: Hash,
}

#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct Election {
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

    fn manifest_fields<'a>(&'a self, opened_at: u64, pin: &'a Pin) -> hashing::ManifestFields<'a> {
        hashing::ManifestFields {
            id: self.id,
            title: &self.title,
            question: &self.question,
            options: &self.options,
            admin: self.admin.as_slice(),
            opened_at,
            roll_hash: self.roll_hash(),
            pin_repo: &pin.repo,
            pin_commit: &pin.commit,
            pin_bundle_sha256: &pin.bundle_sha256,
            pin_site_canister: &pin.site_canister,
            pin_module_sha256: &pin.module_sha256,
            pin_registry_chain_id: pin.registry_chain_id,
            pin_registry_address: &pin.registry_address,
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

    pub fn manifest(&self) -> Option<Manifest> {
        let (mh, pin, opened_at) = (
            self.manifest_hash.as_ref()?,
            self.pin.as_ref()?,
            self.opened_at?,
        );
        Some(Manifest {
            id: self.id,
            title: self.title.clone(),
            question: self.question.clone(),
            options: self.options.clone(),
            admin: self.admin,
            opened_at,
            roll_hash: hex32(&self.roll_hash()),
            pin: pin.clone(),
            manifest_hash: hex32(mh),
        })
    }

    pub fn tally(&self) -> Tally {
        let counts = self.counts();
        Tally {
            election_id: self.id,
            phase: self.phase,
            options: self.options.clone(),
            counts: counts.clone(),
            ballot_count: self.log.len() as u64,
            roll_size: self.roll.len() as u64,
            log_head: hex32(&self.log_head),
            manifest_hash: self.manifest_hash.as_ref().map(hex32),
            tally_hash: self
                .manifest_hash
                .as_ref()
                .map(|mh| hex32(&hashing::tally_hash(mh, &self.log_head, &counts))),
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
        });
        Ok(id)
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
    /// roll, pin -- becomes immutable here, because the ballot log chains from
    /// it and rewriting any of it would silently detach every cast ballot.
    pub fn open(&mut self, caller: Principal, id: u64, now: u64) -> Result<ElectionView, VoteError> {
        let e = self.get_mut(id)?;
        e.require_admin(caller)?;
        e.require_phase(Phase::Draft)?;
        if e.roll.is_empty() {
            return Err(VoteError::EmptyRoll);
        }
        let pin = e.pin.clone().ok_or(VoteError::NoPin)?;
        let mh = hashing::manifest_hash(&e.manifest_fields(now, &pin));
        e.manifest_hash = Some(mh);
        e.log_head = hashing::log_genesis(&mh);
        e.opened_at = Some(now);
        e.phase = Phase::Open;
        Ok(e.view())
    }

    pub fn close(
        &mut self,
        caller: Principal,
        id: u64,
        now: u64,
    ) -> Result<ElectionView, VoteError> {
        let e = self.get_mut(id)?;
        e.require_admin(caller)?;
        e.require_phase(Phase::Open)?;
        e.closed_at = Some(now);
        e.phase = Phase::Closed;
        Ok(e.view())
    }

    pub fn cast(
        &mut self,
        caller: Principal,
        id: u64,
        choice: u32,
        now: u64,
    ) -> Result<Receipt, VoteError> {
        reject_anonymous(caller)?;
        let e = self.get_mut(id)?;
        e.require_phase(Phase::Open)?;
        if e.roll.binary_search(&caller).is_err() {
            return Err(VoteError::NotEligible);
        }
        // V0 has no re-voting. That is a deliberate omission, not an oversight:
        // ROADMAP.md V1 lands re-voting together with the tally and nullifier
        // design, because a last-ballot-counts rule that is bolted onto a
        // public append-only log leaks the fact that a voter changed their
        // mind under observation -- which is the coercion case it exists to
        // help (THREAT_MODEL.md 3).
        let pos = match e.voted.binary_search(&caller) {
            Ok(_) => return Err(VoteError::AlreadyVoted),
            Err(pos) => pos,
        };
        if choice as usize >= e.options.len() {
            return Err(VoteError::InvalidChoice);
        }
        let seq = e.log.len() as u64;
        let entry_hash = hashing::log_append(&e.log_head, seq, caller.as_slice(), choice, now);
        e.log_head = entry_hash;
        e.log.push(Ballot {
            seq,
            voter: caller,
            choice,
            at: now,
            entry_hash,
        });
        e.voted.insert(pos, caller);
        Ok(Receipt {
            election_id: id,
            seq,
            voter: caller,
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
                choice: b.choice,
                at: b.at,
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

    fn p(n: u8) -> Principal {
        Principal::from_slice(&[n])
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
            registry_chain_id: 11155111,
            registry_address: "0xa1362DAda583c56a395D305a8C7A458E0B62A209".into(),
        }
    }

    /// Draft election with roll {p(10), p(11)} and a pin, admin = p(1).
    fn drafted() -> (Store, u64) {
        let mut s = Store::default();
        let id = s.create(p(1), 100, spec()).unwrap();
        s.set_roll(p(1), id, vec![p(11), p(10)]).unwrap();
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
        s.cast(p(10), id, 0, 300).unwrap();
        s.cast(p(11), id, 1, 301).unwrap();
        let t = s.election(id).unwrap().tally();
        assert_eq!(t.counts, vec![1, 1]);
        assert_eq!(t.ballot_count, 2);
        assert!(t.tally_hash.is_some());
    }

    #[test]
    fn non_member_cannot_vote() {
        let (mut s, id) = opened();
        assert_eq!(s.cast(p(99), id, 0, 300), Err(VoteError::NotEligible));
    }

    #[test]
    fn anonymous_cannot_vote_or_create() {
        let (mut s, id) = opened();
        assert_eq!(
            s.cast(Principal::anonymous(), id, 0, 300),
            Err(VoteError::AnonymousCaller)
        );
        assert_eq!(
            s.create(Principal::anonymous(), 1, spec()),
            Err(VoteError::AnonymousCaller)
        );
    }

    #[test]
    fn double_voting_is_rejected_and_leaves_no_trace() {
        let (mut s, id) = opened();
        s.cast(p(10), id, 0, 300).unwrap();
        let head_after_first = s.election(id).unwrap().log_head;
        assert_eq!(s.cast(p(10), id, 1, 301), Err(VoteError::AlreadyVoted));
        // The rejected attempt must not have advanced the chain.
        assert_eq!(s.election(id).unwrap().log_head, head_after_first);
        assert_eq!(s.election(id).unwrap().log.len(), 1);
    }

    #[test]
    fn out_of_range_choice_is_rejected_before_the_log_moves() {
        let (mut s, id) = opened();
        let head = s.election(id).unwrap().log_head;
        assert_eq!(s.cast(p(10), id, 2, 300), Err(VoteError::InvalidChoice));
        assert_eq!(s.election(id).unwrap().log_head, head);
        // and the failed attempt did not consume the voter's one ballot
        assert!(s.cast(p(10), id, 1, 301).is_ok());
    }

    #[test]
    fn voting_is_confined_to_the_open_phase() {
        let (mut s, id) = drafted();
        assert!(matches!(
            s.cast(p(10), id, 0, 150),
            Err(VoteError::WrongPhase { .. })
        ));
        s.open(p(1), id, 200).unwrap();
        s.cast(p(10), id, 0, 300).unwrap();
        s.close(p(1), id, 400).unwrap();
        assert!(matches!(
            s.cast(p(11), id, 0, 500),
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

    #[test]
    fn a_different_pin_is_a_different_election() {
        let (a, ia) = opened();
        let mut b = Store::default();
        let ib = b.create(p(1), 100, spec()).unwrap();
        b.set_roll(p(1), ib, vec![p(11), p(10)]).unwrap();
        let mut other = pin();
        other.bundle_sha256 = "d".repeat(64);
        b.pin_release(p(1), ib, other).unwrap();
        b.open(p(1), ib, 200).unwrap();
        assert_ne!(
            a.election(ia).unwrap().manifest_hash,
            b.election(ib).unwrap().manifest_hash
        );
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
        s.cast(p(10), id, 0, 300).unwrap();
        s.cast(p(11), id, 1, 301).unwrap();
        let e = s.election(id).unwrap();
        let mut head = hashing::log_genesis(&e.manifest_hash.unwrap());
        for b in &e.log {
            head = hashing::log_append(&head, b.seq, b.voter.as_slice(), b.choice, b.at);
            assert_eq!(head, b.entry_hash);
        }
        assert_eq!(head, e.log_head);
    }

    #[test]
    fn certified_root_moves_on_every_mutation() {
        let (mut s, id) = opened();
        let r0 = s.certified_root();
        s.cast(p(10), id, 0, 300).unwrap();
        let r1 = s.certified_root();
        assert_ne!(r0, r1);
        // A rejected ballot must not move it either.
        assert!(s.cast(p(10), id, 1, 301).is_err());
        assert_eq!(s.certified_root(), r1);
    }

    #[test]
    fn witness_ties_each_election_to_the_certified_root() {
        let mut s = Store::default();
        let mut ids = Vec::new();
        for _ in 0..7 {
            let id = s.create(p(1), 100, spec()).unwrap();
            s.set_roll(p(1), id, vec![p(10), p(11)]).unwrap();
            s.pin_release(p(1), id, pin()).unwrap();
            s.open(p(1), id, 200).unwrap();
            ids.push(id);
        }
        s.cast(p(10), ids[3], 1, 300).unwrap();
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
        s.cast(p(10), id, 0, 300).unwrap();
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
