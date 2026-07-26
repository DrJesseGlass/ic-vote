//! Every hash a client is expected to recompute, in one file.
//!
//! This module is the contract between the canister and any independent
//! verifier. `tools/verify-election.mjs` is a second, deliberately separate
//! implementation of exactly these functions; if the two ever disagree, the
//! bulletin board is not verifiable and the election is void. The cross-check
//! is a test (`tests/cross_impl.rs` feeds the same vectors to both), not a
//! comment.
//!
//! Two rules govern everything here, and breaking either one silently converts
//! a verifiable log into a forgeable one:
//!
//! 1. **Domain separation.** Every hash is prefixed by a distinct, length-
//!    prefixed domain string. Without it a leaf hash can be replayed as an
//!    internal node hash, which is the standard Merkle second-preimage attack.
//! 2. **Length prefixing.** Every variable-length field is written as
//!    `u32be(len) || bytes`. Bare concatenation lets `("ab", "c")` and
//!    `("a", "bc")` produce the same digest, so an attacker could move bytes
//!    across a field boundary -- e.g. between a candidate name and the next
//!    option -- without changing the manifest hash.

use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

const D_MANIFEST: &[u8] = b"ic-vote/v0/manifest";
const D_ROLL: &[u8] = b"ic-vote/v0/roll";
const D_GENESIS: &[u8] = b"ic-vote/v0/log-genesis";
const D_ENTRY: &[u8] = b"ic-vote/v0/log-entry";
const D_TALLY: &[u8] = b"ic-vote/v0/tally";
const D_LEAF: &[u8] = b"ic-vote/v0/merkle-leaf";
const D_NODE: &[u8] = b"ic-vote/v0/merkle-node";
const D_EMPTY: &[u8] = b"ic-vote/v0/merkle-empty";

/// A domain-separated, length-prefixed hash builder.
///
/// Deliberately has no method that writes raw bytes without a length prefix.
/// The type is the enforcement mechanism for rule 2 above.
pub struct HashWriter(Sha256);

impl HashWriter {
    pub fn new(domain: &[u8]) -> Self {
        let mut h = Sha256::new();
        // The domain is itself length-prefixed, so no domain string can be a
        // prefix of another one and collide with it.
        h.update((domain.len() as u32).to_be_bytes());
        h.update(domain);
        Self(h)
    }

    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.0.update(v.to_be_bytes());
        self
    }

    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.0.update(v.to_be_bytes());
        self
    }

    /// Fixed 32 bytes, so no length prefix is needed.
    pub fn hash(&mut self, h: &Hash) -> &mut Self {
        self.0.update(h);
        self
    }

    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.0.update((b.len() as u32).to_be_bytes());
        self.0.update(b);
        self
    }

    pub fn text(&mut self, s: &str) -> &mut Self {
        self.bytes(s.as_bytes())
    }

    pub fn finish(&self) -> Hash {
        self.0.clone().finalize().into()
    }
}

/// Commitment to the eligibility roll (T4 in THREAT_MODEL.md).
///
/// `principals` MUST be sorted and deduplicated; the caller owns that
/// invariant because sorting here would hide a duplicate-entry bug in the
/// roll rather than rejecting it.
pub fn roll_hash(principals: &[&[u8]]) -> Hash {
    let mut w = HashWriter::new(D_ROLL);
    w.u32(principals.len() as u32);
    for p in principals {
        w.bytes(p);
    }
    w.finish()
}

/// Fields frozen when an election opens. Everything a voter needs in order to
/// know *which* election their ballot is in, including the provenance pin --
/// so the pin cannot be swapped mid-window without changing every subsequent
/// log entry.
pub struct ManifestFields<'a> {
    pub id: u64,
    pub title: &'a str,
    pub question: &'a str,
    pub options: &'a [String],
    pub admin: &'a [u8],
    pub opened_at: u64,
    pub roll_hash: Hash,
    pub pin_repo: &'a str,
    pub pin_commit: &'a str,
    pub pin_bundle_sha256: &'a str,
    pub pin_site_canister: &'a str,
    pub pin_module_sha256: &'a str,
    pub pin_registry_chain_id: u64,
    pub pin_registry_address: &'a str,
}

pub fn manifest_hash(m: &ManifestFields) -> Hash {
    let mut w = HashWriter::new(D_MANIFEST);
    w.u64(m.id)
        .text(m.title)
        .text(m.question)
        .u32(m.options.len() as u32);
    for o in m.options {
        w.text(o);
    }
    w.bytes(m.admin)
        .u64(m.opened_at)
        .hash(&m.roll_hash)
        .text(m.pin_repo)
        .text(m.pin_commit)
        .text(m.pin_bundle_sha256)
        .text(m.pin_site_canister)
        .text(m.pin_module_sha256)
        .u64(m.pin_registry_chain_id)
        .text(m.pin_registry_address);
    w.finish()
}

/// Head of an empty log. Chains from the manifest hash, so a log is bound to
/// exactly one election: replaying entries from another election, or from the
/// same election under a different pin, does not produce a valid chain.
pub fn log_genesis(manifest: &Hash) -> Hash {
    let mut w = HashWriter::new(D_GENESIS);
    w.hash(manifest);
    w.finish()
}

/// Append one ballot to the chain. The returned hash is both the new head and
/// the voter's receipt: it is unforgeable without every preceding entry, so a
/// voter who keeps it can detect a log that was rewritten behind them.
pub fn log_append(prev: &Hash, seq: u64, voter: &[u8], choice: u32, at: u64) -> Hash {
    let mut w = HashWriter::new(D_ENTRY);
    w.hash(prev).u64(seq).bytes(voter).u32(choice).u64(at);
    w.finish()
}

/// The number to checkpoint on-chain at close (ROADMAP.md V0).
pub fn tally_hash(manifest: &Hash, log_head: &Hash, counts: &[u64]) -> Hash {
    let mut w = HashWriter::new(D_TALLY);
    w.hash(manifest).hash(log_head).u32(counts.len() as u32);
    for c in counts {
        w.u64(*c);
    }
    w.finish()
}

/// One election's leaf in the canister's certified-data tree.
pub fn merkle_leaf(id: u64, manifest: &Hash, log_head: &Hash, ballot_count: u64) -> Hash {
    let mut w = HashWriter::new(D_LEAF);
    w.u64(id).hash(manifest).hash(log_head).u64(ballot_count);
    w.finish()
}

fn merkle_node(left: &Hash, right: &Hash) -> Hash {
    let mut w = HashWriter::new(D_NODE);
    w.hash(left).hash(right);
    w.finish()
}

pub fn merkle_empty() -> Hash {
    HashWriter::new(D_EMPTY).finish()
}

/// One hop up the tree. `sibling_is_right` says which side to place the
/// sibling on when recomputing, because `merkle_node` is not commutative --
/// and it must not be. A commutative combiner lets an attacker swap a
/// left/right pair and produce the same root from a different tree.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MerkleStep {
    pub sibling: Hash,
    pub sibling_is_right: bool,
}

/// Root over leaves in caller-supplied order (elections sorted by id).
///
/// An odd node at a level is promoted unchanged rather than paired with a copy
/// of itself. Duplicating would make a 2-leaf tree and a 3-leaf tree whose
/// third leaf equals the second produce related roots; promotion plus the
/// leaf/node domain split keeps every tree shape unambiguous.
pub fn merkle_root(leaves: &[Hash]) -> Hash {
    if leaves.is_empty() {
        return merkle_empty();
    }
    let mut level: Vec<Hash> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i + 1 < level.len() {
            next.push(merkle_node(&level[i], &level[i + 1]));
            i += 2;
        }
        if i < level.len() {
            next.push(level[i]);
        }
        level = next;
    }
    level[0]
}

/// Sibling path proving `leaves[index]` is in `merkle_root(leaves)`.
pub fn merkle_witness(leaves: &[Hash], index: usize) -> Vec<MerkleStep> {
    let mut steps = Vec::new();
    if index >= leaves.len() {
        return steps;
    }
    let mut level: Vec<Hash> = leaves.to_vec();
    let mut idx = index;
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i + 1 < level.len() {
            next.push(merkle_node(&level[i], &level[i + 1]));
            i += 2;
        }
        let promoted = i < level.len();
        if promoted {
            next.push(level[i]);
        }
        // A promoted node has no sibling, so it contributes no step.
        if !(promoted && idx == level.len() - 1) {
            if idx % 2 == 0 {
                steps.push(MerkleStep {
                    sibling: level[idx + 1],
                    sibling_is_right: true,
                });
            } else {
                steps.push(MerkleStep {
                    sibling: level[idx - 1],
                    sibling_is_right: false,
                });
            }
        }
        idx /= 2;
        level = next;
    }
    steps
}

/// Recompute a root from a leaf and its witness. The canister never needs
/// this -- a client does -- but it lives here so the canister's own tests
/// verify witnesses the same way a client will, rather than asserting against
/// a second copy of the tree builder that would share any bug it has.
#[allow(dead_code)]
pub fn merkle_recompute(leaf: &Hash, steps: &[MerkleStep]) -> Hash {
    let mut acc = *leaf;
    for s in steps {
        acc = if s.sibling_is_right {
            merkle_node(&acc, &s.sibling)
        } else {
            merkle_node(&s.sibling, &acc)
        };
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(n: u8) -> Hash {
        [n; 32]
    }

    #[test]
    fn length_prefixing_prevents_field_boundary_collision() {
        // The attack this defends against: moving a byte from one option into
        // the next one, keeping the concatenation identical.
        let a = vec!["ab".to_string(), "c".to_string()];
        let b = vec!["a".to_string(), "bc".to_string()];
        let mk = |opts: &Vec<String>| {
            manifest_hash(&ManifestFields {
                id: 1,
                title: "t",
                question: "q",
                options: opts,
                admin: &[1, 2, 3],
                opened_at: 0,
                roll_hash: h(0),
                pin_repo: "r",
                pin_commit: "c",
                pin_bundle_sha256: "b",
                pin_site_canister: "s",
                pin_module_sha256: "m",
                pin_registry_chain_id: 1,
                pin_registry_address: "0x0",
            })
        };
        assert_ne!(mk(&a), mk(&b));
    }

    #[test]
    fn domains_are_separated() {
        // A leaf hash must never be usable as an internal node hash.
        let leaf = merkle_leaf(0, &h(0), &h(0), 0);
        let node = merkle_node(&h(0), &h(0));
        assert_ne!(leaf, node);
        assert_ne!(merkle_empty(), h(0));
    }

    #[test]
    fn chain_is_order_sensitive() {
        let g = log_genesis(&h(7));
        let ab = log_append(&log_append(&g, 0, b"a", 0, 1), 1, b"b", 1, 2);
        let ba = log_append(&log_append(&g, 0, b"b", 1, 2), 1, b"a", 0, 1);
        assert_ne!(ab, ba);
    }

    #[test]
    fn chain_is_bound_to_its_manifest() {
        assert_ne!(
            log_append(&log_genesis(&h(1)), 0, b"a", 0, 1),
            log_append(&log_genesis(&h(2)), 0, b"a", 0, 1)
        );
    }

    #[test]
    fn witness_recomputes_root_at_every_size_and_index() {
        // Odd sizes exercise the promotion path, which is where an off-by-one
        // in `merkle_witness` would hide.
        for n in 1..=17usize {
            let leaves: Vec<Hash> = (0..n).map(|i| h(i as u8)).collect();
            let root = merkle_root(&leaves);
            for i in 0..n {
                let w = merkle_witness(&leaves, i);
                assert_eq!(
                    merkle_recompute(&leaves[i], &w),
                    root,
                    "n={n} index={i} witness={w:?}"
                );
            }
        }
    }

    #[test]
    fn witness_does_not_prove_a_leaf_that_is_absent() {
        let leaves: Vec<Hash> = (0..5).map(|i| h(i)).collect();
        let root = merkle_root(&leaves);
        let w = merkle_witness(&leaves, 2);
        assert_ne!(merkle_recompute(&h(99), &w), root);
    }
}
