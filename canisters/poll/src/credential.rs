//! The ballot credential: an Ed25519 key that stands where `msg_caller` used
//! to (THREAT_MODEL.md 2.7).
//!
//! A cast carries the voter's DER-encoded public key and a signature over
//! `hashing::ballot_sig_message`. Eligibility is decided by deriving the
//! self-authenticating principal from that key and looking it up on the roll;
//! the message envelope's caller is never consulted, so a voter submits from
//! a single-use transport key and nothing links the submission to their roll
//! identity at the transport layer. (Network and timing metadata still do --
//! that residual is stated in THREAT_MODEL.md 2.7, not solved here.)
//!
//! The derivation matches the IC's own: principal = sha224(DER pubkey) || 0x02.
//! Using the same rule the platform uses means a roll built from principals
//! that voters obtained any other way (whoami, dfx) still matches.

use candid::Principal;
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha224};

use crate::types::VoteError;

/// The IC's DER wrapper for an Ed25519 SPKI key: a fixed 12-byte prefix
/// followed by the raw 32-byte key. Parsed by exact match rather than by an
/// ASN.1 library: the grammar admits exactly one shape, and a parser that
/// accepted more shapes would let one key have several DER spellings -- and
/// therefore several principals.
pub(crate) const DER_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
pub const DER_LEN: usize = 12 + 32;
pub const SIG_LEN: usize = 64;

fn raw_key(pubkey_der: &[u8]) -> Result<[u8; 32], VoteError> {
    if pubkey_der.len() != DER_LEN || pubkey_der[..12] != DER_PREFIX {
        return Err(VoteError::InvalidInput(
            "voter_pubkey must be a 44-byte DER-encoded Ed25519 public key".to_string(),
        ));
    }
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&pubkey_der[12..]);
    Ok(raw)
}

/// The self-authenticating principal this key controls.
pub fn principal_of(pubkey_der: &[u8]) -> Result<Principal, VoteError> {
    raw_key(pubkey_der)?;
    let digest: [u8; 28] = Sha224::digest(pubkey_der).into();
    let mut blob = [0u8; 29];
    blob[..28].copy_from_slice(&digest);
    blob[28] = 0x02;
    Ok(Principal::from_slice(&blob))
}

/// Verify the ballot signature.
///
/// `verify_strict`, not `verify`: strict rejects small-order and mixed-order
/// points, so every signature this canister accepts also verifies under the
/// laxer cofactorless check that WebCrypto and OpenSSL implement. The
/// independent verifiers (site/lib/election-hash.js, tools/verify-election.mjs)
/// use those platform verifiers, and the acceptance sets must nest in this
/// direction -- a log entry the canister accepted but a voter's browser
/// rejects would read as a forged board.
pub fn verify(pubkey_der: &[u8], message: &[u8], sig: &[u8]) -> Result<(), VoteError> {
    let raw = raw_key(pubkey_der)?;
    let key = VerifyingKey::from_bytes(&raw)
        .map_err(|_| VoteError::InvalidInput("voter_pubkey is not a valid Ed25519 point".to_string()))?;
    let sig: [u8; SIG_LEN] = sig
        .try_into()
        .map_err(|_| VoteError::InvalidInput("sig must be 64 bytes".to_string()))?;
    key.verify_strict(message, &Signature::from_bytes(&sig))
        .map_err(|_| VoteError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn keypair(seed: u8) -> (SigningKey, Vec<u8>) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let mut der = DER_PREFIX.to_vec();
        der.extend_from_slice(sk.verifying_key().as_bytes());
        (sk, der)
    }

    #[test]
    fn principal_matches_the_ic_derivation() {
        // Vector produced independently: sha224 of the DER key, suffix 0x02.
        let (_, der) = keypair(1);
        let p = principal_of(&der).unwrap();
        assert_eq!(p.as_slice().len(), 29);
        assert_eq!(p.as_slice()[28], 0x02);
        let digest: [u8; 28] = Sha224::digest(&der).into();
        assert_eq!(&p.as_slice()[..28], &digest);
    }

    #[test]
    fn malformed_der_is_rejected_everywhere() {
        let (_, mut der) = keypair(1);
        der[0] ^= 1;
        assert!(principal_of(&der).is_err());
        assert!(verify(&der, b"m", &[0u8; 64]).is_err());
        assert!(principal_of(&der[..43]).is_err());
    }

    #[test]
    fn good_signature_verifies_and_forgeries_do_not() {
        let (sk, der) = keypair(2);
        let msg = b"the message";
        let sig = sk.sign(msg).to_bytes();
        assert!(verify(&der, msg, &sig).is_ok());
        assert_eq!(verify(&der, b"another message", &sig), Err(VoteError::InvalidSignature));
        let (_, other_der) = keypair(3);
        assert_eq!(verify(&other_der, msg, &sig), Err(VoteError::InvalidSignature));
        let mut bad = sig;
        bad[0] ^= 1;
        assert_eq!(verify(&der, msg, &bad), Err(VoteError::InvalidSignature));
        assert!(matches!(verify(&der, msg, &sig[..63]), Err(VoteError::InvalidInput(_))));
    }
}
