//! # Schnorr Signature Variant Implementation using Arkworks
//!
//! This library implements a variant of the Schnorr signature scheme using the [Arkworks](https://arkworks.rs) library,
//! specifically with the BLS12-381 elliptic curve.
//!
//! ## Schnorr Signatures Overview
//!
//! Schnorr signatures are a form of digital signature known for their simplicity, efficiency, and
//! security properties including:
//! - Non-malleability: signatures cannot be altered without invalidating them
//! - Linearity: allowing for signature aggregation and threshold signing schemes
//! - Provable security: under the discrete logarithm assumption
//!
//! ## Implementation Details
//!
//! This implementation is a **non-standard variant** of Schnorr signatures with these characteristics:
//! - BLS12-381 elliptic curve (instead of the typical secp256k1 or Edwards25519)
//! - Challenge computation using Hash(Public key || message || R)
//!   (differs from standards like BIP-340 which uses Hash(R || Public key || message))
//! - SHA-256 for hashing
//! - Secure randomness via the `rand` crate
//!
//! > **Note:** This implementation follows the mathematical structure of Schnorr signatures but does not
//! > conform to standardized variants like Bitcoin's BIP-340 or Ed25519.
//!
//! ## Basic Usage
//!
//! ```
//! use schnorr_ark::{generate_key_pair, sign, verify};
//!
//! // Generate a new key pair
//! let keypair = generate_key_pair();
//! // Create a message
//! let message = "hello world".as_bytes().to_vec();
//! // Sign the message
//! let signature = sign(&keypair, message.clone()).expect("Signing should succeed");
//! // Verify the signature
//! let is_valid = verify(keypair.public_key, &signature, message);
//! assert!(is_valid);
//! ```

use ark_ff::{Fp256, MontBackend, UniformRand};
use ark_serialize::CanonicalSerialize;
use ark_test_curves::bls12_381::g1::Config;
use ark_test_curves::bls12_381::FrConfig;
use ark_test_curves::short_weierstrass::Projective;
use ark_test_curves::{
    bls12_381::{Fr, G1Projective},
    PrimeField, PrimeGroup,
};
use sha2::{Digest, Sha256};

/// Errors that can occur in this library
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Error when a signature is invalid
    InvalidSignature,
    /// Error when a public key is invalid
    InvalidPublicKey,
    /// Error when an elliptic curve point is invalid
    InvalidPoint,
    /// Error when hashing fails
    HashingError,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidSignature => write!(f, "Invalid signature"),
            Error::InvalidPublicKey => write!(f, "Invalid public key"),
            Error::InvalidPoint => write!(f, "Invalid elliptic curve point"),
            Error::HashingError => write!(f, "Hashing operation failed"),
        }
    }
}

impl std::error::Error for Error {}

/// Type alias for Result with our Error type
pub type Result<T> = std::result::Result<T, Error>;

/// Represents a key pair for this Schnorr signature variant containing both the private and public keys.
///
/// The private key is a scalar in the field of BLS12-381, and the public key is a point
/// on the BLS12-381 curve (specifically, private_key * G, where G is the generator).
///
/// Note: This implementation uses BLS12-381, which is not commonly used for Schnorr signatures
/// (most standard implementations use secp256k1 or Edwards25519).
pub struct Keypair {
    /// The private key, a scalar in the BLS12-381 field
    pub private_key: Fp256<MontBackend<FrConfig, 4>>,
    /// The public key, a point on the BLS12-381 curve
    pub public_key: Projective<Config>,
}

/// Represents a signature for this Schnorr variant.
///
/// A signature consists of two components:
/// - R: A curve point derived from a random nonce
/// - z: A scalar computed as (r + c * private_key) % curve_order
///   where c is a challenge derived from hashing the public key, message, and R
///
/// Note: The challenge computation order (public_key || message || R) differs from
/// standardized Schnorr implementations like BIP-340 which uses (R || public_key || message).
pub struct Signature {
    /// The R point (commitment) of the signature, derived from a random nonce
    pub big_r: Projective<Config>,
    /// The scalar z component of the signature, computed from the nonce, challenge, and private key
    pub z: Fp256<MontBackend<FrConfig, 4>>,
}

/// Generates a new Schnorr key pair consisting of a private key and its corresponding public key.
///
/// The private key is generated as a random scalar in the BLS12-381 field.
/// The public key is computed as private_key * G, where G is the generator point of the curve.
///
/// # Returns
///
/// A new `Keypair` containing the generated private and public keys.
///
/// # Security Considerations
///
/// This function uses the system's cryptographically secure random number generator.
/// The security of the resulting key pair depends on the randomness quality.
pub fn generate_key_pair() -> Keypair {
    let generator = G1Projective::generator();
    let mut rng = rand::thread_rng();
    let private_key = Fr::rand(&mut rng);
    let public_key = generator * private_key;
    Keypair {
        private_key,
        public_key,
    }
}

/// Computes the challenge hash used in this Schnorr signature variant.
///
/// This function computes c = Hash(Public key || message || R), where:
/// - Public key is the signer's public key
/// - message is the message being signed
/// - R is the commitment point generated during signing
///
/// # Parameters
///
/// * `message` - The message to be hashed
/// * `public_key` - The signer's public key
/// * `big_r` - The R point (commitment) generated during signing
///
/// # Returns
///
/// A SHA-256 hash of the concatenated inputs, as a byte vector.
///
/// # Note
///
/// The order of elements in the hash is important for security. This implementation
/// uses (Public key || message || R), which differs from standardized Schnorr implementations:
/// - Bitcoin's BIP-340 uses (R || Public key || message)
/// - Ed25519 uses a similar order but with different encoding rules
///
/// This difference means this implementation is a non-standard variant of Schnorr.
pub fn hash(
    message: Vec<u8>,
    public_key: Projective<Config>,
    big_r: Projective<Config>,
) -> Result<Vec<u8>> {
    // c = Hash(Public key + message + R)
    let mut hasher = Sha256::new();
    let mut public_key_bytes = Vec::new();
    public_key
        .serialize_uncompressed(&mut public_key_bytes)
        .map_err(|_| Error::InvalidPublicKey)?;

    hasher.update(public_key_bytes);
    hasher.update(message);
    let mut r = Vec::new();
    big_r
        .serialize_uncompressed(&mut r)
        .map_err(|_| Error::InvalidPoint)?;

    hasher.update(r);

    Ok(hasher.finalize().to_vec())
}

/// Signs a message using this Schnorr signature variant.
///
/// The signing process follows these steps:
/// 1. Generate a random nonce r
/// 2. Compute R = r * G, where G is the generator point
/// 3. Compute the challenge c = Hash(public_key || message || R)
/// 4. Compute z = (r + c * private_key) % curve_order
/// 5. The signature is the pair (R, z)
///
/// # Parameters
///
/// * `keypair` - The signer's keypair containing both the private and public keys
/// * `message` - The message to be signed
///
/// # Returns
///
/// A `Result` containing either a `Signature` with the R point and the scalar z,
/// or an `Error` if the signing process fails.
///
/// # Security Considerations
///
/// This implementation:
/// - Uses fresh randomness for each signature through a secure RNG
/// - Follows the mathematical structure of Schnorr signatures, but with non-standard parameters
/// - Uses a non-standard hash input ordering (public_key || message || R)
/// - Does not implement protection against side-channel attacks
pub fn sign(keypair: &Keypair, message: Vec<u8>) -> Result<Signature> {
    let generator = G1Projective::generator();
    let mut rng = rand::thread_rng();
    // Generate a random nonce for this signature
    let r = Fr::rand(&mut rng);
    // Compute the commitment point R = r * G
    let big_r = generator * r;
    // Compute the challenge c = Hash(public_key || message || R)
    let c = hash(message, keypair.public_key, big_r)?;
    let c = Fr::from_be_bytes_mod_order(c.as_slice());
    // z = (r + c * private_key) % curve_order
    let z = r + c * keypair.private_key;

    Ok(Signature { big_r, z })
}

/// Verifies a signature against a message and public key using this Schnorr variant.
///
/// The verification process follows these steps:
/// 1. Compute the challenge c = Hash(public_key || message || R)
/// 2. Check if R + (c * public_key) = z * G, where:
///    - R is the R point from the signature
///    - c is the computed challenge
///    - public_key is the signer's public key
///    - z is the scalar from the signature
///    - G is the generator point
///
/// # Parameters
///
/// * `public_key` - The signer's public key
/// * `signature` - The signature to verify
/// * `message` - The message that was signed
///
/// # Returns
///
/// `true` if the signature is valid for the given message and public key, `false` otherwise.
/// If an error occurs during verification (such as invalid points), returns `false`.
///
/// # Mathematical Explanation
///
/// In a valid signature:
/// - z * G = (r + c * private_key) * G = r * G + c * private_key * G = R + c * public_key
///
/// Therefore, the equation R + (c * public_key) = z * G must hold for a valid signature.
///
/// # Implementation Note
///
/// While the verification equation is consistent with standard Schnorr signatures,
/// the challenge computation (Hash(public_key || message || R)) differs from standardized
/// variants, making this a non-standard implementation.
pub fn verify(public_key: Projective<Config>, signature: &Signature, message: Vec<u8>) -> bool {
    let generator = G1Projective::generator();
    // Compute the challenge c using the same process as in signing
    let c = match hash(message, public_key, signature.big_r) {
        Ok(hash_result) => hash_result,
        Err(_) => return false, // If hashing fails, verification fails
    };
    
    let c = Fr::from_be_bytes_mod_order(c.as_slice());
    // Verify that R + (c * public_key) = z * G
    signature.big_r + (public_key * c) == generator * signature.z
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that a properly generated signature is correctly verified.
    #[test]
    fn sign_and_verify() {
        let message = "hello".as_bytes();
        let keypair = generate_key_pair();
        let signature = sign(&keypair, message.into()).expect("Signing should succeed");

        assert!(verify(keypair.public_key, &signature, message.into()));
    }

    /// Test that verification fails when a different message is used.
    #[test]
    fn verify_with_wrong_message() {
        let message = "hello".as_bytes();
        let keypair = generate_key_pair();
        let signature = sign(&keypair, message.into()).expect("Signing should succeed");

        let wrong_message = "hello world".as_bytes();
        assert!(!verify(
            keypair.public_key,
            &signature,
            wrong_message.into()
        ));
    }

    /// Test that verification fails when a different public key is used.
    #[test]
    fn verify_with_wrong_public_key() {
        let message = "hello".as_bytes();
        let keypair = generate_key_pair();
        let signature = sign(&keypair, message.into()).expect("Signing should succeed");

        let wrong_keypair = generate_key_pair();
        assert!(!verify(
            wrong_keypair.public_key,
            &signature,
            message.into()
        ));
    }

    /// Test for error handling in the sign function
    #[test]
    fn test_sign_error_handling() {
        // This test doesn't actually test a real error case,
        // but ensures the Result is being returned correctly
        let message = "hello".as_bytes();
        let keypair = generate_key_pair();
        let result = sign(&keypair, message.into());
        assert!(result.is_ok());
    }
}
