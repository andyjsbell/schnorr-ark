# Schnorr-Ark

A Rust implementation of a Schnorr signature variant using [Arkworks](https://arkworks.rs/).

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

This library provides a simple and efficient implementation of a Schnorr signature variant using the BLS12-381 elliptic curve through the Arkworks ecosystem. Schnorr signatures are a type of digital signature known for their simplicity, efficiency, and mathematical elegance.

> **Note:** This implementation follows the general mathematical structure of Schnorr signatures but does not conform to any standardized Schnorr variant (such as Bitcoin's BIP-340 or Ed25519). See the [Implementation Details](#implementation-details) section for more information.

### Features

- Key pair generation
- Message signing
- Signature verification
- Built on the strong cryptographic primitives of Arkworks
- Simple, clean API

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
schnorr-ark = { git = "https://github.com/andyjsbell/schnorr-ark" }
```

## Usage

### Basic Example

```rust
use schnorr_ark::{generate_key_pair, sign, verify};

// Generate a new key pair
let keypair = generate_key_pair();

// Sign a message
let message = "Hello, world!".as_bytes().to_vec();
let signature = sign(&keypair, message.clone()).expect("Signing should succeed");

// Verify the signature
let is_valid = verify(keypair.public_key, &signature, message);
assert!(is_valid);
```

### API Documentation

For detailed API documentation, run:

```
cargo doc --open
```

## Cryptographic Details

### Implementation Details

This implementation uses a variant of the Schnorr signature scheme with the following characteristics:

1. **Curve Choice**:
   - Uses the **BLS12-381 curve** instead of the more commonly used secp256k1 (Bitcoin) or Edwards25519 (Ed25519) curves
   - BLS12-381 is a pairing-friendly curve typically used for BLS signatures, not commonly used for Schnorr signatures

2. **Hash Construction**:
   - Uses `Hash(Public key || message || R)` for the challenge computation
   - This differs from standardized variants like Bitcoin's BIP-340 which uses `Hash(R || Public key || message)`
   - The order of elements in the hash affects security properties

3. **Point Representation**:
   - Uses Arkworks' projective coordinates for elliptic curve points
   - Lacks standardized point compression format specified in protocols like BIP-340

### Schnorr Signature Scheme

The general Schnorr signature scheme operates as follows:

1. **Key Generation**:
   - Select a random scalar `x` as the private key
   - Compute `X = x * G` as the public key, where `G` is the generator point

2. **Signing**:
   - Select a random scalar `r` as the nonce
   - Compute `R = r * G`
   - Compute challenge `c = Hash(X || message || R)` (in this implementation)
   - Compute `z = r + c * x`
   - The signature is the pair `(R, z)`

3. **Verification**:
   - Compute challenge `c = Hash(X || message || R)` (in this implementation) 
   - Check if `R + c * X = z * G`

### Security Properties

- **Non-malleability**: Signatures cannot be transformed into other valid signatures for the same message
- **Linearity**: Enables signature aggregation and threshold schemes
- **Provable security**: Secure under the discrete logarithm assumption

### Comparison with Standard Implementations

| Feature | This Implementation | Bitcoin BIP-340 | Ed25519 |
|---------|---------------------|----------------|---------|
| Curve   | BLS12-381           | secp256k1      | Edwards25519 |
| Hash Challenge | `H(X‖m‖R)`   | `H(R‖X‖m)`     | `H(R‖X‖m)` |
| Point Format | Projective coordinates | 32-byte compressed | 32-byte compressed |
| Standardization | Custom variant | Standardized | Standardized |

## Error Handling

This library uses a custom `Error` enum to handle various error conditions:

```rust
// Example with error handling
use schnorr_ark::{generate_key_pair, sign, verify, Error};

let keypair = generate_key_pair();
let message = "Hello, world!".as_bytes().to_vec();

// Using Result handling
match sign(&keypair, message.clone()) {
    Ok(signature) => {
        let is_valid = verify(keypair.public_key, &signature, message);
        println!("Signature valid: {}", is_valid);
    },
    Err(Error::InvalidPublicKey) => println!("Invalid public key"),
    Err(Error::InvalidPoint) => println!("Invalid point"),
    Err(err) => println!("Signing failed: {:?}", err),
}
```

## Security Considerations

This library is provided as-is without any guarantees. It has not undergone extensive security auditing. Consider the following limitations:

- **Non-standard implementation**: This implementation does not follow established Schnorr standards and hasn't undergone the same level of security analysis
- No protection against side-channel attacks
- No constant-time operations
- No explicit memory zeroing for sensitive values
- Proper error handling but no specific countermeasures against timing attacks in error paths

**Production Use Warning**: If you need a standardized Schnorr implementation for production use, consider:
- Using the `secp256k1` crate for Bitcoin-style Schnorr signatures
- Using the `ed25519-dalek` crate for Ed25519 signatures
- Or modifying this implementation to conform to a specific standard

## Development

### Building

```
cargo build
```

### Testing

```
cargo test
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- The [Arkworks](https://arkworks.rs/) team for their excellent cryptographic primitives
- The Schnorr signature scheme was introduced by Claus-Peter Schnorr

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.