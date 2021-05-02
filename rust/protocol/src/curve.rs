//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// TODO
// #![warn(missing_docs)]

//! Identity creation primitives.

pub mod curve25519;

use curve25519::{PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH};

use crate::{Result, SignalProtocolError};
use internal::constant_time_ops;

use std::cmp::Ordering;
use std::convert::TryFrom;
use std::fmt;

use arrayref::array_ref;
use rand::{CryptoRng, Rng};
use subtle::ConstantTimeEq;

/// Encapsulate the variant of key being used.
///
/// Currently the only type of key Signal supports is "djb"-type [Self::Curve25519] keys, but in
/// theory we could move to another key type that supports both *signatures* and *Diffie-Helman
/// agreements* in the future. This would probably need to be another [elliptic curve], but that's
/// not inherently necessary.
///
/// [elliptic curve]: https://en.wikipedia.org/wiki/Elliptic-curve_cryptography
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum KeyType {
    /// See [Curve25519].
    ///
    /// [Curve25519]: https://en.wikipedia.org/wiki/Curve25519.
    Curve25519,
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl KeyType {
    fn value(&self) -> u8 {
        match &self {
            KeyType::Curve25519 => 0x05u8,
        }
    }
}

impl TryFrom<u8> for KeyType {
    type Error = SignalProtocolError;

    fn try_from(x: u8) -> Result<Self> {
        match x {
            0x05u8 => Ok(KeyType::Curve25519),
            t => Err(SignalProtocolError::BadKeyType(t)),
        }
    }
}

/// Interface for structs carrying data that conforms to [KeyType].
pub trait Keyed {
    fn key_type(&self) -> KeyType;
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum PublicKeyData {
    Curve25519PublicKey([u8; PUBLIC_KEY_LENGTH]),
}

/// Public key half of a [KeyPair].
#[derive(Clone, Copy, Eq)]
pub struct PublicKey {
    key: PublicKeyData,
}

impl PublicKey {
    /// Create a new instance from the data in `key`.
    fn new(key: PublicKeyData) -> Self {
        Self { key }
    }

    pub fn deserialize(value: &[u8]) -> Result<Self> {
        if value.is_empty() {
            return Err(SignalProtocolError::NoKeyTypeIdentifier);
        }
        let key_type = KeyType::try_from(value[0])?;
        match key_type {
            KeyType::Curve25519 => {
                // We allow trailing data after the public key (why?)
                if value.len() < PUBLIC_KEY_LENGTH + 1 {
                    return Err(SignalProtocolError::BadKeyLength(
                        KeyType::Curve25519,
                        value.len(),
                    ));
                }
                let mut key = [0u8; PUBLIC_KEY_LENGTH];
                key.copy_from_slice(&value[1..(PUBLIC_KEY_LENGTH + 1)]);
                Ok(PublicKey {
                    key: PublicKeyData::Curve25519PublicKey(key),
                })
            }
        }
    }

    /// Return the bytes that make up this public key.
    pub fn public_key_bytes(&self) -> Result<&[u8]> {
        match self.key {
            PublicKeyData::Curve25519PublicKey(ref v) => Ok(v),
        }
    }

    /// Create an instance by attempting to interpret `bytes` as a [KeyType::Curve25519] public key.
    pub fn from_djb_public_key_bytes(bytes: &[u8]) -> Result<Self> {
        match <[u8; PUBLIC_KEY_LENGTH]>::try_from(bytes) {
            Err(_) => Err(SignalProtocolError::BadKeyLength(
                KeyType::Curve25519,
                bytes.len(),
            )),
            Ok(key) => Ok(PublicKey {
                key: PublicKeyData::Curve25519PublicKey(key),
            }),
        }
    }

    pub fn serialize(&self) -> Box<[u8]> {
        let value_len = match self.key {
            PublicKeyData::Curve25519PublicKey(v) => v.len(),
        };
        let mut result = Vec::with_capacity(1 + value_len);
        result.push(self.key_type().value());
        match self.key {
            PublicKeyData::Curve25519PublicKey(v) => result.extend_from_slice(&v),
        }
        result.into_boxed_slice()
    }

    pub fn verify_signature(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        match self.key {
            PublicKeyData::Curve25519PublicKey(pub_key) => {
                if signature.len() != 64 {
                    return Ok(false);
                }
                Ok(curve25519::KeyPair::verify_signature(
                    &pub_key,
                    message,
                    array_ref![signature, 0, 64],
                ))
            }
        }
    }

    fn key_data(&self) -> &[u8] {
        match self.key {
            PublicKeyData::Curve25519PublicKey(ref k) => k.as_ref(),
        }
    }
}

impl Keyed for PublicKey {
    fn key_type(&self) -> KeyType {
        match self.key {
            PublicKeyData::Curve25519PublicKey(_) => KeyType::Curve25519,
        }
    }
}

impl From<PublicKeyData> for PublicKey {
    fn from(key: PublicKeyData) -> PublicKey {
        Self { key }
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        Self::deserialize(value)
    }
}

impl subtle::ConstantTimeEq for PublicKey {
    /// A constant-time comparison as long as the two keys have a matching type.
    ///
    /// If the two keys have different types, the comparison short-circuits,
    /// much like comparing two slices of different lengths.
    fn ct_eq(&self, other: &PublicKey) -> subtle::Choice {
        if self.key_type() != other.key_type() {
            return 0.ct_eq(&1);
        }
        self.key_data().ct_eq(other.key_data())
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Ord for PublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.key_type() != other.key_type() {
            return self.key_type().cmp(&other.key_type());
        }

        constant_time_ops::constant_time_cmp(self.key_data(), other.key_data())
    }
}

impl PartialOrd for PublicKey {
    fn partial_cmp(&self, other: &PublicKey) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "PublicKey {{ key_type={}, serialize={:?} }}",
            self.key_type(),
            self.serialize()
        )
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum PrivateKeyData {
    Curve25519PrivateKey([u8; PRIVATE_KEY_LENGTH]),
}

/// Private key half of a [KeyPair].
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PrivateKey {
    key: PrivateKeyData,
}

impl PrivateKey {
    pub fn deserialize(value: &[u8]) -> Result<Self> {
        if value.len() != PRIVATE_KEY_LENGTH {
            Err(SignalProtocolError::BadKeyLength(
                KeyType::Curve25519,
                value.len(),
            ))
        } else {
            let mut key = [0u8; PRIVATE_KEY_LENGTH];
            key.copy_from_slice(&value[..PRIVATE_KEY_LENGTH]);
            // Clamp:
            key[0] &= 0xF8;
            key[PRIVATE_KEY_LENGTH - 1] &= 0x7F;
            key[PRIVATE_KEY_LENGTH - 1] |= 0x40;
            Ok(Self {
                key: PrivateKeyData::Curve25519PrivateKey(key),
            })
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        match self.key {
            PrivateKeyData::Curve25519PrivateKey(v) => v.to_vec(),
        }
    }

    /// Derive a public key from the current private key's contents.
    pub fn public_key(&self) -> Result<PublicKey> {
        match self.key {
            PrivateKeyData::Curve25519PrivateKey(private_key) => {
                let public_key = curve25519::derive_public_key(&private_key);
                Ok(PublicKey::new(PublicKeyData::Curve25519PublicKey(
                    public_key,
                )))
            }
        }
    }

    /// Calculate a signature for `message` given this private key.
    pub fn calculate_signature<R: CryptoRng + Rng>(
        &self,
        message: &[u8],
        csprng: &mut R,
    ) -> Result<Box<[u8]>> {
        match self.key {
            PrivateKeyData::Curve25519PrivateKey(k) => {
                let kp = curve25519::KeyPair::from(k);
                Ok(Box::new(kp.calculate_signature(csprng, message)))
            }
        }
    }

    /// Calculate a shared secret between this private key and the public key `their_key`.
    pub fn calculate_agreement(&self, their_key: &PublicKey) -> Result<Box<[u8]>> {
        match (self.key, their_key.key) {
            (
                PrivateKeyData::Curve25519PrivateKey(priv_key),
                PublicKeyData::Curve25519PublicKey(pub_key),
            ) => {
                let kp = curve25519::KeyPair::from(priv_key);
                Ok(Box::new(kp.calculate_agreement(&pub_key)))
            }
        }
    }
}

impl Keyed for PrivateKey {
    fn key_type(&self) -> KeyType {
        match self.key {
            PrivateKeyData::Curve25519PrivateKey(_) => KeyType::Curve25519,
        }
    }
}

impl From<PrivateKeyData> for PrivateKey {
    fn from(key: PrivateKeyData) -> PrivateKey {
        Self { key }
    }
}

impl TryFrom<&[u8]> for PrivateKey {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        Self::deserialize(value)
    }
}

/// A matching public and private key.
#[derive(Copy, Clone)]
pub struct KeyPair {
    pub public_key: PublicKey,
    pub private_key: PrivateKey,
}

impl KeyPair {
    /// Create a new identity from random state.
    pub fn generate<R: Rng + CryptoRng>(csprng: &mut R) -> Self {
        let keypair = curve25519::KeyPair::new(csprng);

        let public_key = PublicKey::from(PublicKeyData::Curve25519PublicKey(*keypair.public_key()));
        let private_key =
            PrivateKey::from(PrivateKeyData::Curve25519PrivateKey(*keypair.private_key()));

        Self {
            public_key,
            private_key,
        }
    }

    /// Instantiate an identity from a known public/private key pair.
    pub fn new(public_key: PublicKey, private_key: PrivateKey) -> Self {
        Self {
            public_key,
            private_key,
        }
    }

    /// Instantiate an identity from serialized public and private keys.
    pub fn from_public_and_private(public_key: &[u8], private_key: &[u8]) -> Result<Self> {
        let public_key = PublicKey::try_from(public_key)?;
        let private_key = PrivateKey::try_from(private_key)?;
        Ok(Self {
            public_key,
            private_key,
        })
    }

    /// Calculate a signature for `message` given the current identity's private key.
    pub fn calculate_signature<R: CryptoRng + Rng>(
        &self,
        message: &[u8],
        csprng: &mut R,
    ) -> Result<Box<[u8]>> {
        self.private_key.calculate_signature(message, csprng)
    }

    /// Calculate a shared secret between our private key and the public key `their_key`.
    pub fn calculate_agreement(&self, their_key: &PublicKey) -> Result<Box<[u8]>> {
        self.private_key.calculate_agreement(their_key)
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;

    use super::*;

    #[test]
    fn test_large_signatures() -> Result<()> {
        let mut csprng = OsRng;
        let key_pair = KeyPair::generate(&mut csprng);
        let mut message = [0u8; 1024 * 1024];
        let signature = key_pair
            .private_key
            .calculate_signature(&message, &mut csprng)?;

        assert!(key_pair.public_key.verify_signature(&message, &signature)?);
        message[0] ^= 0x01u8;
        assert!(!key_pair.public_key.verify_signature(&message, &signature)?);
        message[0] ^= 0x01u8;
        let public_key = key_pair.private_key.public_key()?;
        assert!(public_key.verify_signature(&message, &signature)?);

        Ok(())
    }

    #[test]
    fn test_decode_size() -> Result<()> {
        let mut csprng = OsRng;
        let key_pair = KeyPair::generate(&mut csprng);
        let serialized_public = key_pair.public_key.serialize();

        assert_eq!(
            serialized_public,
            key_pair.private_key.public_key()?.serialize()
        );
        let empty: [u8; 0] = [];

        let just_right = PublicKey::try_from(&serialized_public[..]);

        assert!(just_right.is_ok());
        assert!(PublicKey::try_from(&serialized_public[1..]).is_err());
        assert!(PublicKey::try_from(&empty[..]).is_err());

        let mut bad_key_type = [0u8; 33];
        bad_key_type[..].copy_from_slice(&serialized_public[..]);
        bad_key_type[0] = 0x01u8;
        assert!(PublicKey::try_from(&bad_key_type[..]).is_err());

        let mut extra_space = [0u8; 34];
        extra_space[..33].copy_from_slice(&serialized_public[..]);
        let extra_space_decode = PublicKey::try_from(&extra_space[..]);
        assert!(extra_space_decode.is_ok());

        assert_eq!(&serialized_public[..], &just_right?.serialize()[..]);
        assert_eq!(&serialized_public[..], &extra_space_decode?.serialize()[..]);
        Ok(())
    }
}
