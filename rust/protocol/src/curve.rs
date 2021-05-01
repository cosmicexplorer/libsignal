//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Identity creation primitives.

mod curve25519;

pub use curve25519::{AGREEMENT_LENGTH, PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};

use crate::utils::traits::{
    message::SignatureVerifiable,
    serde::{Deserializable, Serializable},
};
use crate::{Result, SignalProtocolError};

use std::cmp::Ordering;
use std::convert::TryFrom;
use std::fmt;

use arrayref::array_ref;
use rand::{CryptoRng, Rng};
use subtle::ConstantTimeEq;

pub trait Keyed {
    fn key_type(&self) -> KeyType;
}

/// TODO: describe the intent of this enum!
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum KeyType {
    /// TODO: What does this case mean?
    Djb,
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl KeyType {
    fn value(&self) -> u8 {
        match &self {
            KeyType::Djb => 0x05u8,
        }
    }
}

impl TryFrom<u8> for KeyType {
    type Error = SignalProtocolError;

    fn try_from(x: u8) -> Result<Self> {
        match x {
            0x05u8 => Ok(KeyType::Djb),
            t => Err(SignalProtocolError::BadKeyType(t)),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum PublicKeyData {
    DjbPublicKey([u8; PUBLIC_KEY_LENGTH]),
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

    /// Return the bytes that make up this public key.
    pub fn public_key_bytes(&self) -> Result<&[u8]> {
        match self.key {
            PublicKeyData::DjbPublicKey(ref v) => Ok(v),
        }
    }

    /// Create an instance by attempting to interpret `bytes` as a [KeyType::Djb] public key.
    pub fn from_djb_public_key_bytes(bytes: &[u8]) -> Result<Self> {
        match <[u8; PUBLIC_KEY_LENGTH]>::try_from(bytes) {
            Err(_) => Err(SignalProtocolError::BadKeyLength(KeyType::Djb, bytes.len())),
            Ok(key) => Ok(PublicKey {
                key: PublicKeyData::DjbPublicKey(key),
            }),
        }
    }

    fn key_data(&self) -> &[u8] {
        match self.key {
            PublicKeyData::DjbPublicKey(ref k) => k.as_ref(),
        }
    }
}

impl Keyed for PublicKey {
    fn key_type(&self) -> KeyType {
        match self.key {
            PublicKeyData::DjbPublicKey(_) => KeyType::Djb,
        }
    }
}

/// All the information necessary to implement [SignatureVerifiable] for [PublicKey].
pub struct PublicKeySignature<'a> {
    pub message: &'a [u8],
    pub signature: &'a [u8; SIGNATURE_LENGTH],
}

impl<'a> SignatureVerifiable<PublicKeySignature<'a>> for PublicKey {
    fn verify_signature(&self, sig: PublicKeySignature<'a>) -> Result<bool> {
        let PublicKeySignature { message, signature } = sig;
        match self.key {
            PublicKeyData::DjbPublicKey(pub_key) => {
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
}

impl Deserializable for PublicKey {
    fn deserialize(value: &[u8]) -> Result<Self> {
        if value.is_empty() {
            return Err(SignalProtocolError::NoKeyTypeIdentifier);
        }
        let key_type = KeyType::try_from(value[0])?;
        match key_type {
            KeyType::Djb => {
                // We allow trailing data after the public key (why?)
                if value.len() < PUBLIC_KEY_LENGTH + 1 {
                    return Err(SignalProtocolError::BadKeyLength(KeyType::Djb, value.len()));
                }
                let mut key = [0u8; PUBLIC_KEY_LENGTH];
                key.copy_from_slice(&value[1..(PUBLIC_KEY_LENGTH + 1)]);
                Ok(PublicKey {
                    key: PublicKeyData::DjbPublicKey(key),
                })
            }
        }
    }
}

impl Serializable<Box<[u8]>> for PublicKey {
    fn serialize(&self) -> Box<[u8]> {
        let value_len = match self.key {
            PublicKeyData::DjbPublicKey(v) => v.len(),
        };
        let mut result = Vec::with_capacity(1 + value_len);
        result.push(self.key_type().value());
        match self.key {
            PublicKeyData::DjbPublicKey(v) => result.extend_from_slice(&v),
        }
        result.into_boxed_slice()
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

        crate::utils::constant_time_cmp(self.key_data(), other.key_data())
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
    DjbPrivateKey([u8; PRIVATE_KEY_LENGTH]),
}

/// Private key half of a [KeyPair].
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PrivateKey {
    key: PrivateKeyData,
}

impl PrivateKey {
    /// Derive a public key from the current private key's contents.
    pub fn public_key(&self) -> PublicKey {
        match self.key {
            PrivateKeyData::DjbPrivateKey(private_key) => {
                let public_key = curve25519::derive_public_key(&private_key);
                PublicKey::new(PublicKeyData::DjbPublicKey(public_key))
            }
        }
    }

    /// Calculate a signature for `message` given this private key.
    pub fn calculate_signature<R: CryptoRng + Rng>(
        &self,
        message: &[u8],
        csprng: &mut R,
    ) -> [u8; SIGNATURE_LENGTH] {
        match self.key {
            PrivateKeyData::DjbPrivateKey(k) => {
                let kp = curve25519::KeyPair::from(k);
                kp.calculate_signature(csprng, message)
            }
        }
    }

    /// Calculate a new key agreed between this private key and the public key `their_key`.
    pub fn calculate_agreement(&self, their_key: &PublicKey) -> [u8; AGREEMENT_LENGTH] {
        match (self.key, their_key.key) {
            (PrivateKeyData::DjbPrivateKey(priv_key), PublicKeyData::DjbPublicKey(pub_key)) => {
                let kp = curve25519::KeyPair::from(priv_key);
                kp.calculate_agreement(&pub_key)
            }
        }
    }
}

impl Keyed for PrivateKey {
    fn key_type(&self) -> KeyType {
        match self.key {
            PrivateKeyData::DjbPrivateKey(_) => KeyType::Djb,
        }
    }
}

impl Deserializable for PrivateKey {
    fn deserialize(value: &[u8]) -> Result<Self> {
        if value.len() != PRIVATE_KEY_LENGTH {
            Err(SignalProtocolError::BadKeyLength(KeyType::Djb, value.len()))
        } else {
            let mut key = [0u8; PRIVATE_KEY_LENGTH];
            key.copy_from_slice(&value[..PRIVATE_KEY_LENGTH]);
            // Clamp:
            key[0] &= 0xF8;
            key[PRIVATE_KEY_LENGTH - 1] &= 0x7F;
            key[PRIVATE_KEY_LENGTH - 1] |= 0x40;
            Ok(Self {
                key: PrivateKeyData::DjbPrivateKey(key),
            })
        }
    }
}

impl Serializable<Vec<u8>> for PrivateKey {
    fn serialize(&self) -> Vec<u8> {
        match self.key {
            PrivateKeyData::DjbPrivateKey(v) => v.to_vec(),
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

        let public_key = PublicKey::from(PublicKeyData::DjbPublicKey(*keypair.public_key()));
        let private_key = PrivateKey::from(PrivateKeyData::DjbPrivateKey(*keypair.private_key()));

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

    /// Instantiate an identity from byte strings for public and private keys.
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
    ) -> [u8; SIGNATURE_LENGTH] {
        self.private_key.calculate_signature(message, csprng)
    }

    /// Calculate a new key agreed between our private key and the public key `their_key`.
    pub fn calculate_agreement(&self, their_key: &PublicKey) -> [u8; AGREEMENT_LENGTH] {
        self.private_key.calculate_agreement(their_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PublicKeySignature;

    use arrayref::array_ref;
    use rand::rngs::OsRng;

    #[test]
    fn test_large_signatures() -> Result<()> {
        let mut csprng = OsRng;
        let key_pair = KeyPair::generate(&mut csprng);
        let mut message = [0u8; 1024 * 1024];
        let signature = key_pair
            .private_key
            .calculate_signature(&message, &mut csprng);

        assert!(key_pair.public_key.verify_signature(PublicKeySignature {
            message: &message,
            signature: array_ref![&signature, 0, 64],
        })?);
        message[0] ^= 0x01u8;
        assert!(!key_pair.public_key.verify_signature(PublicKeySignature {
            message: &message,
            signature: array_ref![&signature, 0, 64],
        })?);
        message[0] ^= 0x01u8;
        let public_key = key_pair.private_key.public_key();
        assert!(public_key.verify_signature(PublicKeySignature {
            message: &message,
            signature: array_ref![&signature, 0, 64],
        })?);

        Ok(())
    }

    #[test]
    fn test_decode_size() -> Result<()> {
        let mut csprng = OsRng;
        let key_pair = KeyPair::generate(&mut csprng);
        let serialized_public = key_pair.public_key.serialize();

        assert_eq!(
            serialized_public,
            key_pair.private_key.public_key().serialize()
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
