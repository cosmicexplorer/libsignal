//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Wrappers over identity primitives from [crate::curve].

use crate::{
    curve::{KeyPair, PrivateKey, PublicKey},
    proto,
    utils::{
        unwrap::no_encoding_error,
        traits::serde::{Deserializable, Serializable},
    },
    Result, SignalProtocolError,
};

use rand::{CryptoRng, Rng};
use std::convert::TryFrom;

use prost::Message;

/// Wrapper for [PublicKey].
#[derive(Debug, PartialOrd, Ord, PartialEq, Eq, Clone, Copy, Hash)]
pub struct IdentityKey {
    public_key: PublicKey,
}

impl IdentityKey {
    /// Create a new instance.
    pub fn new(public_key: PublicKey) -> Self {
        Self { public_key }
    }

    #[inline]
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

impl Serializable<Box<[u8]>> for IdentityKey {
    #[inline]
    fn serialize(&self) -> Box<[u8]> {
        self.public_key.serialize()
    }
}

impl Deserializable for IdentityKey {
    fn deserialize(value: &[u8]) -> Result<Self> {
        let pk = PublicKey::try_from(value)?;
        Ok(Self { public_key: pk })
    }
}

impl TryFrom<&[u8]> for IdentityKey {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        IdentityKey::deserialize(value)
    }
}

impl From<PublicKey> for IdentityKey {
    fn from(value: PublicKey) -> Self {
        Self { public_key: value }
    }
}

/// Wrapper for [KeyPair].
#[derive(Debug, Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct IdentityKeyPair {
    identity_key: IdentityKey,
    private_key: PrivateKey,
}

impl IdentityKeyPair {
    /// Create a new key pair from a public `identity_key` and a private `private_key`.
    pub fn new(identity_key: IdentityKey, private_key: PrivateKey) -> Self {
        Self {
            identity_key,
            private_key,
        }
    }

    /// Generate an unguessable new identity from randomness in `csprng`.
    pub fn generate<R: CryptoRng + Rng>(csprng: &mut R) -> Self {
        let keypair = KeyPair::generate(csprng);

        Self {
            identity_key: keypair.public_key.into(),
            private_key: keypair.private_key,
        }
    }

    #[inline]
    pub fn identity_key(&self) -> &IdentityKey {
        &self.identity_key
    }

    #[inline]
    pub fn public_key(&self) -> &PublicKey {
        &self.identity_key.public_key()
    }

    #[inline]
    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }
}

impl Serializable<Box<[u8]>> for IdentityKeyPair {
    fn serialize(&self) -> Box<[u8]> {
        let structure = proto::storage::IdentityKeyPairStructure {
            public_key: self.identity_key.serialize().to_vec(),
            private_key: self.private_key.serialize().to_vec(),
        };
        let mut result = Vec::new();

        no_encoding_error(structure.encode(&mut result));
        result.into_boxed_slice()
    }
}

impl Deserializable for IdentityKeyPair {
    fn deserialize(value: &[u8]) -> Result<Self> {
        let structure = proto::storage::IdentityKeyPairStructure::decode(value)?;
        Ok(Self {
            identity_key: IdentityKey::try_from(&structure.public_key[..])?,
            private_key: PrivateKey::deserialize(&structure.private_key)?,
        })
    }
}

impl TryFrom<&[u8]> for IdentityKeyPair {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        Self::deserialize(value)
    }
}

impl From<PrivateKey> for IdentityKeyPair {
    fn from(private_key: PrivateKey) -> Self {
        let identity_key = IdentityKey::new(private_key.public_key());
        Self::new(identity_key, private_key)
    }
}

impl From<KeyPair> for IdentityKeyPair {
    fn from(value: KeyPair) -> Self {
        Self {
            identity_key: value.public_key.into(),
            private_key: value.private_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::Keyed;

    use rand::rngs::OsRng;

    #[test]
    fn test_identity_key_from() {
        let key_pair = KeyPair::generate(&mut OsRng);
        let key_pair_public_serialized = key_pair.public_key.serialize();
        let identity_key = IdentityKey::from(key_pair.public_key);
        assert_eq!(key_pair_public_serialized, identity_key.serialize());
    }

    #[test]
    fn test_serialize_identity_key_pair() -> Result<()> {
        let identity_key_pair = IdentityKeyPair::generate(&mut OsRng);
        let serialized = identity_key_pair.serialize();
        let deserialized_identity_key_pair = IdentityKeyPair::try_from(&serialized[..])?;
        assert_eq!(
            identity_key_pair.identity_key(),
            deserialized_identity_key_pair.identity_key()
        );
        assert_eq!(
            identity_key_pair.private_key().key_type(),
            deserialized_identity_key_pair.private_key().key_type()
        );
        assert_eq!(
            identity_key_pair.private_key().serialize(),
            deserialized_identity_key_pair.private_key().serialize()
        );

        Ok(())
    }
}
