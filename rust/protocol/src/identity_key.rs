//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// TODO
// #![warn(missing_docs)]

//! Wrappers over identity primitives from [crate::curve].

use crate::proto;
use crate::utils::unwrap::no_encoding_error;
use crate::{KeyPair, PrivateKey, PublicKey, Result, SignalProtocolError};

use rand::{CryptoRng, Rng};
use std::convert::{AsRef, TryFrom};

use prost::Message;

/// Wrapper for [PublicKey].
#[derive(Debug, PartialOrd, Ord, PartialEq, Eq, Clone, Copy)]
pub struct IdentityKey {
    public_key: PublicKey,
}

impl IdentityKey {
    pub fn new(public_key: PublicKey) -> Self {
        Self { public_key }
    }

    #[inline]
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }
}

#[cfg(feature = "bridge")]
impl IdentityKey {
    pub fn serialize(k: &IdentityKey) -> Box<[u8]> {
        serialize::<Box<[u8]>, _>(k)
    }
}

impl From<&IdentityKey> for Box<[u8]> {
    #[inline]
    fn from(key: &IdentityKey) -> Box<[u8]> {
        (&key.public_key).into()
    }
}

impl TryFrom<&[u8]> for IdentityKey {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        let pk = PublicKey::try_from(value)?;
        Ok(Self::from(pk))
    }
}

impl From<PublicKey> for IdentityKey {
    fn from(value: PublicKey) -> Self {
        Self { public_key: value }
    }
}

/// Wrapper for [KeyPair].
#[derive(Copy, Clone)]
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

    /// Generate a cryptographically random new identity from randomness in `csprng`.
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

impl From<&IdentityKeyPair> for Box<[u8]> {
    fn from(kp: &IdentityKeyPair) -> Box<[u8]> {
        let IdentityKeyPair {
            identity_key,
            private_key,
        } = kp;
        let id_bytes: Box<[u8]> = identity_key.into();
        let priv_bytes: Box<[u8]> = private_key.into();
        let structure = proto::storage::IdentityKeyPairStructure {
            public_key: id_bytes.into_vec(),
            private_key: priv_bytes.into_vec(),
        };
        let mut result = Vec::new();

        no_encoding_error(structure.encode(&mut result));
        result.into_boxed_slice()
    }
}

#[cfg(feature = "bridge")]
impl IdentityKeyPair {
    pub fn serialize(k: &IdentityKeyPair) -> Box<[u8]> {
        serialize::<Box<[u8]>, _>(k)
    }
}

impl TryFrom<&[u8]> for IdentityKeyPair {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        let structure = proto::storage::IdentityKeyPairStructure::decode(value)?;
        Ok(Self {
            identity_key: IdentityKey::try_from(&structure.public_key[..])?,
            private_key: PrivateKey::try_from(structure.private_key.as_ref())?,
        })
    }
}

impl TryFrom<PrivateKey> for IdentityKeyPair {
    type Error = SignalProtocolError;
    fn try_from(private_key: PrivateKey) -> Result<Self> {
        let identity_key = IdentityKey::new(private_key.public_key()?);
        Ok(Self::new(identity_key, private_key))
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

    use crate::Keyed;

    use rand::rngs::OsRng;

    #[test]
    fn test_identity_key_from() {
        let key_pair = KeyPair::generate(&mut OsRng);
        let key_pair_public_serialized = serialize::<Box<[u8]>, _>(&key_pair.public_key);
        let identity_key = IdentityKey::from(key_pair.public_key);
        assert_eq!(
            key_pair_public_serialized,
            serialize::<Box<[u8]>, _>(&identity_key)
        );
    }

    #[test]
    fn test_serialize_identity_key_pair() -> Result<()> {
        let identity_key_pair = IdentityKeyPair::generate(&mut OsRng);
        let serialized = serialize::<Box<[u8]>, _>(&identity_key_pair);
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
            serialize::<Box<[u8]>, _>(identity_key_pair.private_key()),
            serialize::<Box<[u8]>, _>(deserialized_identity_key_pair.private_key()),
        );

        Ok(())
    }
}
