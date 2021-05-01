//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::{
    curve::{KeyPair, PrivateKey, PublicKey},
    proto::storage::PreKeyRecordStructure,
    utils::{
        traits::serde::{Deserializable, Serializable},
        unwrap::no_encoding_error,
    },
    Result,
};

use prost::Message;

/// Type used to record the identity of a specific pre-key in the
/// [crate::storage::traits::PreKeyStore].
pub type PreKeyId = u32;

/// An entry for a [crate::storage::traits::PreKeyStore].
#[derive(Debug, Clone)]
pub struct PreKeyRecord {
    pre_key: PreKeyRecordStructure,
}

impl PreKeyRecord {
    pub fn new(id: PreKeyId, key: &KeyPair) -> Self {
        let public_key = key.public_key.serialize().to_vec();
        let private_key = key.private_key.serialize().to_vec();
        Self {
            pre_key: PreKeyRecordStructure {
                id,
                public_key,
                private_key,
            },
        }
    }

    pub fn id(&self) -> Result<PreKeyId> {
        Ok(self.pre_key.id)
    }

    pub fn key_pair(&self) -> Result<KeyPair> {
        KeyPair::from_public_and_private(&self.pre_key.public_key, &self.pre_key.private_key)
    }

    pub fn public_key(&self) -> Result<PublicKey> {
        PublicKey::deserialize(&self.pre_key.public_key)
    }

    pub fn private_key(&self) -> Result<PrivateKey> {
        PrivateKey::deserialize(&self.pre_key.private_key)
    }
}

impl Deserializable for PreKeyRecord {
    fn deserialize(data: &[u8]) -> Result<Self> {
        Ok(Self {
            pre_key: PreKeyRecordStructure::decode(data)?,
        })
    }
}

impl Serializable<Vec<u8>> for PreKeyRecord {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = vec![];
        no_encoding_error(self.pre_key.encode(&mut buf));
        buf
    }
}
