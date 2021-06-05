//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::curve::curve25519::{PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH};
use crate::proto::storage::PreKeyRecordStructure;
use crate::{KeyPair, KeyType, PrivateKey, PublicKey, Result, SignalProtocolError};
use prost::Message;

use std::convert::TryInto;

pub type PreKeyId = u32;

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

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        Ok(Self {
            pre_key: PreKeyRecordStructure::decode(data)?,
        })
    }

    pub fn id(&self) -> Result<PreKeyId> {
        Ok(self.pre_key.id)
    }

    pub fn key_pair(&self) -> Result<KeyPair> {
        let public: &[u8; 1 + PUBLIC_KEY_LENGTH] = &self
            .pre_key
            .public_key
            .clone()
            .try_into()
            .map_err(|e: Vec<u8>| {
                SignalProtocolError::BadKeyLength(KeyType::Curve25519, e.len())
            })?;
        let private: &[u8; PRIVATE_KEY_LENGTH] = &self
            .pre_key
            .private_key
            .clone()
            .try_into()
            .map_err(|e: Vec<u8>| {
                SignalProtocolError::BadKeyLength(KeyType::Curve25519, e.len())
            })?;
        KeyPair::from_public_and_private(public, private)
    }

    pub fn public_key(&self) -> Result<PublicKey> {
        PublicKey::deserialize_result(&self.pre_key.public_key)
    }

    pub fn private_key(&self) -> Result<PrivateKey> {
        PrivateKey::deserialize_result(&self.pre_key.private_key)
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = vec![];
        self.pre_key.encode(&mut buf)?;
        Ok(buf)
    }
}
