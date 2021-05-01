//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::proto::storage::SignedPreKeyRecordStructure;
use crate::utils::unwrap::no_encoding_error;
use crate::{DeviceId, KeyPair, PrivateKey, PublicKey, Result, SignalProtocolError};

use internal::conversions::serialize;

use std::convert::TryFrom;

use prost::Message;

/// A unique identifier selecting among this client's known signed pre-keys.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct SignedPreKeyId(u32);

impl From<u32> for SignedPreKeyId {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<SignedPreKeyId> for u32 {
    fn from(value: SignedPreKeyId) -> Self {
        value.0
    }
}

#[derive(Debug, Clone)]
pub struct SignedPreKeyRecord {
    signed_pre_key: SignedPreKeyRecordStructure,
}

impl SignedPreKeyRecord {
    pub fn new(id: SignedPreKeyId, timestamp: u64, key: &KeyPair, signature: &[u8]) -> Self {
        let public_key = key.public_key.serialize().to_vec();
        let private_key = key.private_key.serialize().to_vec();
        let signature = signature.to_vec();
        Self {
            signed_pre_key: SignedPreKeyRecordStructure {
                id: id.into(),
                timestamp,
                public_key,
                private_key,
                signature,
            },
        }
    }

    pub fn id(&self) -> Result<DeviceId> {
        Ok(self.signed_pre_key.id)
    }

    pub fn timestamp(&self) -> Result<u64> {
        Ok(self.signed_pre_key.timestamp)
    }

    pub fn signature(&self) -> Result<Vec<u8>> {
        Ok(self.signed_pre_key.signature.clone())
    }

    pub fn public_key(&self) -> Result<PublicKey> {
        PublicKey::try_from(self.signed_pre_key.public_key.as_ref())
    }

    pub fn private_key(&self) -> Result<PrivateKey> {
        PrivateKey::try_from(self.signed_pre_key.private_key.as_ref())
    }

    pub fn key_pair(&self) -> Result<KeyPair> {
        KeyPair::from_public_and_private(
            &self.signed_pre_key.public_key,
            &self.signed_pre_key.private_key,
        )
    }
}

#[cfg(feature = "bridge")]
impl SignedPreKeyRecord {
    pub fn serialize(k: &SignedPreKeyRecord) -> Box<[u8]> {
        serialize::<Box<[u8]>, _>(k)
    }
}

impl TryFrom<&[u8]> for SignedPreKeyRecord {
    type Error = SignalProtocolError;
    fn try_from(data: &[u8]) -> Result<Self> {
        Ok(Self {
            signed_pre_key: SignedPreKeyRecordStructure::decode(data)?,
        })
    }
}

impl From<&SignedPreKeyRecord> for Box<[u8]> {
    fn from(spkr: &SignedPreKeyRecord) -> Box<[u8]> {
        let mut buf = vec![];
        no_encoding_error(spkr.signed_pre_key.encode(&mut buf));
        buf.into_boxed_slice()
    }
}
