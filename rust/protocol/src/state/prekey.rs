//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::proto::storage::PreKeyRecordStructure;
use crate::utils::unwrap::no_encoding_error;
use crate::{DeviceId, KeyPair, PrivateKey, PublicKey, Result, SignalProtocolError};

use internal::conversions::serialize;

use std::convert::TryFrom;

use prost::Message;

/// A unique identifier selecting among this client's known pre-keys.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct PreKeyId(u32);

impl From<u32> for PreKeyId {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<PreKeyId> for u32 {
    fn from(value: PreKeyId) -> Self {
        value.0
    }
}

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
                id: id.into(),
                public_key,
                private_key,
            },
        }
    }

    pub fn id(&self) -> Result<PreKeyId> {
        Ok(self.pre_key.id.into())
    }

    pub fn key_pair(&self) -> Result<KeyPair> {
        KeyPair::from_public_and_private(&self.pre_key.public_key, &self.pre_key.private_key)
    }

    pub fn public_key(&self) -> Result<PublicKey> {
        PublicKey::try_from(self.pre_key.public_key.as_ref())
    }

    pub fn private_key(&self) -> Result<PrivateKey> {
        PrivateKey::try_from(self.pre_key.private_key.as_ref())
    }
}

#[cfg(feature = "bridge")]
impl PreKeyRecord {
    pub fn serialize(k: &PreKeyRecord) -> Box<[u8]> {
        serialize::<Box<[u8]>, _>(k)
    }
}

impl From<&PreKeyRecord> for Box<[u8]> {
    fn from(pkr: &PreKeyRecord) -> Box<[u8]> {
        let mut buf = vec![];
        no_encoding_error(pkr.pre_key.encode(&mut buf));
        buf.into_boxed_slice()
    }
}

impl TryFrom<&[u8]> for PreKeyRecord {
    type Error = SignalProtocolError;
    fn try_from(data: &[u8]) -> Result<Self> {
        Ok(Self {
            pre_key: PreKeyRecordStructure::decode(data)?,
        })
    }
}
