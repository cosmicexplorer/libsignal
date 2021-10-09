//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use async_trait::async_trait;
use uuid::Uuid;

use crate::state::{PreKeyId, SignedPreKeyId};
use crate::{
    IdentityKey, IdentityKeyPair, PreKeyRecord, ProtocolAddress, Result, SenderKeyRecord,
    SessionRecord, SignalProtocolError, SignedPreKeyRecord,
};

pub type Context = Option<*mut std::ffi::c_void>;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Direction {
    Sending,
    Receiving,
}

/// A locally-generated random number used to construct the initial value of a message chain.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq)]
pub struct RegistrationId(u16);

impl RegistrationId {
    /// Ensure the registration id `value` fits into 14 bits, panicking if not.
    pub fn unsafe_from_value(value: u32) -> Self {
        if value & 0x3FFF != value {
            panic!("registration id {:X} did not fit into 14 bits", value)
        }
        Self(value as u16)
    }

    /// Ensure the registration id `value` fits into 14 bits.
    pub fn deserialize(value: u32, destination: &ProtocolAddress) -> Result<Self> {
        if value & 0x3FFF != value {
            Err(SignalProtocolError::InvalidRegistrationId(
                destination.clone(),
                value,
            ))
        } else {
            Ok(Self(value as u16))
        }
    }
}

impl From<RegistrationId> for u16 {
    fn from(value: RegistrationId) -> Self {
        value.0
    }
}

impl From<RegistrationId> for u32 {
    fn from(value: RegistrationId) -> Self {
        value.0 as u32
    }
}

#[async_trait(?Send)]
pub trait IdentityKeyStore {
    async fn get_identity_key_pair(&self, ctx: Context) -> Result<IdentityKeyPair>;

    async fn get_local_registration_id(&self, ctx: Context) -> Result<RegistrationId>;

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        ctx: Context,
    ) -> Result<bool>;

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: Direction,
        ctx: Context,
    ) -> Result<bool>;

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
        ctx: Context,
    ) -> Result<Option<IdentityKey>>;
}

#[async_trait(?Send)]
pub trait PreKeyStore {
    async fn get_pre_key(&self, prekey_id: PreKeyId, ctx: Context) -> Result<PreKeyRecord>;

    async fn save_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        record: &PreKeyRecord,
        ctx: Context,
    ) -> Result<()>;

    async fn remove_pre_key(&mut self, prekey_id: PreKeyId, ctx: Context) -> Result<()>;
}

#[async_trait(?Send)]
pub trait SignedPreKeyStore {
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: SignedPreKeyId,
        ctx: Context,
    ) -> Result<SignedPreKeyRecord>;

    async fn save_signed_pre_key(
        &mut self,
        signed_prekey_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
        ctx: Context,
    ) -> Result<()>;
}

#[async_trait(?Send)]
pub trait SessionStore {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
        ctx: Context,
    ) -> Result<Option<SessionRecord>>;

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
        ctx: Context,
    ) -> Result<()>;
}

#[async_trait(?Send)]
pub trait SenderKeyStore {
    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        record: &SenderKeyRecord,
        ctx: Context,
    ) -> Result<()>;

    async fn load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        ctx: Context,
    ) -> Result<Option<SenderKeyRecord>>;
}

pub trait ProtocolStore: SessionStore + PreKeyStore + SignedPreKeyStore + IdentityKeyStore {}

#[test]
fn test_bad_registration_id() {
    let bob_device_id: crate::DeviceId = 42.into();

    let bob_uuid = "796abedb-ca4e-4f18-8803-1fde5b921f9f".to_string();

    let bob_uuid_address = ProtocolAddress::new(bob_uuid.clone(), bob_device_id);

    match RegistrationId::deserialize(0x4000, &bob_uuid_address) {
        Err(SignalProtocolError::InvalidRegistrationId(addr, num)) => {
            assert_eq!(addr, bob_uuid_address);
            assert_eq!(num, 0x4000);
        }
        _ => panic!("failed!"),
    }
}
