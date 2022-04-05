//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use async_trait::async_trait;
use uuid::Uuid;

use crate::state::{PreKeyId, SessionStructure, SignedPreKeyId};
use crate::{
    IdentityKey, IdentityKeyPair, PreKeyRecord, ProtocolAddress, Result, SenderKeyRecord,
    SessionRecord, SignedPreKeyRecord,
};

pub type Context = Option<*mut std::ffi::c_void>;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Direction {
    Sending,
    Receiving,
}

#[async_trait(?Send)]
pub trait IdentityKeyStore {
    async fn get_identity_key_pair(&self, ctx: Context) -> Result<IdentityKeyPair>;

    async fn get_local_registration_id(&self, ctx: Context) -> Result<u32>;

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
    type S: SessionStructure;
    async fn load_session(
        &self,
        address: &ProtocolAddress,
        ctx: Context,
    ) -> Result<Option<SessionRecord<Self::S>>>;

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord<Self::S>,
        ctx: Context,
    ) -> Result<()>;

    /// Bulk version of [`Self::load_session`].
    ///
    /// Useful for [crate::sealed_sender_multi_recipient_encrypt].
    ///
    /// [`SessionStore::load_session`]: crate::SessionStore::load_session
    async fn load_existing_sessions(
        &self,
        addresses: &[&ProtocolAddress],
        ctx: Context,
    ) -> Result<Vec<SessionRecord<Self::S>>>;
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
