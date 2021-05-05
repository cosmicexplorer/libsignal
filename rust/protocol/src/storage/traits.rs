//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Traits defining several stores used throughout the Signal Protocol.

// TODO
// #![warn(missing_docs)]

use async_trait::async_trait;
use uuid::Uuid;

use crate::{
    address::ProtocolAddress,
    error::Result,
    sender_keys::SenderKeyRecord,
    state::{PreKeyId, PreKeyRecord, SessionRecord, SignedPreKeyId, SignedPreKeyRecord},
    IdentityKey, IdentityKeyPair,
};

/// Handle to FFI-provided context object.
///
/// This object is not manipulated in rust, but is instead passed back to each FFI
/// method invocation.
pub type Context = Option<*mut std::ffi::c_void>;

/// Each Signal message can be considered to have exactly two participants, a sender and receiver.
///
/// [IdentityKeyStore::is_trusted_identity] uses this to ensure the identity provided is configured
/// for the appropriate role.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Direction {
    Sending,
    Receiving,
}

/// A locally-generated random number used to construct the initial value of a message chain.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct SessionSeed(u32);

impl From<u32> for SessionSeed {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<SessionSeed> for u32 {
    fn from(value: SessionSeed) -> Self {
        value.0
    }
}

/// Interface defining the identity store, which may be in-memory, on-disk, etc.
///
/// Signal clients usually use the identity store in a [TOFU] manner, but this is not at
/// all guaranteed.
///
/// [TOFU]: https://en.wikipedia.org/wiki/Trust_on_first_use
#[async_trait(?Send)]
pub trait IdentityKeyStore {
    /// Return the single specific identity the store is assumed to represent, with private key.
    async fn get_identity_key_pair(&self, ctx: Context) -> Result<IdentityKeyPair>;

    /// Return an id specific to this store instance.
    ///
    /// This local registration id is the same per-device identifier used in [ProtocolAddress] and
    /// should not change run over run.
    async fn get_local_registration_id(&self, ctx: Context) -> Result<SessionSeed>;

    /// Record an identity into the store. The identity is then considered "trusted".
    ///
    /// The return value represents whether an existing identity was replaced (`Ok(true)`). If it is
    /// new or hasn't changed, the return value is `Ok(false)`.
    // TODO: create a separate enum for this result instead of using a `bool`!
    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        ctx: Context,
    ) -> Result<bool>;

    /// Return whether an identity is trusted for the role specified by `direction`.
    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: Direction,
        ctx: Context,
    ) -> Result<bool>;

    /// Return the public identity for the given `address`, if known.
    async fn get_identity(
        &self,
        address: &ProtocolAddress,
        ctx: Context,
    ) -> Result<Option<IdentityKey>>;
}

/// Interface for storing pre-keys downloaded from a server.
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

/// Interface for storing signed pre-keys downloaded from a server.
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

/// Interface for a Signal client instance to store a session associated with another particular
/// separate Signal client instance.
///
/// This [SessionRecord] object between a pair of Signal clients is used to drive the state for the
/// forward-secret message chain in the [Double Ratchet] protocol.
///
/// [Double Ratchet]: https://signal.org/docs/specifications/doubleratchet/
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

/// Interface for storing sender keys for other users, allowing multiple keys per user.
#[async_trait(?Send)]
pub trait SenderKeyStore {
    /// Store the sender key `record` corresponding to the user `sender` associated to the given
    /// `distribution_id`.
    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        record: &SenderKeyRecord,
        ctx: Context,
    ) -> Result<()>;

    /// Read a sender key record stored for the user `sender` associated to `distribution_id`.
    async fn load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        ctx: Context,
    ) -> Result<Option<SenderKeyRecord>>;
}

/// Mixes in all the store interfaces defined in this module.
pub trait ProtocolStore: SessionStore + PreKeyStore + SignedPreKeyStore + IdentityKeyStore {}
