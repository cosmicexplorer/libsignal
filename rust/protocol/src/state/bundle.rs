//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::{
    address::DeviceId,
    consts::types::SignatureBytes,
    curve::PublicKey,
    state::{PreKeyId, SignedPreKeyId},
    IdentityKey,
};

/// The type in memory to represent the unique identity of a specific [PreKeyBundle].
pub type RegistrationId = u32;

/// Corresponds to the pre-key bundle described in the [X3DH] key agreement protocol.
///
/// [X3DH]: https://signal.org/docs/specifications/x3dh/#sending-the-initial-message
#[derive(Debug, Clone)]
pub struct PreKeyBundle {
    registration_id: RegistrationId,
    device_id: DeviceId,
    pre_key_id: Option<PreKeyId>,
    pre_key_public: Option<PublicKey>,
    signed_pre_key_id: SignedPreKeyId,
    signed_pre_key_public: PublicKey,
    signed_pre_key_signature: SignatureBytes,
    identity_key: IdentityKey,
}

impl PreKeyBundle {
    /// Create a new instance.
    pub fn new(
        registration_id: RegistrationId,
        device_id: DeviceId,
        pre_key: Option<(PreKeyId, PublicKey)>,
        signed_pre_key_id: SignedPreKeyId,
        signed_pre_key_public: PublicKey,
        signed_pre_key_signature: SignatureBytes,
        identity_key: IdentityKey,
    ) -> Self {
        let (pre_key_id, pre_key_public) = match pre_key {
            None => (None, None),
            Some((id, key)) => (Some(id), Some(key)),
        };

        Self {
            registration_id,
            device_id,
            pre_key_id,
            pre_key_public,
            signed_pre_key_id,
            signed_pre_key_public,
            signed_pre_key_signature,
            identity_key,
        }
    }

    pub fn registration_id(&self) -> RegistrationId {
        self.registration_id
    }

    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }

    pub fn pre_key_id(&self) -> Option<PreKeyId> {
        self.pre_key_id
    }

    pub fn pre_key_public(&self) -> Option<PublicKey> {
        self.pre_key_public
    }

    pub fn signed_pre_key_id(&self) -> SignedPreKeyId {
        self.signed_pre_key_id
    }

    #[inline]
    pub fn signed_pre_key_public(&self) -> PublicKey {
        self.signed_pre_key_public
    }

    #[inline]
    pub fn signed_pre_key_signature(&self) -> &SignatureBytes {
        &self.signed_pre_key_signature
    }

    #[inline]
    pub fn identity_key(&self) -> &IdentityKey {
        &self.identity_key
    }
}
