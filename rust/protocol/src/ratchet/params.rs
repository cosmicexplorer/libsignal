//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! An organization of the requirements necessary for the "Alice" and "Bob" participants in
//! a particular [Double Ratchet] chain.
//!
//! [Double Ratchet]: https://signal.org/docs/specifications/doubleratchet/#overview-1

use crate::{
    curve::{KeyPair, PublicKey},
    IdentityKey, IdentityKeyPair,
};

/// Operations defined for both Alice and Bob in a particular conversation.
pub trait SignalProtocolParametersBase {
    fn our_identity_key_pair(&self) -> &IdentityKeyPair;
    fn their_identity_key(&self) -> &IdentityKey;
}

/// Operations defined *only* for Alice in a particular conversation.
pub trait AliceSpecificParameters: SignalProtocolParametersBase {
    fn our_base_key_pair(&self) -> &KeyPair;
    fn their_signed_pre_key(&self) -> &PublicKey;
    fn their_one_time_pre_key(&self) -> Option<&PublicKey>;
    fn their_ratchet_key(&self) -> &PublicKey;
}

/// Implementation of [AliceSpecificParameters].
pub struct AliceSignalProtocolParameters {
    our_identity_key_pair: IdentityKeyPair,
    our_base_key_pair: KeyPair,
    their_identity_key: IdentityKey,
    their_signed_pre_key: PublicKey,
    their_one_time_pre_key: Option<PublicKey>,
    their_ratchet_key: PublicKey,
}

impl AliceSignalProtocolParameters {
    /// Create a new instance.
    pub fn new(
        our_identity_key_pair: IdentityKeyPair,
        our_base_key_pair: KeyPair,
        their_identity_key: IdentityKey,
        their_signed_pre_key: PublicKey,
        their_one_time_pre_key: Option<PublicKey>,
        their_ratchet_key: PublicKey,
    ) -> Self {
        Self {
            our_identity_key_pair,
            our_base_key_pair,
            their_identity_key,
            their_signed_pre_key,
            their_one_time_pre_key,
            their_ratchet_key,
        }
    }
}

impl SignalProtocolParametersBase for AliceSignalProtocolParameters {
    #[inline]
    fn our_identity_key_pair(&self) -> &IdentityKeyPair {
        &self.our_identity_key_pair
    }

    #[inline]
    fn their_identity_key(&self) -> &IdentityKey {
        &self.their_identity_key
    }
}

impl AliceSpecificParameters for AliceSignalProtocolParameters {
    #[inline]
    fn our_base_key_pair(&self) -> &KeyPair {
        &self.our_base_key_pair
    }

    #[inline]
    fn their_signed_pre_key(&self) -> &PublicKey {
        &self.their_signed_pre_key
    }

    #[inline]
    fn their_one_time_pre_key(&self) -> Option<&PublicKey> {
        self.their_one_time_pre_key.as_ref()
    }

    #[inline]
    fn their_ratchet_key(&self) -> &PublicKey {
        &self.their_ratchet_key
    }
}

/// Operations defined *only* for Bob in a particular conversation.
pub trait BobSpecificParameters: SignalProtocolParametersBase {
    fn our_signed_pre_key_pair(&self) -> &KeyPair;

    fn our_one_time_pre_key_pair(&self) -> Option<&KeyPair>;

    fn our_ratchet_key_pair(&self) -> &KeyPair;

    fn their_base_key(&self) -> &PublicKey;
}

/// Implementation of [BobSpecificParameters].
pub struct BobSignalProtocolParameters {
    our_identity_key_pair: IdentityKeyPair,
    our_signed_pre_key_pair: KeyPair,
    our_one_time_pre_key_pair: Option<KeyPair>,
    our_ratchet_key_pair: KeyPair,

    their_identity_key: IdentityKey,
    their_base_key: PublicKey,
}

impl BobSignalProtocolParameters {
    /// Create a new instance.
    pub fn new(
        our_identity_key_pair: IdentityKeyPair,
        our_signed_pre_key_pair: KeyPair,
        our_one_time_pre_key_pair: Option<KeyPair>,
        our_ratchet_key_pair: KeyPair,
        their_identity_key: IdentityKey,
        their_base_key: PublicKey,
    ) -> Self {
        Self {
            our_identity_key_pair,
            our_signed_pre_key_pair,
            our_one_time_pre_key_pair,
            our_ratchet_key_pair,
            their_identity_key,
            their_base_key,
        }
    }
}

impl SignalProtocolParametersBase for BobSignalProtocolParameters {
    #[inline]
    fn our_identity_key_pair(&self) -> &IdentityKeyPair {
        &self.our_identity_key_pair
    }

    #[inline]
    fn their_identity_key(&self) -> &IdentityKey {
        &self.their_identity_key
    }
}

impl BobSpecificParameters for BobSignalProtocolParameters {
    #[inline]
    fn our_signed_pre_key_pair(&self) -> &KeyPair {
        &self.our_signed_pre_key_pair
    }

    #[inline]
    fn our_one_time_pre_key_pair(&self) -> Option<&KeyPair> {
        self.our_one_time_pre_key_pair.as_ref()
    }

    #[inline]
    fn our_ratchet_key_pair(&self) -> &KeyPair {
        &self.our_ratchet_key_pair
    }

    #[inline]
    fn their_base_key(&self) -> &PublicKey {
        &self.their_base_key
    }
}
