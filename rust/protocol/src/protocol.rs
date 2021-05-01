//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Structs which are sent over the wire. See [proto::wire].

use crate::{
    consts::{
        types::{Counter, VersionType},
        CIPHERTEXT_MESSAGE_CURRENT_VERSION,
    },
    curve::{PrivateKey, PublicKey, PublicKeySignature, SIGNATURE_LENGTH},
    proto,
    sender_keys::ChainId,
    state::PreKeyId,
    utils::{
        traits::{
            message::{SequencedMessage, SignalProtocolMessage, SignatureVerifiable},
            serde::{Deserializable, RefSerializable, Serializable},
        },
        unwrap::{no_encoding_error, no_hmac_varkey_error},
    },
    IdentityKey, Result, SignalProtocolError,
};

use std::convert::{AsRef, TryFrom};
use std::fmt::Debug;

use arrayref::array_ref;
use hmac::{Hmac, Mac, NewMac};
use prost::Message;
use rand::{CryptoRng, Rng};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use uuid::Uuid;

/// Sub-objects required to create a message in a Double Ratchet chain.
pub mod chain_message {
    use crate::{consts::types::Counter, IdentityKey};
    use arrayref::array_ref;

    /// Pair used to disambiguate sender and receiver keys for MAC validation.
    #[derive(Debug, Copy, Clone)]
    pub struct MACPair {
        pub sender: IdentityKey,
        pub receiver: IdentityKey,
    }

    /// The size in bytes of the MAC key used to validate each [super::SignalMessage].
    pub const MAC_KEY_LENGTH: usize = 32;

    /// All the information necessary to validate a MAC against a particular message contents.
    #[derive(Debug, Copy, Clone)]
    pub struct MACSignature<'a> {
        pub mac_pair: MACPair,
        pub mac_key: &'a [u8; MAC_KEY_LENGTH],
    }

    impl<'a> MACSignature<'a> {
        pub fn new(mac_pair: MACPair, mac_key: &'a [u8]) -> Self {
            Self {
                mac_pair,
                mac_key: array_ref![mac_key, 0, MAC_KEY_LENGTH],
            }
        }
    }

    /// Pair used to disambiguate current and previous [Counter] values in a Double Ratchet
    /// message chain.
    #[derive(Debug, Copy, Clone)]
    pub struct SignalIncrementingCounters {
        pub counter: Counter,
        pub previous_counter: Counter,
    }
}
use chain_message::{MACPair, MACSignature, SignalIncrementingCounters};

/// A serializable object which can be decrypted by the other participant in a Signal Protocol
/// double ratchet session. This type of message contains encrypted plaintext.
#[derive(Debug, Clone)]
pub struct SignalMessage {
    message_version: VersionType,
    sender_ratchet_key: PublicKey,
    counters: SignalIncrementingCounters,
    ciphertext: Box<[u8]>,
    serialized: Box<[u8]>,
}

impl SignalMessage {
    // TODO: Where does this come from?
    const MAC_LENGTH: usize = 8;

    pub fn new(
        message_version: VersionType,
        sender_ratchet_key: PublicKey,
        counters: SignalIncrementingCounters,
        ciphertext: Vec<u8>,
        mac_signature: MACSignature<'_>,
    ) -> Self {
        let SignalIncrementingCounters {
            counter,
            previous_counter,
        } = counters;
        let message = proto::wire::SignalMessage {
            ratchet_key: Some(sender_ratchet_key.serialize().into_vec()),
            counter: Some(counter),
            previous_counter: Some(previous_counter),
            ciphertext: Some(ciphertext.clone()),
        };
        let mut serialized = vec![0u8; 1 + message.encoded_len() + Self::MAC_LENGTH];
        serialized[0] = ((message_version & 0xF) << 4) | CIPHERTEXT_MESSAGE_CURRENT_VERSION;
        no_encoding_error(message.encode(&mut &mut serialized[1..message.encoded_len() + 1]));
        let msg_len_for_mac = serialized.len() - Self::MAC_LENGTH;
        let mac = Self::compute_mac(mac_signature, &serialized[..msg_len_for_mac]);
        serialized[msg_len_for_mac..].copy_from_slice(&mac);
        let serialized = serialized.into_boxed_slice();
        Self {
            message_version,
            sender_ratchet_key,
            counters,
            ciphertext: ciphertext.into(),
            serialized,
        }
    }

    #[inline]
    pub fn sender_ratchet_key(&self) -> &PublicKey {
        &self.sender_ratchet_key
    }

    #[inline]
    pub fn body(&self) -> &[u8] {
        &*self.ciphertext
    }

    fn compute_mac(mac_signature: MACSignature<'_>, message: &[u8]) -> [u8; Self::MAC_LENGTH] {
        let MACSignature { mac_pair, mac_key } = mac_signature;
        let MACPair {
            sender: sender_identity_key,
            receiver: receiver_identity_key,
        } = mac_pair;
        let mut mac = no_hmac_varkey_error(Hmac::<Sha256>::new_varkey(mac_key));

        mac.update(sender_identity_key.public_key().serialize().as_ref());
        mac.update(receiver_identity_key.public_key().serialize().as_ref());
        mac.update(message);
        let mut result = [0u8; Self::MAC_LENGTH];
        result.copy_from_slice(&mac.finalize().into_bytes()[..Self::MAC_LENGTH]);
        result
    }
}

impl<'a> RefSerializable<'a> for SignalMessage {
    #[inline]
    fn serialize(&'a self) -> &'a [u8] {
        &*self.serialized
    }
}

impl<'a> SignalProtocolMessage<'a> for SignalMessage {
    #[inline]
    fn message_version(&self) -> VersionType {
        self.message_version
    }
}

impl SequencedMessage for SignalMessage {
    type Count = crate::consts::types::Counter;

    #[inline]
    fn counter(&self) -> Self::Count {
        self.counters.counter
    }
}

impl<'a> SignatureVerifiable<MACSignature<'a>> for SignalMessage {
    fn verify_signature(&self, signature: MACSignature<'a>) -> Result<bool> {
        let our_mac = &Self::compute_mac(
            signature,
            &self.serialized[..self.serialized.len() - Self::MAC_LENGTH],
        );
        let their_mac = &self.serialized[self.serialized.len() - Self::MAC_LENGTH..];
        let result: bool = our_mac.ct_eq(their_mac).into();
        if !result {
            log::error!(
                "Bad Mac! Their Mac: {} Our Mac: {}",
                hex::encode(their_mac),
                hex::encode(our_mac)
            );
        }
        Ok(result)
    }
}

impl AsRef<[u8]> for SignalMessage {
    fn as_ref(&self) -> &[u8] {
        self.serialize()
    }
}

impl TryFrom<&[u8]> for SignalMessage {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        if value.len() < Self::MAC_LENGTH + 1 {
            return Err(SignalProtocolError::CiphertextMessageTooShort(value.len()));
        }
        let message_version = value[0] >> 4;
        if message_version < CIPHERTEXT_MESSAGE_CURRENT_VERSION {
            return Err(SignalProtocolError::LegacyCiphertextVersion(
                message_version,
            ));
        }
        if message_version > CIPHERTEXT_MESSAGE_CURRENT_VERSION {
            return Err(SignalProtocolError::UnrecognizedCiphertextVersion(
                message_version,
            ));
        }

        let proto_structure =
            proto::wire::SignalMessage::decode(&value[1..value.len() - Self::MAC_LENGTH])?;

        let sender_ratchet_key = proto_structure
            .ratchet_key
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let sender_ratchet_key = PublicKey::deserialize(&sender_ratchet_key)?;
        let counter = proto_structure
            .counter
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let previous_counter = proto_structure.previous_counter.unwrap_or(0);
        let ciphertext = proto_structure
            .ciphertext
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?
            .into_boxed_slice();

        Ok(SignalMessage {
            message_version,
            sender_ratchet_key,
            counters: SignalIncrementingCounters {
                counter,
                previous_counter,
            },
            ciphertext,
            serialized: Box::from(value),
        })
    }
}

/// This is the [`prekey bundle`] of the X3DH specification.
///
/// [`prekey bundle`]: https://signal.org/docs/specifications/x3dh/#sending-the-initial-message
#[derive(Debug, Clone)]
pub struct PreKeySignalMessage {
    message_version: VersionType,
    registration_id: u32,
    pre_key_id: Option<PreKeyId>,
    signed_pre_key_id: PreKeyId,
    base_key: PublicKey,
    identity_key: IdentityKey,
    message: SignalMessage,
    serialized: Box<[u8]>,
}

impl<'a> RefSerializable<'a> for PreKeySignalMessage {
    #[inline]
    fn serialize(&'a self) -> &'a [u8] {
        &*self.serialized
    }
}

impl<'a> SignalProtocolMessage<'a> for PreKeySignalMessage {
    #[inline]
    fn message_version(&self) -> VersionType {
        self.message_version
    }
}

impl PreKeySignalMessage {
    pub fn new(
        message_version: VersionType,
        registration_id: u32,
        pre_key_id: Option<PreKeyId>,
        signed_pre_key_id: PreKeyId,
        base_key: PublicKey,
        identity_key: IdentityKey,
        message: SignalMessage,
    ) -> Self {
        // TODO: check that message.message_version() matches message_version?
        let proto_message = proto::wire::PreKeySignalMessage {
            registration_id: Some(registration_id),
            pre_key_id,
            signed_pre_key_id: Some(signed_pre_key_id),
            base_key: Some(base_key.serialize().into_vec()),
            identity_key: Some(identity_key.serialize().into_vec()),
            message: Some(Vec::from(message.as_ref())),
        };
        let mut serialized = vec![0u8; 1 + proto_message.encoded_len()];
        serialized[0] = ((message_version & 0xF) << 4) | CIPHERTEXT_MESSAGE_CURRENT_VERSION;
        no_encoding_error(proto_message.encode(&mut &mut serialized[1..]));
        Self {
            message_version,
            registration_id,
            pre_key_id,
            signed_pre_key_id,
            base_key,
            identity_key,
            message,
            serialized: serialized.into_boxed_slice(),
        }
    }

    #[inline]
    pub fn registration_id(&self) -> u32 {
        self.registration_id
    }

    #[inline]
    pub fn pre_key_id(&self) -> Option<PreKeyId> {
        self.pre_key_id
    }

    #[inline]
    pub fn signed_pre_key_id(&self) -> PreKeyId {
        self.signed_pre_key_id
    }

    #[inline]
    pub fn base_key(&self) -> &PublicKey {
        &self.base_key
    }

    #[inline]
    pub fn identity_key(&self) -> &IdentityKey {
        &self.identity_key
    }

    #[inline]
    pub fn message(&self) -> &SignalMessage {
        &self.message
    }
}

impl AsRef<[u8]> for PreKeySignalMessage {
    fn as_ref(&self) -> &[u8] {
        self.serialize()
    }
}

impl TryFrom<&[u8]> for PreKeySignalMessage {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        if value.is_empty() {
            return Err(SignalProtocolError::CiphertextMessageTooShort(value.len()));
        }

        let message_version = value[0] >> 4;
        if message_version < CIPHERTEXT_MESSAGE_CURRENT_VERSION {
            return Err(SignalProtocolError::LegacyCiphertextVersion(
                message_version,
            ));
        }
        if message_version > CIPHERTEXT_MESSAGE_CURRENT_VERSION {
            return Err(SignalProtocolError::UnrecognizedCiphertextVersion(
                message_version,
            ));
        }

        let proto_structure = proto::wire::PreKeySignalMessage::decode(&value[1..])?;

        let base_key = proto_structure
            .base_key
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let identity_key = proto_structure
            .identity_key
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let message = proto_structure
            .message
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let signed_pre_key_id = proto_structure
            .signed_pre_key_id
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;

        let base_key = PublicKey::deserialize(base_key.as_ref())?;

        Ok(PreKeySignalMessage {
            message_version,
            registration_id: proto_structure.registration_id.unwrap_or(0),
            pre_key_id: proto_structure.pre_key_id,
            signed_pre_key_id,
            base_key,
            identity_key: IdentityKey::try_from(identity_key.as_ref())?,
            message: SignalMessage::try_from(message.as_ref())?,
            serialized: Box::from(value),
        })
    }
}

/// This is the initial [`post-X3DH message`] of the X3DH specification.
///
/// [`post-X3DH message`]: https://signal.org/docs/specifications/x3dh/#sending-the-initial-message
#[derive(Debug, Clone)]
pub struct SenderKeyMessage {
    message_version: VersionType,
    distribution_id: Uuid,
    chain_id: ChainId,
    iteration: Counter,
    ciphertext: Box<[u8]>,
    serialized: Box<[u8]>,
}

impl<'a> RefSerializable<'a> for SenderKeyMessage {
    #[inline]
    fn serialize(&'a self) -> &'a [u8] {
        &*self.serialized
    }
}

impl<'a> SignalProtocolMessage<'a> for SenderKeyMessage {
    #[inline]
    fn message_version(&self) -> VersionType {
        self.message_version
    }
}

impl SignatureVerifiable<PublicKey> for SenderKeyMessage {
    fn verify_signature(&self, signature_key: PublicKey) -> Result<bool> {
        assert!(self.serialized.len() > SIGNATURE_LENGTH);
        let message_span: usize = self.serialized.len() - SIGNATURE_LENGTH;
        let valid = signature_key.verify_signature(PublicKeySignature {
            message: &self.serialized[..message_span],
            signature: array_ref![&self.serialized, message_span, SIGNATURE_LENGTH],
        })?;
        Ok(valid)
    }
}

impl SenderKeyMessage {
    /// ???/Create a new instance.
    pub fn new<R: CryptoRng + Rng>(
        distribution_id: Uuid,
        chain_id: ChainId,
        iteration: Counter,
        ciphertext: Box<[u8]>,
        csprng: &mut R,
        signature_key: &PrivateKey,
    ) -> Self {
        let proto_message = proto::wire::SenderKeyMessage {
            distribution_uuid: Some(distribution_id.as_bytes().to_vec()),
            chain_id: Some(chain_id),
            iteration: Some(iteration),
            ciphertext: Some(ciphertext.to_vec()),
        };
        let proto_message_len = proto_message.encoded_len();
        let mut serialized = vec![0u8; 1 + proto_message_len + SIGNATURE_LENGTH];
        serialized[0] =
            ((CIPHERTEXT_MESSAGE_CURRENT_VERSION & 0xF) << 4) | CIPHERTEXT_MESSAGE_CURRENT_VERSION;
        no_encoding_error(proto_message.encode(&mut &mut serialized[1..1 + proto_message_len]));
        let signature =
            signature_key.calculate_signature(&serialized[..1 + proto_message_len], csprng);
        serialized[1 + proto_message_len..].copy_from_slice(&signature[..]);
        Self {
            message_version: CIPHERTEXT_MESSAGE_CURRENT_VERSION,
            distribution_id,
            chain_id,
            iteration,
            ciphertext,
            serialized: serialized.into_boxed_slice(),
        }
    }

    #[inline]
    pub fn distribution_id(&self) -> Uuid {
        self.distribution_id
    }

    #[inline]
    pub fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    #[inline]
    pub fn iteration(&self) -> Counter {
        self.iteration
    }

    #[inline]
    pub fn ciphertext(&self) -> &[u8] {
        &*self.ciphertext
    }
}

impl AsRef<[u8]> for SenderKeyMessage {
    fn as_ref(&self) -> &[u8] {
        &*self.serialized
    }
}

impl TryFrom<&[u8]> for SenderKeyMessage {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        if value.len() < 1 + SIGNATURE_LENGTH {
            return Err(SignalProtocolError::CiphertextMessageTooShort(value.len()));
        }
        let message_version = value[0] >> 4;
        if message_version < CIPHERTEXT_MESSAGE_CURRENT_VERSION {
            return Err(SignalProtocolError::LegacyCiphertextVersion(
                message_version,
            ));
        }
        if message_version > CIPHERTEXT_MESSAGE_CURRENT_VERSION {
            return Err(SignalProtocolError::UnrecognizedCiphertextVersion(
                message_version,
            ));
        }
        let proto_structure =
            proto::wire::SenderKeyMessage::decode(&value[1..value.len() - SIGNATURE_LENGTH])?;

        let distribution_id = proto_structure
            .distribution_uuid
            .and_then(|bytes| Uuid::from_slice(bytes.as_slice()).ok())
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let chain_id = proto_structure
            .chain_id
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let iteration = proto_structure
            .iteration
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let ciphertext = proto_structure
            .ciphertext
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?
            .into_boxed_slice();

        Ok(SenderKeyMessage {
            message_version,
            distribution_id,
            chain_id,
            iteration,
            ciphertext,
            serialized: Box::from(value),
        })
    }
}

/// This is the calculation of [`SK`] from the X3DH specification.
///
/// [`SK`]: https://signal.org/docs/specifications/x3dh/#sending-the-initial-message
#[derive(Debug, Clone)]
pub struct SenderKeyDistributionMessage {
    message_version: VersionType,
    distribution_id: Uuid,
    chain_id: ChainId,
    iteration: Counter,
    chain_key: [u8; 32],
    signing_key: PublicKey,
    serialized: Box<[u8]>,
}

impl<'a> RefSerializable<'a> for SenderKeyDistributionMessage {
    #[inline]
    fn serialize(&'a self) -> &'a [u8] {
        &*self.serialized
    }
}

impl<'a> SignalProtocolMessage<'a> for SenderKeyDistributionMessage {
    #[inline]
    fn message_version(&self) -> VersionType {
        self.message_version
    }
}

impl SenderKeyDistributionMessage {
    pub fn new(
        distribution_id: Uuid,
        chain_id: ChainId,
        iteration: Counter,
        chain_key: [u8; 32],
        signing_key: PublicKey,
    ) -> Self {
        let proto_message = proto::wire::SenderKeyDistributionMessage {
            distribution_uuid: Some(distribution_id.as_bytes().to_vec()),
            chain_id: Some(chain_id),
            iteration: Some(iteration),
            chain_key: Some(chain_key.to_vec()),
            signing_key: Some(signing_key.serialize().to_vec()),
        };
        let message_version = CIPHERTEXT_MESSAGE_CURRENT_VERSION;
        let mut serialized = vec![0u8; 1 + proto_message.encoded_len()];
        serialized[0] = ((message_version & 0xF) << 4) | message_version;
        no_encoding_error(proto_message.encode(&mut &mut serialized[1..]));
        Self {
            message_version,
            distribution_id,
            chain_id,
            iteration,
            chain_key,
            signing_key,
            serialized: serialized.into_boxed_slice(),
        }
    }

    #[inline]
    pub fn distribution_id(&self) -> Uuid {
        self.distribution_id
    }

    #[inline]
    pub fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    #[inline]
    pub fn iteration(&self) -> Counter {
        self.iteration
    }

    #[inline]
    pub fn chain_key(&self) -> [u8; 32] {
        self.chain_key
    }

    #[inline]
    pub fn signing_key(&self) -> &PublicKey {
        &self.signing_key
    }
}

impl AsRef<[u8]> for SenderKeyDistributionMessage {
    fn as_ref(&self) -> &[u8] {
        &*self.serialized
    }
}

impl TryFrom<&[u8]> for SenderKeyDistributionMessage {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        // The message contains at least a X25519 key and a chain key
        if value.len() < 1 + 32 + 32 {
            return Err(SignalProtocolError::CiphertextMessageTooShort(value.len()));
        }

        let message_version = value[0] >> 4;

        if message_version < CIPHERTEXT_MESSAGE_CURRENT_VERSION {
            return Err(SignalProtocolError::LegacyCiphertextVersion(
                message_version,
            ));
        }
        if message_version > CIPHERTEXT_MESSAGE_CURRENT_VERSION {
            return Err(SignalProtocolError::UnrecognizedCiphertextVersion(
                message_version,
            ));
        }

        let proto_structure = proto::wire::SenderKeyDistributionMessage::decode(&value[1..])?;

        let distribution_id = proto_structure
            .distribution_uuid
            .and_then(|bytes| Uuid::from_slice(bytes.as_slice()).ok())
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let chain_id = proto_structure
            .chain_id
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let iteration = proto_structure
            .iteration
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let chain_key = proto_structure
            .chain_key
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let signing_key = proto_structure
            .signing_key
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;

        if chain_key.len() != 32 || signing_key.len() != 33 {
            return Err(SignalProtocolError::InvalidProtobufEncoding);
        }

        let signing_key = PublicKey::deserialize(&signing_key)?;

        Ok(SenderKeyDistributionMessage {
            message_version,
            distribution_id,
            chain_id,
            iteration,
            chain_key: *array_ref![&chain_key, 0, 32],
            signing_key,
            serialized: Box::from(value),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::KeyPair;

    use rand::rngs::OsRng;
    use rand::{CryptoRng, Rng};

    fn create_signal_message<T>(csprng: &mut T) -> SignalMessage
    where
        T: Rng + CryptoRng,
    {
        let mut mac_key = [0u8; 32];
        csprng.fill_bytes(&mut mac_key);
        let mac_key = mac_key;

        let mut ciphertext = [0u8; 20];
        csprng.fill_bytes(&mut ciphertext);
        let ciphertext = ciphertext;

        let sender_ratchet_key_pair = KeyPair::generate(csprng);
        let sender_identity_key_pair = KeyPair::generate(csprng);
        let receiver_identity_key_pair = KeyPair::generate(csprng);

        SignalMessage::new(
            CIPHERTEXT_MESSAGE_CURRENT_VERSION,
            sender_ratchet_key_pair.public_key,
            SignalIncrementingCounters {
                counter: 42,
                previous_counter: 41,
            },
            ciphertext.to_vec(),
            MACSignature::new(
                MACPair {
                    sender: sender_identity_key_pair.public_key.into(),
                    receiver: receiver_identity_key_pair.public_key.into(),
                },
                mac_key.as_ref(),
            ),
        )
    }

    fn assert_signal_message_equals(m1: &SignalMessage, m2: &SignalMessage) {
        assert_eq!(m1.message_version, m2.message_version);
        assert_eq!(m1.sender_ratchet_key, m2.sender_ratchet_key);
        assert_eq!(m1.counters.counter, m2.counters.counter);
        assert_eq!(m1.counters.previous_counter, m2.counters.previous_counter);
        assert_eq!(m1.ciphertext, m2.ciphertext);
        assert_eq!(m1.serialized, m2.serialized);
    }

    #[test]
    fn test_signal_message_serialize_deserialize() -> Result<()> {
        let mut csprng = OsRng;
        let message = create_signal_message(&mut csprng);
        assert_eq!(
            message.message_version(),
            CIPHERTEXT_MESSAGE_CURRENT_VERSION
        );
        let deser_message =
            SignalMessage::try_from(message.as_ref()).expect("should deserialize without error");
        assert_signal_message_equals(&message, &deser_message);
        Ok(())
    }

    #[test]
    fn test_pre_key_signal_message_serialize_deserialize() -> Result<()> {
        let mut csprng = OsRng;
        let identity_key_pair = KeyPair::generate(&mut csprng);
        let base_key_pair = KeyPair::generate(&mut csprng);
        let message = create_signal_message(&mut csprng);
        let pre_key_signal_message = PreKeySignalMessage::new(
            3,
            365,
            None,
            97,
            base_key_pair.public_key,
            identity_key_pair.public_key.into(),
            message,
        );
        let deser_pre_key_signal_message =
            PreKeySignalMessage::try_from(pre_key_signal_message.as_ref())
                .expect("should deserialize without error");
        assert_eq!(
            pre_key_signal_message.message_version(),
            deser_pre_key_signal_message.message_version()
        );
        assert_eq!(
            pre_key_signal_message.registration_id,
            deser_pre_key_signal_message.registration_id
        );
        assert_eq!(
            pre_key_signal_message.pre_key_id,
            deser_pre_key_signal_message.pre_key_id
        );
        assert_eq!(
            pre_key_signal_message.signed_pre_key_id,
            deser_pre_key_signal_message.signed_pre_key_id
        );
        assert_eq!(
            pre_key_signal_message.base_key,
            deser_pre_key_signal_message.base_key
        );
        assert_eq!(
            pre_key_signal_message.identity_key.public_key(),
            deser_pre_key_signal_message.identity_key.public_key()
        );
        assert_signal_message_equals(
            &pre_key_signal_message.message,
            &deser_pre_key_signal_message.message,
        );
        assert_eq!(
            pre_key_signal_message.serialized,
            deser_pre_key_signal_message.serialized
        );
        Ok(())
    }

    #[test]
    fn test_sender_key_message_serialize_deserialize() -> Result<()> {
        let mut csprng = rand::rngs::OsRng;
        let signature_key_pair = KeyPair::generate(&mut csprng);
        let sender_key_message = SenderKeyMessage::new(
            Uuid::from_u128(0xd1d1d1d1_7000_11eb_b32a_33b8a8a487a6),
            42,
            7,
            [1u8, 2, 3].into(),
            &mut csprng,
            &signature_key_pair.private_key,
        );
        let deser_sender_key_message = SenderKeyMessage::try_from(sender_key_message.as_ref())
            .expect("should deserialize without error");
        assert_eq!(
            sender_key_message.message_version(),
            deser_sender_key_message.message_version()
        );
        assert_eq!(
            sender_key_message.chain_id(),
            deser_sender_key_message.chain_id()
        );
        assert_eq!(
            sender_key_message.iteration(),
            deser_sender_key_message.iteration()
        );
        assert_eq!(
            sender_key_message.ciphertext(),
            deser_sender_key_message.ciphertext()
        );
        assert_eq!(
            sender_key_message.serialize(),
            deser_sender_key_message.serialize()
        );
        Ok(())
    }
}
