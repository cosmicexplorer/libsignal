//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::proto;
use crate::{IdentityKey, PublicKey, Result, SignalProtocolError};

use std::convert::{AsRef, TryFrom};
use std::fmt::Debug;

use hmac::{Hmac, Mac, NewMac};
use prost::Message;
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// The definition of the data used to represent the message version.
pub type VersionType = u8;

/// Each SignalProtocolMessage implementor has this message version mixed into it when created.
/// Prefer to reference this value over use of the literal version number.
pub const CIPHERTEXT_MESSAGE_CURRENT_VERSION: VersionType = 3;

/// The similar base set of capabilities we expect from this library's
/// in-memory representations of over-the-wire structs.
pub trait SignalProtocolMessage {
    fn message_version(&self) -> VersionType;
    fn serialized(&self) -> &[u8];
}

/// Each message in the Double Ratchet protocol is associated with a particular sequence.
pub trait SequencedMessage {
    /// This is typically an unsigned integer type.
    type Count;
    /// This value is incremented in some way when sending each message.
    fn counter(&self) -> Self::Count;
}

/// Pair used to disambiguate sender and receiver keys.
#[derive(Debug, Copy, Clone)]
pub struct MACPair {
    pub sender: IdentityKey,
    pub receiver: IdentityKey,
}

pub trait MACVerifiable {
    /// Verify whether a MAC key matches the message contents from `self` given the sender and
    /// receiver keys.
    fn verify_mac(&self, mac_pair: MACPair, mac_key: &[u8]) -> Result<bool>;
}

/// A serializable object which can be decrypted by the other participant in a Signal Protocol
/// double ratchet session. This type of message contains encrypted plaintext.
#[derive(Debug, Clone)]
pub struct SignalMessage {
    message_version: u8,
    sender_ratchet_key: PublicKey,
    counter: u32,
    /// TODO: document why this is retained despite being dead?
    #[allow(dead_code)]
    previous_counter: u32,
    ciphertext: Box<[u8]>,
    serialized: Box<[u8]>,
}

impl SignalProtocolMessage for SignalMessage {
    #[inline]
    fn message_version(&self) -> u8 {
        self.message_version
    }

    #[inline]
    fn serialized(&self) -> &[u8] {
        &*self.serialized
    }
}

impl SequencedMessage for SignalMessage {
    type Count = u32;

    #[inline]
    fn counter(&self) -> u32 {
        self.counter
    }
}

impl MACVerifiable for SignalMessage {
    fn verify_mac(&self, mac_pair: MACPair, mac_key: &[u8]) -> Result<bool> {
        let our_mac = &Self::compute_mac(
            mac_pair,
            mac_key,
            &self.serialized[..self.serialized.len() - Self::MAC_LENGTH],
        )?;
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

impl SignalMessage {
    const MAC_LENGTH: usize = 8;
    const MAC_KEY_LENGTH: usize = 32;

    pub fn new(
        message_version: u8,
        mac_key: &[u8],
        sender_ratchet_key: PublicKey,
        counter: u32,
        previous_counter: u32,
        ciphertext: Vec<u8>,
        mac_pair: MACPair,
    ) -> Result<Self> {
        let message = proto::wire::SignalMessage {
            ratchet_key: Some(sender_ratchet_key.serialize().into_vec()),
            counter: Some(counter),
            previous_counter: Some(previous_counter),
            ciphertext: Some(ciphertext.clone()),
        };
        let mut serialized = vec![0u8; message.encoded_len()];
        message.encode(&mut &mut serialized)?;
        let mac = Self::compute_mac(mac_pair, mac_key, &serialized)?;
        serialized.extend_from_slice(&mac);
        Ok(Self {
            message_version,
            sender_ratchet_key,
            counter,
            previous_counter,
            serialized: Box::from(serialized),
            ciphertext: Box::from(ciphertext),
        })
    }

    #[inline]
    pub fn sender_ratchet_key(&self) -> &PublicKey {
        &self.sender_ratchet_key
    }

    #[inline]
    pub fn body(&self) -> &[u8] {
        &*self.ciphertext
    }

    fn compute_mac(
        mac_pair: MACPair,
        mac_key: &[u8],
        message: &[u8],
    ) -> Result<[u8; Self::MAC_LENGTH]> {
        if mac_key.len() != Self::MAC_KEY_LENGTH {
            return Err(SignalProtocolError::InvalidMacKeyLength(mac_key.len()));
        }
        let MACPair {
            sender: sender_identity_key,
            receiver: receiver_identity_key,
        } = mac_pair;
        let mut mac = Hmac::<Sha256>::new_varkey(mac_key).map_err(|_| {
            SignalProtocolError::InvalidArgument(format!(
                "Invalid HMAC key length <{}>",
                mac_key.len()
            ))
        })?;

        mac.update(sender_identity_key.public_key().serialize().as_ref());
        mac.update(receiver_identity_key.public_key().serialize().as_ref());
        mac.update(message);
        let mut result = [0u8; Self::MAC_LENGTH];
        result.copy_from_slice(&mac.finalize().into_bytes()[..Self::MAC_LENGTH]);
        Ok(result)
    }
}

impl AsRef<[u8]> for SignalMessage {
    fn as_ref(&self) -> &[u8] {
        self.serialized()
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
            .to_vec();

        Ok(SignalMessage {
            message_version,
            sender_ratchet_key,
            counter,
            previous_counter,
            ciphertext: Box::from(ciphertext),
            serialized: Box::from(value),
        })
    }
}

#[derive(Debug, Clone)]
pub struct PreKeySignalMessage {
    registration_id: u32,
    pre_key_id: Option<u32>,
    signed_pre_key_id: u32,
    base_key: PublicKey,
    identity_key: IdentityKey,
    message: SignalMessage,
    serialized: Box<[u8]>,
}

impl SignalProtocolMessage for PreKeySignalMessage {
    #[inline]
    fn message_version(&self) -> u8 {
        self.message.message_version()
    }
    #[inline]
    fn serialized(&self) -> &[u8] {
        &*self.serialized
    }
}

impl PreKeySignalMessage {
    pub fn new(
        message_version: u8,
        registration_id: u32,
        pre_key_id: Option<u32>,
        signed_pre_key_id: u32,
        base_key: PublicKey,
        identity_key: IdentityKey,
        message: SignalMessage,
    ) -> Result<Self> {
        // Ensure message version agrees with inner message.
        if message_version != message.message_version() {
            return Err(SignalProtocolError::UnrecognizedCiphertextVersion(
                message.message_version(),
            ));
        }
        let proto_message = proto::wire::PreKeySignalMessage {
            registration_id: Some(registration_id),
            pre_key_id,
            signed_pre_key_id: Some(signed_pre_key_id),
            base_key: Some(base_key.serialize().into_vec()),
            identity_key: Some(identity_key.serialize().into_vec()),
            message: Some(Vec::from(message.as_ref())),
        };
        let mut serialized = vec![0u8; proto_message.encoded_len()];
        proto_message.encode(&mut &mut serialized)?;
        Ok(Self {
            registration_id,
            pre_key_id,
            signed_pre_key_id,
            base_key,
            identity_key,
            message,
            serialized: serialized.into_boxed_slice(),
        })
    }

    #[inline]
    pub fn registration_id(&self) -> u32 {
        self.registration_id
    }

    #[inline]
    pub fn pre_key_id(&self) -> Option<u32> {
        self.pre_key_id
    }

    #[inline]
    pub fn signed_pre_key_id(&self) -> u32 {
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
}

impl AsRef<SignalMessage> for PreKeySignalMessage {
    #[inline]
    fn as_ref(&self) -> &SignalMessage {
        &self.message
    }
}

impl AsRef<[u8]> for PreKeySignalMessage {
    fn as_ref(&self) -> &[u8] {
        self.serialized()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyPair;

    use rand::rngs::OsRng;
    use rand::{CryptoRng, Rng};

    fn create_signal_message<T>(csprng: &mut T) -> Result<SignalMessage>
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
            &mac_key,
            sender_ratchet_key_pair.public_key,
            42,
            41,
            ciphertext.to_vec(),
            MACPair {
                sender: sender_identity_key_pair.public_key.into(),
                receiver: receiver_identity_key_pair.public_key.into(),
            },
        )
    }

    fn assert_signal_message_equals(m1: &SignalMessage, m2: &SignalMessage) {
        assert_eq!(m1.message_version, m2.message_version);
        assert_eq!(m1.sender_ratchet_key, m2.sender_ratchet_key);
        assert_eq!(m1.counter, m2.counter);
        assert_eq!(m1.previous_counter, m2.previous_counter);
        assert_eq!(m1.ciphertext, m2.ciphertext);
        assert_eq!(m1.serialized, m2.serialized);
    }

    #[test]
    fn test_signal_message_serialize_deserialize() -> Result<()> {
        let mut csprng = OsRng;
        let message = create_signal_message(&mut csprng)?;
        assert_eq!(message.message_version(), CIPHERTEXT_MESSAGE_CURRENT_VERSION);
        let deser_message =
            SignalMessage::try_from(message.as_ref()).expect("should deserialize without error");
        assert_signal_message_equals(&message, &deser_message);
        Ok(())
    }

    #[test]
    fn test_sender_key_message_serialize_deserialize() -> Result<()> {
        use crate::sealed_sender::SenderKeyMessage;
        use uuid::Uuid;
        let mut csprng = rand::rngs::OsRng;
        let signature_key_pair = KeyPair::generate(&mut csprng);
        let sender_key_message = SenderKeyMessage::new(
            Uuid::from_u128(0xd1d1d1d1_7000_11eb_b32a_33b8a8a487a6),
            42,
            7,
            [1u8, 2, 3].into(),
            &mut csprng,
            &signature_key_pair.private_key,
        )?;
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
            sender_key_message.serialized(),
            deser_sender_key_message.serialized()
        );
        Ok(())
    }

    #[test]
    fn test_pre_key_signal_message_serialize_deserialize() -> Result<()> {
        let mut csprng = OsRng;
        let identity_key_pair = KeyPair::generate(&mut csprng);
        let base_key_pair = KeyPair::generate(&mut csprng);
        let message = create_signal_message(&mut csprng)?;
        let pre_key_signal_message = PreKeySignalMessage::new(
            3,
            365,
            None,
            97,
            base_key_pair.public_key,
            identity_key_pair.public_key.into(),
            message,
        )?;
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
}
