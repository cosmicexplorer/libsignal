//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! The various types of messages a Signal Protocol client may receive which
//! would kick off a new Double Ratchet chain.
//!
//! This module has two implementations of what amounts to the [`X3DH`] key agreement protocol:
//! 1. [sealed_sender_v1], which only allows for a single recipient.
//! 2. [sealed_sender_v2], which can send to multiple recipients.
//!
//! [`X3DH`]: https://signal.org/docs/specifications/x3dh/#receiving-the-initial-message

use crate::address::DeviceId;
use crate::consts::byte_lengths::SIGNATURE_LENGTH;
use crate::crypto;
use crate::curve::SignatureVerificationError;
use crate::proto;
use crate::session_cipher;
use crate::session_cipher::message_encrypt;
use crate::utils::unwrap::no_encoding_error;
use crate::{
    message_encrypt, CiphertextMessageType, Context, DeviceId, Direction, IdentityKeyStore,
    KeyPair, PreKeySignalMessage, PreKeyStore, PrivateKey, ProtocolAddress, ProtocolAddress,
    PublicKey, PublicKeySignature, Result, SenderKeyMessage, SessionStore, SessionStore,
    SignalMessage, SignalProtocolError, SignedPreKeyStore, HKDF,
};

use internal::{conversions::serialize, traits::SignatureVerifiable};

use arrayref::array_ref;
use async_trait::async_trait;
use curve25519_dalek::scalar::Scalar;
use prost::Message;
use rand::{CryptoRng, Rng};
use signal_crypto::Aes256GcmSiv;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use std::array::TryFromSliceError;
use std::convert::{TryFrom, TryInto};

/// The `ContentHint` object from [proto::sealed_sender].
pub type ProtoContentHint = proto::sealed_sender::unidentified_sender_message::message::ContentHint;
/// The message type from [proto::sealed_sender].
pub type ProtoMessageType = proto::sealed_sender::unidentified_sender_message::message::Type;

pub enum CiphertextMessage {
    SignalMessage(SignalMessage),
    PreKeySignalMessage(PreKeySignalMessage),
    SenderKeyMessage(SenderKeyMessage),
}

#[cfg(feature = "bridge")]
impl CiphertextMessage {
    pub fn serialized(&self) -> &[u8] {
        self.as_ref()
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, num_enum::TryFromPrimitive)]
#[repr(u8)]
pub enum CiphertextMessageType {
    Whisper = 2,
    PreKey = 3,
    // Further cases should line up with Envelope.Type (proto), even though old cases don't.
    SenderKey = 7,
}

pub trait EncipheredMessage {
    fn message_type(&self) -> CiphertextMessageType;
}

impl EncipheredMessage for CiphertextMessage {
    fn message_type(&self) -> CiphertextMessageType {
        match self {
            CiphertextMessage::SignalMessage(_) => CiphertextMessageType::Whisper,
            CiphertextMessage::PreKeySignalMessage(_) => CiphertextMessageType::PreKey,
            CiphertextMessage::SenderKeyMessage(_) => CiphertextMessageType::SenderKey,
        }
    }
}

impl From<CiphertextMessageType> for ProtoMessageType {
    fn from(value: CiphertextMessageType) -> ProtoMessageType {
        match value {
            CiphertextMessageType::Whisper => ProtoMessageType::Message,
            CiphertextMessageType::PreKey => ProtoMessageType::PrekeyMessage,
            CiphertextMessageType::SenderKey => ProtoMessageType::SenderkeyMessage,
        }
    }
}

impl AsRef<[u8]> for CiphertextMessage {
    fn as_ref(&self) -> &[u8] {
        match self {
            CiphertextMessage::SignalMessage(x) => x.as_ref(),
            CiphertextMessage::PreKeySignalMessage(x) => x.as_ref(),
            CiphertextMessage::SenderKeyMessage(x) => x.as_ref(),
        }
    }
}

/// Certificate information provided by a Signal server instance.
#[derive(Debug, Clone)]
pub struct ServerCertificate {
    serialized: Vec<u8>,
    key_id: u32,
    key: PublicKey,
    certificate: Vec<u8>,
    signature: Vec<u8>,
}

/// Test data for certificate revocation.
///
/// 0xDEADC357 is a server certificate ID which is used to test the
/// revocation logic. As of this writing, no prod server certificates have
/// been revoked. If one ever does, add its key ID here.
///
/// If a production server certificate is ever generated which collides
/// with this test certificate ID, Bad Things will happen.
pub const REVOKED_SERVER_CERTIFICATE_KEY_IDS: &[u32] = &[0xDEADC357];

impl SignatureVerifiable for ServerCertificate {
    type Sig = PublicKey;
    type Error = SignalProtocolError;
    fn verify_signature(&self, trust_root: PublicKey) -> Result<()> {
        if REVOKED_SERVER_CERTIFICATE_KEY_IDS.contains(&self.key_id()?) {
            log::error!(
                "received server certificate with revoked ID {:x}",
                self.key_id()?
            );
            return Err(SignatureVerificationError::RevokedServerCert.into());
        }
        trust_root
            .signature_checker()
            .verify_signature(PublicKeySignature {
                message: &self.certificate,
                signature: array_ref![&self.signature, 0, SIGNATURE_LENGTH],
            })
            .map_err(|e| e.into())
    }
}

impl ServerCertificate {
    /// Create a new instance.
    pub fn new<R: Rng + CryptoRng>(
        key_id: u32,
        key: PublicKey,
        trust_root: &PrivateKey,
        rng: &mut R,
    ) -> Result<Self> {
        let certificate_pb = proto::sealed_sender::server_certificate::Certificate {
            id: Some(key_id),
            key: Some(serialize::<Box<[u8]>, _>(&key).into_vec()),
        };

        let mut certificate = vec![];
        no_encoding_error(certificate_pb.encode(&mut certificate));

        let signature = trust_root.calculate_signature(&certificate, rng).to_vec();

        let mut serialized = vec![];
        let pb = proto::sealed_sender::ServerCertificate {
            certificate: Some(certificate.clone()),
            signature: Some(signature.clone()),
        };
        no_encoding_error(pb.encode(&mut serialized));

        Ok(Self {
            serialized,
            certificate,
            signature,
            key,
            key_id,
        })
    }

    pub(crate) fn to_protobuf(&self) -> proto::sealed_sender::ServerCertificate {
        proto::sealed_sender::ServerCertificate {
            certificate: Some(self.certificate.clone()),
            signature: Some(self.signature.clone()),
        }
    }

    #[inline]
    pub fn key_id(&self) -> Result<u32> {
        Ok(self.key_id)
    }

    #[inline]
    pub fn public_key(&self) -> Result<PublicKey> {
        Ok(self.key)
    }

    #[inline]
    pub fn certificate(&self) -> Result<&[u8]> {
        Ok(&self.certificate)
    }

    #[inline]
    pub fn signature(&self) -> Result<&[u8]> {
        Ok(&self.signature)
    }
}

impl AsRef<[u8]> for ServerCertificate {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.serialized
    }
}

#[cfg(feature = "bridge")]
impl ServerCertificate {
    pub fn serialize(k: &ServerCertificate) -> Box<[u8]> {
        Box::from(k.as_ref())
    }
}

#[derive(Debug, Clone)]
pub struct SenderCertificate {
    signer: ServerCertificate,
    key: PublicKey,
    sender_device_id: DeviceId,
    sender_uuid: String,
    sender_e164: Option<String>,
    expiration: u64,
    serialized: Vec<u8>,
    certificate: Vec<u8>,
    signature: Vec<u8>,
}

impl TryFrom<&[u8]> for ServerCertificate {
    type Error = SignalProtocolError;
    fn try_from(data: &[u8]) -> Result<Self> {
        let pb = proto::sealed_sender::ServerCertificate::decode(data)?;

        if pb.certificate.is_none() || pb.signature.is_none() {
            return Err(SignalProtocolError::InvalidProtobufEncoding);
        }

        let certificate = pb
            .certificate
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let signature = pb
            .signature
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let certificate_data =
            proto::sealed_sender::server_certificate::Certificate::decode(certificate.as_ref())?;
        let key = PublicKey::try_from(
            &certificate_data
                .key
                .ok_or(SignalProtocolError::InvalidProtobufEncoding)?[..],
        )?;
        let key_id = certificate_data
            .id
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;

        Ok(Self {
            serialized: data.to_vec(),
            certificate,
            signature,
            key,
            key_id,
        })
    }
}

/// The [ServerCertificate] along with the signed pre-key [`SPK_B`] from the Signal server.
///
/// [`SPK_B`]: https://signal.org/docs/specifications/x3dh/#publishing-keys
#[derive(Debug, Clone)]
pub struct SenderCertificate {
    signer: ServerCertificate,
    key: PublicKey,
    sender_device_id: DeviceId,
    sender_uuid: String,
    sender_e164: Option<String>,
    expiration: u64,
    serialized: Vec<u8>,
    certificate: Vec<u8>,
    signature: Vec<u8>,
}

/// All the information necessary to validate a server's signature.
#[derive(Debug, Copy, Clone)]
pub struct ServerSignature {
    pub trust_root: PublicKey,
    pub validation_time: u64,
}

impl ServerSignature {
    pub fn new(trust_root: PublicKey, validation_time: u64) -> Self {
        Self {
            trust_root,
            validation_time,
        }
    }
}

impl SignatureVerifiable for SenderCertificate {
    type Sig = ServerSignature;
    type Error = SignalProtocolError;
    fn verify_signature(&self, signature: ServerSignature) -> Result<()> {
        let ServerSignature {
            trust_root,
            validation_time,
        } = signature;
        match self.signer.verify_signature(trust_root) {
            Err(e) => {
                log::error!("received server certificate not signed by trust root");
                return Err(e);
            }
            Ok(()) => (),
        }

        match self
            .signer
            .public_key()?
            .signature_checker()
            .verify_signature(PublicKeySignature {
                message: &self.certificate,
                signature: array_ref![&self.signature, 0, SIGNATURE_LENGTH],
            }) {
            Err(e) => {
                log::error!("received sender certificate not signed by server");
                return Err(e.into());
            }
            Ok(()) => (),
        }

        if validation_time > self.expiration {
            log::error!(
                "received expired sender certificate (expiration: {}, validation_time: {})",
                self.expiration,
                validation_time
            );
            return Err(SignalProtocolError::SignatureValidationFailed);
        }

        Ok(())
    }
}

impl SenderCertificate {
    /// Create a new instance.
    pub fn new<R: Rng + CryptoRng>(
        sender_uuid: String,
        sender_e164: Option<String>,
        key: PublicKey,
        sender_device_id: DeviceId,
        expiration: u64,
        signer: ServerCertificate,
        signer_key: &PrivateKey,
        rng: &mut R,
    ) -> Self {
        let certificate_pb = proto::sealed_sender::sender_certificate::Certificate {
            sender_uuid: Some(sender_uuid.clone()),
            sender_e164: sender_e164.clone(),
            sender_device: Some(sender_device_id.into()),
            expires: Some(expiration),
            identity_key: Some(serialize::<Box<[u8]>, _>(&key).to_vec()),
            signer: Some(signer.to_protobuf()),
        };

        let mut certificate = vec![];
        no_encoding_error(certificate_pb.encode(&mut certificate));

        let signature = signer_key.calculate_signature(&certificate, rng).to_vec();

        let pb = proto::sealed_sender::SenderCertificate {
            certificate: Some(certificate.clone()),
            signature: Some(signature.clone()),
        };
        let mut serialized = vec![];
        no_encoding_error(pb.encode(&mut serialized));

        Self {
            signer,
            key,
            sender_device_id,
            sender_uuid,
            sender_e164,
            expiration,
            serialized,
            certificate,
            signature,
        }
    }

    pub(crate) fn from_protobuf(pb: &proto::sealed_sender::SenderCertificate) -> Result<Self> {
        let mut bits = vec![];
        no_encoding_error(pb.encode(&mut bits));
        Self::try_from(bits.as_ref())
    }

    pub(crate) fn to_protobuf(&self) -> proto::sealed_sender::SenderCertificate {
        proto::sealed_sender::SenderCertificate {
            certificate: Some(self.certificate.clone()),
            signature: Some(self.signature.clone()),
        }
    }

    #[inline]
    pub fn signer(&self) -> Result<&ServerCertificate> {
        Ok(&self.signer)
    }

    #[inline]
    pub fn key(&self) -> Result<PublicKey> {
        Ok(self.key)
    }

    #[inline]
    pub fn sender_device_id(&self) -> Result<DeviceId> {
        Ok(self.sender_device_id)
    }

    #[inline]
    pub fn sender_uuid(&self) -> Result<&str> {
        Ok(&self.sender_uuid)
    }

    #[inline]
    pub fn sender_e164(&self) -> Result<Option<&str>> {
        Ok(self.sender_e164.as_deref())
    }

    #[inline]
    pub fn expiration(&self) -> Result<u64> {
        Ok(self.expiration)
    }

    #[inline]
    pub fn certificate(&self) -> Result<&[u8]> {
        Ok(&self.certificate)
    }

    #[inline]
    pub fn signature(&self) -> Result<&[u8]> {
        Ok(&self.signature)
    }
}

impl AsRef<[u8]> for SenderCertificate {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.serialized
    }
}

#[cfg(feature = "bridge")]
impl SenderCertificate {
    pub fn serialize(k: &SenderCertificate) -> Box<[u8]> {
        Box::from(k.as_ref())
    }
}

impl From<ProtoMessageType> for CiphertextMessageType {
    fn from(message_type: ProtoMessageType) -> Self {
        let result = match message_type {
            ProtoMessageType::Message => Self::Whisper,
            ProtoMessageType::PrekeyMessage => Self::PreKey,
            ProtoMessageType::SenderkeyMessage => Self::SenderKey,
        };
        // Keep raw values in sync from now on, for efficient codegen.
        assert!(result == Self::PreKey || message_type as i32 == result as i32);
        result
    }
}

impl TryFrom<&[u8]> for SenderCertificate {
    type Error = SignalProtocolError;
    fn try_from(data: &[u8]) -> Result<Self> {
        let pb = proto::sealed_sender::SenderCertificate::decode(data)?;
        let certificate = pb
            .certificate
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let signature = pb
            .signature
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let certificate_data =
            proto::sealed_sender::sender_certificate::Certificate::decode(certificate.as_ref())?;

        let sender_device_id = certificate_data
            .sender_device
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let expiration = certificate_data
            .expires
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let signer_pb = certificate_data
            .signer
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let sender_uuid = certificate_data
            .sender_uuid
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let sender_e164 = certificate_data.sender_e164;

        let key = PublicKey::try_from(
            &certificate_data
                .identity_key
                .ok_or(SignalProtocolError::InvalidProtobufEncoding)?[..],
        )?;

        let mut signer_bits = vec![];
        no_encoding_error(signer_pb.encode(&mut signer_bits));
        let signer = ServerCertificate::try_from(signer_bits.as_ref())?;

        Ok(Self {
            signer,
            key,
            sender_device_id,
            sender_uuid,
            sender_e164,
            expiration,
            serialized: data.to_vec(),
            certificate,
            signature,
        })
    }
}

/// The "state" of an [UnidentifiedSenderMessageContent] instance, which may allow its contents to
/// be ignored.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ContentHint {
    Default,
    Supplementary,
    Retry,
    Unknown(u32),
}

impl ContentHint {
    fn to_proto(self) -> Option<i32> {
        if self == ContentHint::Default {
            None
        } else {
            Some(u32::from(self) as i32)
        }
    }

    pub const fn to_u32(self) -> u32 {
        match self {
            ContentHint::Default => 0,
            ContentHint::Supplementary => ProtoContentHint::Supplementary as u32,
            ContentHint::Retry => ProtoContentHint::Retry as u32,
            ContentHint::Unknown(value) => value,
        }
    }
}

impl From<u32> for ContentHint {
    fn from(raw_value: u32) -> Self {
        assert!(!ProtoContentHint::is_valid(0));
        match ProtoContentHint::from_i32(raw_value as i32) {
            None if raw_value == 0 => ContentHint::Default,
            None => ContentHint::Unknown(raw_value),
            Some(ProtoContentHint::Supplementary) => ContentHint::Supplementary,
            Some(ProtoContentHint::Retry) => ContentHint::Retry,
        }
    }
}

impl From<ContentHint> for u32 {
    fn from(hint: ContentHint) -> Self {
        hint.to_u32()
    }
}

/// A serialized message of a given [CiphertextMessageType] containing a [SenderCertificate].
pub struct UnidentifiedSenderMessageContent {
    serialized: Vec<u8>,
    contents: Vec<u8>,
    sender: SenderCertificate,
    msg_type: CiphertextMessageType,
    content_hint: ContentHint,
    group_id: Option<Vec<u8>>,
}

impl UnidentifiedSenderMessageContent {
    /// Create a new instance.
    pub fn new(
        msg_type: CiphertextMessageType,
        sender: SenderCertificate,
        contents: Vec<u8>,
        content_hint: ContentHint,
        group_id: Option<Vec<u8>>,
    ) -> Self {
        let proto_msg_type = ProtoMessageType::from(msg_type);
        let msg = proto::sealed_sender::unidentified_sender_message::Message {
            content: Some(contents.clone()),
            r#type: Some(proto_msg_type.into()),
            sender_certificate: Some(sender.to_protobuf()),
            content_hint: content_hint.to_proto(),
            group_id: group_id.as_ref().and_then(|buf| {
                if buf.is_empty() {
                    None
                } else {
                    Some(buf.clone())
                }
            }),
        };

        let mut serialized = vec![];
        no_encoding_error(msg.encode(&mut serialized));

        Self {
            serialized,
            msg_type,
            sender,
            contents,
            content_hint,
            group_id,
        }
    }

    #[inline]
    pub fn sender(&self) -> Result<&SenderCertificate> {
        Ok(&self.sender)
    }

    #[inline]
    pub fn contents(&self) -> Result<&[u8]> {
        Ok(&self.contents)
    }

    #[inline]
    pub fn content_hint(&self) -> Result<ContentHint> {
        Ok(self.content_hint)
    }

    #[inline]
    pub fn group_id(&self) -> Result<Option<&[u8]>> {
        Ok(self.group_id.as_deref())
    }
}

#[cfg(feature = "bridge")]
impl UnidentifiedSenderMessageContent {
    pub fn serialize(k: &UnidentifiedSenderMessageContent) -> Box<[u8]> {
        Box::from(k.as_ref())
    }
}

impl EncipheredMessage for UnidentifiedSenderMessageContent {
    #[inline]
    fn message_type(&self) -> CiphertextMessageType {
        self.msg_type
    }
}

impl AsRef<[u8]> for UnidentifiedSenderMessageContent {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.serialized
    }
}

impl TryFrom<&[u8]> for UnidentifiedSenderMessageContent {
    type Error = SignalProtocolError;
    fn try_from(data: &[u8]) -> Result<Self> {
        let pb = proto::sealed_sender::unidentified_sender_message::Message::decode(data)?;

        let msg_type = pb
            .r#type
            .and_then(ProtoMessageType::from_i32)
            .map(CiphertextMessageType::from)
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let sender = pb
            .sender_certificate
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let contents = pb
            .content
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        let content_hint = pb
            .content_hint
            .map(|raw| ContentHint::from(raw as u32))
            .unwrap_or(ContentHint::Default);
        let group_id = pb.group_id;

        let sender = SenderCertificate::from_protobuf(&sender)?;

        let serialized = data.to_vec();

        log::info!(
            "deserialized UnidentifiedSenderMessageContent from {}.{} with type {:?}",
            sender.sender_uuid()?,
            sender.sender_device_id()?,
            msg_type,
        );

        Ok(Self {
            serialized,
            contents,
            sender,
            msg_type,
            content_hint,
            group_id,
        })
    }
}

/// All the types of [MessageCodec] messages that we can read.
pub enum UnidentifiedSenderMessage {
    /// See the [sealed_sender_v1] module documentation.
    V1(UnidentifiedSenderMessageV1),
    /// See the [sealed_sender_v2] module documentation.
    V2(UnidentifiedSenderMessageV2),
}

impl TryFrom<&[u8]> for UnidentifiedSenderMessage {
    type Error = SignalProtocolError;
    fn try_from(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(SignalProtocolError::InvalidSealedSenderMessage(
                "Message was empty".to_owned(),
            ));
        }
        let version = data[0] >> 4;
        log::info!(
            "deserializing UnidentifiedSenderMessage with version {}",
            version
        );

        match version {
            0 | sealed_sender_v1::SEALED_SENDER_V1_VERSION => {
                // XXX should we really be accepted version == 0 here?
                let pb = proto::sealed_sender::UnidentifiedSenderMessage::decode(&data[1..])?;

                let ephemeral_public = pb
                    .ephemeral_public
                    .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
                let encrypted_static = pb
                    .encrypted_static
                    .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
                let encrypted_message = pb
                    .encrypted_message
                    .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;

                let ephemeral_public = PublicKey::try_from(&ephemeral_public[..])?;

                Ok(Self::V1(UnidentifiedSenderMessageV1 {
                    ephemeral_public,
                    encrypted_static,
                    encrypted_message,
                }))
            }
            sealed_sender_v2::SEALED_SENDER_V2_VERSION => {
                // Uses a flat representation: C || AT || E.pub || ciphertext
                let remaining = &data[1..];
                if remaining.len() < 32 + 16 + 32 {
                    return Err(SignalProtocolError::InvalidProtobufEncoding);
                }
                let (encrypted_message_key, remaining) = remaining.split_at(32);
                let (encrypted_authentication_tag, remaining) = remaining.split_at(16);
                let (ephemeral_public, encrypted_message) = remaining.split_at(32);

                Ok(Self::V2(UnidentifiedSenderMessageV2 {
                    ephemeral_public: PublicKey::from_djb_public_key_bytes(ephemeral_public)?,
                    encrypted_message_key: encrypted_message_key.into(),
                    authentication_tag: encrypted_authentication_tag.into(),
                    encrypted_message: encrypted_message.into(),
                }))
            }
            _ => Err(SignalProtocolError::UnknownSealedSenderVersion(version)),
        }
    }
}

/// Defines a codec for encrypting and decrypting "sealed-sender" messages, which are used to kick
/// off a post-X3DH Double Ratchet.
#[async_trait(?Send)]
pub trait MessageCodec<'a> {
    /// Where to send the message to. See [ProtocolAddress].
    type Destination;
    type MessageContent;
    /// What type of message we need to decrypt. See [UnidentifiedSenderMessageV1] and
    /// [UnidentifiedSenderMessageV2].
    type SenderMessage;
    type DecryptMessage;
    /// Encipher the contents of `usmc` in order to send to `destination`.
    async fn encrypt<R: Rng + CryptoRng>(
        destination: &'a Self::Destination,
        usmc: &'a Self::MessageContent,
        identity_store: &'a mut dyn IdentityKeyStore,
        ctx: Context,
        rng: &'a mut R,
    ) -> Result<Vec<u8>>;
    /// Decrypt the contents of `sender_message`.
    async fn decrypt(
        identity_store: &'a mut dyn IdentityKeyStore,
        ctx: Context,
        sender_message: Self::SenderMessage,
    ) -> Result<Self::DecryptMessage>;
}

/// Described at <https://signal.org/blog/sealed-sender/>.
///
/// 1. `e_pub, e_priv                  = X25519.generateEphemeral();`
/// 1. `e_chain, e_cipherKey, e_macKey = HKDF(salt="UnidentifiedDelivery" || recipientIdentityPublic || e_pub, ikm=ECDH(recipientIdentityPublic, e_priv), info="");`
/// 1. `e_ciphertext                   = AES_CTR(key=e_cipherKey, input=senderIdentityPublic);`
/// 1. `e_mac                          = Hmac256(key=e_macKey, input=e_ciphertext);`
///
/// 1. `s_cipherKey, s_macKey = HKDF(salt=e_chain || e_ciphertext || e_mac, ikm=ECDH(recipientIdentityPublic, senderIdentityPrivate), info="");`
/// 1. `s_ciphertext          = AES_CTR(key=s_cipherKey, input=sender_certificate || message_ciphertext);`
/// 1. `s_mac                 = Hmac256(key=s_macKey, input=s_ciphertext);`
///
/// 1. `message_to_send = s_ciphertext || s_mac;`
pub mod sealed_sender_v1 {
    use super::*;

    /// Wrapper over a KDF derived from ephemeral keys created for X3DH.
    pub struct EphemeralKeys {
        derived_values: [u8; 96],
    }

    impl EphemeralKeys {
        pub fn calculate(
            their_public: &PublicKey,
            our_public: &PublicKey,
            our_private: &PrivateKey,
            // TODO: convert this into an enum!
            sending: bool,
        ) -> Result<Self> {
            /* TODO: where does `2 * 32 + 20` come from? */
            let mut ephemeral_salt = Vec::with_capacity(2 * 32 + 20);
            ephemeral_salt.extend_from_slice("UnidentifiedDelivery".as_bytes());

            if sending {
                let their_pub_bytes: Box<[u8]> = their_public.into();
                ephemeral_salt.extend_from_slice(their_pub_bytes.as_ref());
            }
            let our_pub_bytes: Box<[u8]> = our_public.into();
            ephemeral_salt.extend_from_slice(our_pub_bytes.as_ref());
            if !sending {
                let their_pub_bytes: Box<[u8]> = their_public.into();
                ephemeral_salt.extend_from_slice(their_pub_bytes.as_ref());
            }

            let shared_secret = our_private.calculate_agreement(their_public);
            let derived_values = HKDF::new()?.derive_salted_secrets(
                shared_secret.as_ref(),
                &ephemeral_salt,
                &[],
                96,
            )?;

            Ok(Self {
                derived_values: *array_ref![&derived_values, 0, 96],
            })
        }

        pub fn chain_key(&self) -> &[u8] {
            array_ref![&self.derived_values, 0, 32]
        }

        pub fn cipher_key(&self) -> &[u8] {
            array_ref![&self.derived_values, 32, 32]
        }

        pub fn mac_key(&self) -> &[u8] {
            array_ref![&self.derived_values, 64, 32]
        }
    }

    /// Wrapper over a KDF derived from a signed pre-key and not an ephemeral key (???)
    pub struct StaticKeys {
        derived_values: [u8; 64],
    }
    impl StaticKeys {
        pub fn calculate(
            their_public: &PublicKey,
            our_private: &PrivateKey,
            chain_key: &[u8; 32],
            ctext: &[u8],
        ) -> Result<Self> {
            let mut salt = Vec::with_capacity(chain_key.len() + ctext.len());
            salt.extend_from_slice(chain_key);
            salt.extend_from_slice(ctext);

            let shared_secret = our_private.calculate_agreement(their_public);
            let kdf = HKDF::new()?;
            let derived_values = {
                // NB: 96 bytes are derived but the first 32 are discarded/unused.
                // TODO: this is presumably in order to agree with the results of
                // [EphemeralKeys] above.
                let ret = kdf.derive_salted_secrets(shared_secret.as_ref(), &salt, &[], 96)?;
                *array_ref![&ret, 32, 64]
            };

            Ok(Self { derived_values })
        }

        pub fn cipher_key(&self) -> &[u8; 32] {
            array_ref![&self.derived_values, 0, 32]
        }

        pub fn mac_key(&self) -> &[u8; 32] {
            array_ref![&self.derived_values, 32, 32]
        }
    }

    pub const SEALED_SENDER_V1_VERSION: crate::consts::types::VersionType = 1;

    pub struct UnidentifiedSenderMessageV1 {
        pub ephemeral_public: PublicKey,
        pub encrypted_static: Vec<u8>,
        pub encrypted_message: Vec<u8>,
    }

    /// Implements [MessageCodec] for [sealed_sender_v1].
    pub struct SealedSenderV1;

    #[async_trait(?Send)]
    impl<'a> MessageCodec<'a> for SealedSenderV1 {
        type Destination = ProtocolAddress;
        type MessageContent = UnidentifiedSenderMessageContent;
        type SenderMessage = UnidentifiedSenderMessageV1;
        type DecryptMessage = UnidentifiedSenderMessageContent;
        async fn encrypt<R: Rng + CryptoRng>(
            destination: &'a ProtocolAddress,
            usmc: &'a UnidentifiedSenderMessageContent,
            identity_store: &'a mut dyn IdentityKeyStore,
            ctx: Context,
            rng: &'a mut R,
        ) -> Result<Vec<u8>> {
            sealed_sender_encrypt_from_usmc::<R>(destination, usmc, identity_store, ctx, rng).await
        }
        async fn decrypt(
            identity_store: &'a mut dyn IdentityKeyStore,
            ctx: Context,
            sender_message: UnidentifiedSenderMessageV1,
        ) -> Result<UnidentifiedSenderMessageContent> {
            let UnidentifiedSenderMessageV1 {
                ephemeral_public,
                encrypted_static,
                encrypted_message,
            } = sender_message;
            let our_identity = identity_store.get_identity_key_pair(ctx).await?;
            let eph_keys = sealed_sender_v1::EphemeralKeys::calculate(
                &ephemeral_public,
                &our_identity.public_key(),
                &our_identity.private_key(),
                false,
            )?;

            let message_key_bytes = crypto::aes256_ctr_hmacsha256_decrypt(
                &encrypted_static,
                array_ref![&eph_keys.cipher_key(), 0, 32],
                &*eph_keys.mac_key(),
            )?;

            let static_key = PublicKey::try_from(&message_key_bytes[..])?;

            let static_keys = sealed_sender_v1::StaticKeys::calculate(
                &static_key,
                our_identity.private_key(),
                array_ref![&eph_keys.chain_key(), 0, 32],
                &encrypted_static,
            )?;

            let message_bytes = crypto::aes256_ctr_hmacsha256_decrypt(
                &encrypted_message,
                array_ref![&static_keys.cipher_key(), 0, 32],
                &*static_keys.mac_key(),
            )?;

            let usmc = UnidentifiedSenderMessageContent::try_from(message_bytes.as_ref())?;

            if !bool::from(
                message_key_bytes.ct_eq(serialize::<Box<[u8]>, _>(&usmc.sender()?.key()?).as_ref()),
            ) {
                return Err(SignalProtocolError::InvalidSealedSenderMessage(
                    "sender certificate key does not match message key".to_string(),
                ));
            }

            Ok(usmc)
        }
    }

    /// Implements `.encrypt()` for [SealedSenderV1].
    pub async fn sealed_sender_encrypt_from_usmc<'a, R: Rng + CryptoRng>(
        destination: &ProtocolAddress,
        usmc: &'a UnidentifiedSenderMessageContent,
        identity_store: &mut dyn IdentityKeyStore,
        ctx: Context,
        rng: &mut R,
    ) -> Result<Vec<u8>> {
        let our_identity = identity_store.get_identity_key_pair(ctx).await?;
        let their_identity = identity_store
            .get_identity(destination, ctx)
            .await?
            .ok_or_else(|| SignalProtocolError::SessionNotFound(format!("{}", destination)))?;

        let ephemeral = KeyPair::generate(rng);

        let eph_keys = sealed_sender_v1::EphemeralKeys::calculate(
            their_identity.public_key(),
            &ephemeral.public_key,
            &ephemeral.private_key,
            true,
        )?;

        let bytes: Box<[u8]> = our_identity.public_key().into();
        let static_key_ctext = crypto::aes256_ctr_hmacsha256_encrypt(
            &bytes,
            array_ref![&eph_keys.cipher_key(), 0, 32],
            &*eph_keys.mac_key(),
        );

        let static_keys = sealed_sender_v1::StaticKeys::calculate(
            their_identity.public_key(),
            our_identity.private_key(),
            array_ref![&eph_keys.chain_key(), 0, 32],
            &static_key_ctext,
        )?;

        let message_data = crypto::aes256_ctr_hmacsha256_encrypt(
            usmc.as_ref(),
            array_ref![&static_keys.cipher_key(), 0, 32],
            &*static_keys.mac_key(),
        );

        let version = SEALED_SENDER_V1_VERSION;
        let mut serialized = vec![];
        serialized.push(version | (version << 4));
        let pb = proto::sealed_sender::UnidentifiedSenderMessage {
            ephemeral_public: Some(serialize::<Box<[u8]>, _>(&ephemeral.public_key).into_vec()),
            encrypted_static: Some(static_key_ctext),
            encrypted_message: Some(message_data),
        };
        no_encoding_error(pb.encode(&mut serialized));

        Ok(serialized)
    }
}
pub use sealed_sender_v1::{
    sealed_sender_encrypt_from_usmc, SealedSenderV1, UnidentifiedSenderMessageV1,
};

/// This is a single-key multi-recipient KEM, defined in [Manuel Barbosa's "Randomness Reuse:
/// Extensions and Improvements"](https://haslab.uminho.pt/mbb/files/reuse.pdf). It uses the
/// "Generic Construction" in 4.1 of that paper, instantiated with ElGamal encryption.
///
/// ### `ENCRYPT(message, R_i)`:
/// 1. `M = Random(32);`
/// 2. `r = KDF(label_r, M, len=64);`
/// 3. `K = KDF(label_K, M, len=32);`
/// 4. `E = DeriveKeyPair(r);`
/// 5. `for i in num_recipients:`
///     - `C_i = KDF(label_DH, DH(E, R_i) || E.public || R_i.public, len=32) XOR M;`
///     - `AT_i = KDF(label_DH_s, DH(S, R_i) || E.public || C_i || S.public || R_i.public, len=16);`
/// 6. `ciphertext = AEAD_Encrypt(K, message);`
/// 7. `return E.public, C_i, AT_i, ciphertext;`
///
/// ### `DECRYPT(E.public, C, AT, ciphertext)`:
/// 1. `M = KDF(label_DH, DH(E, R) || E.public || R.public, len=32) xor C;`
/// 2. `r = KDF(label_r, M, len=64);`
/// 3. `K = KDF(label_K, M, len=32);`
/// 4. `E_prime = DeriveKeyPair(r);`
/// 5. `if E.public != E_prime.public:`
///     - `return DecryptionError;`
/// 6. `message = AEAD_Decrypt(K, ciphertext); // includes S.public`
/// 7. `AT_prime = KDF(label_DH_s, DH(S, R) || E.public || C || S.public || R.public, len=16);`
/// 8. `if AT != AT_prime:`
///     - `return DecryptionError;`
/// 9. `return message;`
pub mod sealed_sender_v2 {
    use super::*;

    const LABEL_R: &[u8] = b"Sealed Sender v2: r";
    const LABEL_K: &[u8] = b"Sealed Sender v2: K";
    const LABEL_DH: &[u8] = b"Sealed Sender v2: DH";
    const LABEL_DH_S: &[u8] = b"Sealed Sender v2: DH-sender";

    pub struct DerivedKeys {
        pub e: PrivateKey,
        pub k: Box<[u8]>,
    }

    impl DerivedKeys {
        pub(super) fn calculate(m: &[u8]) -> DerivedKeys {
            let kdf = HKDF::new().expect("valid KDF version");
            let r = kdf
                .derive_secrets(&m, LABEL_R, 64)
                .expect("valid use of KDF");
            let k = kdf
                .derive_secrets(&m, LABEL_K, 32)
                .expect("valid use of KDF");
            let e_raw =
                Scalar::from_bytes_mod_order_wide(r.as_ref().try_into().expect("64-byte slice"));
            let e = PrivateKey::try_from(&e_raw.as_bytes()[..]).expect("valid PrivateKey");
            DerivedKeys { e, k }
        }
    }

    pub fn apply_agreement_xor(
        priv_key: &PrivateKey,
        pub_key: &PublicKey,
        direction: Direction,
        input: &[u8],
    ) -> Result<Box<[u8]>> {
        assert!(input.len() == 32);

        let agreement = priv_key
            .calculate_agreement(&pub_key)
            .to_vec()
            .into_boxed_slice();
        let agreement_key_input = match direction {
            Direction::Sending => [
                agreement,
                serialize::<Box<[u8]>, _>(&priv_key.public_key()?),
                serialize::<Box<[u8]>, _>(pub_key),
            ],
            Direction::Receiving => [
                agreement,
                serialize::<Box<[u8]>, _>(pub_key),
                serialize::<Box<[u8]>, _>(&priv_key.public_key()?),
            ],
        }
        .concat();

        let mut result = HKDF::new()?.derive_secrets(&agreement_key_input, LABEL_DH, 32)?;
        result
            .iter_mut()
            .zip(input)
            .for_each(|(result_byte, input_byte)| *result_byte ^= input_byte);
        Ok(result)
    }

    pub fn compute_authentication_tag(
        priv_key: &PrivateKey,
        pub_key: &PublicKey,
        direction: Direction,
        ephemeral_pub_key: &PublicKey,
        encrypted_message_key: &[u8],
    ) -> Result<Box<[u8]>> {
        let agreement = priv_key.calculate_agreement(&pub_key);
        let mut agreement_key_input = agreement.to_vec();
        agreement_key_input
            .extend_from_slice(serialize::<Box<[u8]>, _>(ephemeral_pub_key).as_ref());
        agreement_key_input.extend_from_slice(encrypted_message_key);
        match direction {
            Direction::Sending => {
                agreement_key_input
                    .extend_from_slice(serialize::<Box<[u8]>, _>(&priv_key.public_key()?).as_ref());
                agreement_key_input.extend_from_slice(serialize::<Box<[u8]>, _>(pub_key).as_ref());
            }
            Direction::Receiving => {
                agreement_key_input.extend_from_slice(serialize::<Box<[u8]>, _>(pub_key).as_ref());
                agreement_key_input
                    .extend_from_slice(serialize::<Box<[u8]>, _>(&priv_key.public_key()?).as_ref());
            }
        }

        HKDF::new()?.derive_secrets(&agreement_key_input, LABEL_DH_S, 16)
    }

    pub const SEALED_SENDER_V2_VERSION: crate::consts::types::VersionType = 2;

    pub struct UnidentifiedSenderMessageV2 {
        pub ephemeral_public: PublicKey,
        pub encrypted_message_key: Box<[u8]>,
        pub authentication_tag: Box<[u8]>,
        pub encrypted_message: Box<[u8]>,
    }

    /// Implements [MessageCodec] for [sealed_sender_v2].
    pub struct SealedSenderV2;

    #[async_trait(?Send)]
    impl<'a> MessageCodec<'a> for SealedSenderV2 {
        type Destination = Vec<ProtocolAddress>;
        type MessageContent = UnidentifiedSenderMessageContent;
        type DecryptMessage = UnidentifiedSenderMessageContent;
        type SenderMessage = UnidentifiedSenderMessageV2;
        async fn encrypt<R: Rng + CryptoRng>(
            destination: &'a Vec<ProtocolAddress>,
            usmc: &'a UnidentifiedSenderMessageContent,
            identity_store: &'a mut dyn IdentityKeyStore,
            ctx: Context,
            rng: &'a mut R,
        ) -> Result<Vec<u8>> {
            let intermediate_slice: Vec<&ProtocolAddress> = destination.iter().collect();
            let destination: &[&ProtocolAddress] = intermediate_slice.as_ref();
            sealed_sender_multi_recipient_encrypt::<R>(destination, usmc, identity_store, ctx, rng)
                .await
        }
        async fn decrypt(
            identity_store: &'a mut dyn IdentityKeyStore,
            ctx: Context,
            sender_message: UnidentifiedSenderMessageV2,
        ) -> Result<UnidentifiedSenderMessageContent> {
            let UnidentifiedSenderMessageV2 {
                ephemeral_public,
                encrypted_message_key,
                authentication_tag,
                encrypted_message,
            } = sender_message;
            let our_identity = identity_store.get_identity_key_pair(ctx).await?;
            let m = sealed_sender_v2::apply_agreement_xor(
                our_identity.private_key(),
                &ephemeral_public,
                Direction::Receiving,
                &encrypted_message_key,
            )?;

            let keys = sealed_sender_v2::DerivedKeys::calculate(&m);
            if !bool::from(keys.e.public_key()?.ct_eq(&ephemeral_public)) {
                return Err(SignalProtocolError::InvalidSealedSenderMessage(
                    "derived ephemeral key did not match key provided in message".to_string(),
                ));
            }

            let mut message_bytes = encrypted_message.into_vec();
            let result = Aes256GcmSiv::new(&keys.k).and_then(|aes_gcm_siv| {
                aes_gcm_siv.decrypt_with_appended_tag(
                    &mut message_bytes,
                    // There's no nonce because the key is already one-use.
                    &[0; Aes256GcmSiv::NONCE_SIZE],
                    // And there's no associated data.
                    &[],
                )
            });
            if let Err(err) = result {
                return Err(SignalProtocolError::InvalidSealedSenderMessage(format!(
                    "failed to decrypt inner message: {}",
                    err
                )));
            }

            let usmc = UnidentifiedSenderMessageContent::try_from(message_bytes.as_ref())?;

            let at = sealed_sender_v2::compute_authentication_tag(
                our_identity.private_key(),
                &usmc.sender()?.key()?,
                Direction::Receiving,
                &ephemeral_public,
                &encrypted_message_key,
            )?;
            if !bool::from(authentication_tag.ct_eq(&at)) {
                return Err(SignalProtocolError::InvalidSealedSenderMessage(
                    "sender certificate key does not match authentication tag".to_string(),
                ));
            }

            Ok(usmc)
        }
    }

    pub async fn sealed_sender_multi_recipient_encrypt<R: Rng + CryptoRng>(
        destinations: &[&ProtocolAddress],
        usmc: &UnidentifiedSenderMessageContent,
        identity_store: &mut dyn IdentityKeyStore,
        ctx: Context,
        rng: &mut R,
    ) -> Result<Vec<u8>> {
        let m: [u8; 32] = rng.gen();
        let keys = sealed_sender_v2::DerivedKeys::calculate(&m);
        let e_pub = keys.e.public_key()?;

        let mut ciphertext = usmc.as_ref().to_vec();
        let tag = Aes256GcmSiv::new(&keys.k)
            .and_then(|aes_gcm_siv| {
                aes_gcm_siv.encrypt(
                    &mut ciphertext,
                    // There's no nonce because the key is already one-use.
                    &[0; Aes256GcmSiv::NONCE_SIZE],
                    // And there's no associated data.
                    &[],
                )
            })
            .map_err(|err| {
                log::error!("failed to encrypt using AES-GCM-SIV: {}", err);
                SignalProtocolError::InternalError("failed to encrypt using AES-GCM-SIV")
            })?;

        // Uses a flat representation: count || UUID_i || deviceId_i || C_i || AT_i || ... || E.pub || ciphertext
        let version = SEALED_SENDER_V2_VERSION;
        let mut serialized: Vec<u8> = vec![(version | (version << 4))];

        prost::encode_length_delimiter(destinations.len(), &mut serialized)
            .expect("cannot fail encoding to Vec");

        let our_identity = identity_store.get_identity_key_pair(ctx).await?;
        for destination in destinations {
            let their_uuid = Uuid::parse_str(destination.name()).map_err(|_| {
                SignalProtocolError::InvalidArgument(format!(
                    "multi-recipient sealed sender requires UUID recipients (not {})",
                    destination.name()
                ))
            })?;

            let their_identity = identity_store
                .get_identity(destination, ctx)
                .await?
                .ok_or_else(|| SignalProtocolError::SessionNotFound(format!("{}", destination)))?;

            let c_i = sealed_sender_v2::apply_agreement_xor(
                &keys.e,
                their_identity.public_key(),
                Direction::Sending,
                &m,
            )?;

            let at_i = sealed_sender_v2::compute_authentication_tag(
                our_identity.private_key(),
                their_identity.public_key(),
                Direction::Sending,
                &e_pub,
                &c_i,
            )?;

            serialized.extend_from_slice(their_uuid.as_bytes());
            prost::encode_length_delimiter(destination.device_id() as usize, &mut serialized)
                .expect("cannot fail encoding to Vec");
            serialized.extend_from_slice(&c_i);
            serialized.extend_from_slice(&at_i);
        }

        serialized.extend_from_slice(&*e_pub.public_key_bytes());
        serialized.extend_from_slice(&ciphertext);
        serialized.extend_from_slice(&tag);

        Ok(serialized)
    }
}
pub use sealed_sender_v2::{
    sealed_sender_multi_recipient_encrypt, SealedSenderV2, UnidentifiedSenderMessageV2,
};

/// TODO: For testing purposes only (?).
pub fn sealed_sender_multi_recipient_fan_out(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let version = data[0] >> 4;
    if version != sealed_sender_v2::SEALED_SENDER_V2_VERSION {
        return Err(SignalProtocolError::UnknownSealedSenderVersion(version));
    }

    fn advance<'a>(buf: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
        if n > buf.len() {
            return Err(SignalProtocolError::InvalidProtobufEncoding);
        }
        let (prefix, remaining) = buf.split_at(n);
        *buf = remaining;
        Ok(prefix)
    }
    fn decode_varint(buf: &mut &[u8]) -> Result<u32> {
        let result: usize = prost::decode_length_delimiter(*buf)?;
        let _ = advance(buf, prost::length_delimiter_len(result))
            .expect("just decoded that many bytes");
        result
            .try_into()
            .map_err(|_| SignalProtocolError::InvalidProtobufEncoding)
    }

    let mut remaining = &data[1..];
    let recipient_count = decode_varint(&mut remaining)?;

    let mut messages: Vec<Vec<u8>> = Vec::new();
    for _ in 0..recipient_count {
        // Skip UUID.
        let _ = advance(&mut remaining, 16)?;
        // Skip device ID.
        let _ = decode_varint(&mut remaining)?;
        // Read C_i and AT_i.
        let c_and_at = advance(&mut remaining, 32 + 16)?;

        let mut next_message = vec![data[0]];
        next_message.extend_from_slice(c_and_at);
        messages.push(next_message);
    }

    // Remaining data is shared among all messages.
    for message in messages.iter_mut() {
        message.extend_from_slice(remaining)
    }

    Ok(messages)
}

/// Deserialize `ciphertext` into an [UnidentifiedSenderMessage] instance, then call
/// [MessageCodec::decrypt].
pub async fn sealed_sender_decrypt_to_usmc(
    ciphertext: &[u8],
    identity_store: &mut dyn IdentityKeyStore,
    ctx: Context,
) -> Result<UnidentifiedSenderMessageContent> {
    match UnidentifiedSenderMessage::try_from(ciphertext)? {
        UnidentifiedSenderMessage::V1(sender_message) => {
            SealedSenderV1::decrypt(identity_store, ctx, sender_message).await
        }
        UnidentifiedSenderMessage::V2(sender_message) => {
            SealedSenderV2::decrypt(identity_store, ctx, sender_message).await
        }
    }
}

/// The decrypted initial message of a Double Ratchet chain, after performing a successful X3DH
/// key agreement.
#[derive(Debug)]
pub struct SealedSenderDecryptionResult {
    pub sender_uuid: String,
    pub sender_e164: Option<String>,
    pub device_id: DeviceId,
    pub message: Vec<u8>,
}

impl SealedSenderDecryptionResult {
    pub fn sender_uuid(&self) -> Result<&str> {
        Ok(self.sender_uuid.as_ref())
    }

    pub fn sender_e164(&self) -> Result<Option<&str>> {
        Ok(self.sender_e164.as_deref())
    }

    pub fn device_id(&self) -> Result<DeviceId> {
        Ok(self.device_id)
    }

    pub fn message(&self) -> Result<&[u8]> {
        Ok(self.message.as_ref())
    }
}

pub async fn sealed_sender_encrypt<R: Rng + CryptoRng>(
    destination: &ProtocolAddress,
    sender_cert: &SenderCertificate,
    ptext: &[u8],
    session_store: &mut dyn SessionStore,
    identity_store: &mut dyn IdentityKeyStore,
    ctx: Context,
    rng: &mut R,
) -> Result<Vec<u8>> {
    let message = message_encrypt(ptext, destination, session_store, identity_store, ctx).await?;
    let ty = message.message_type();
    let msg = message.as_ref().to_vec();
    let usmc = UnidentifiedSenderMessageContent::new(
        ty,
        sender_cert.clone(),
        msg,
        ContentHint::Default,
        None,
    );
    sealed_sender_encrypt_from_usmc(destination, &usmc, identity_store, ctx, rng).await
}

/// Call [sealed_sender_decrypt_to_usmc], then validate the server's signature.
#[allow(clippy::too_many_arguments)]
pub async fn sealed_sender_decrypt<'a>(
    ciphertext: &'a [u8],
    trust_root: &'a PublicKey,
    timestamp: u64,
    local_e164: Option<String>,
    local_uuid: String,
    local_device_id: DeviceId,
    identity_store: &'a mut dyn IdentityKeyStore,
    session_store: &'a mut dyn SessionStore,
    pre_key_store: &'a mut dyn PreKeyStore,
    signed_pre_key_store: &'a mut dyn SignedPreKeyStore,
    ctx: Context,
) -> Result<SealedSenderDecryptionResult> {
    let usmc = sealed_sender_decrypt_to_usmc(ciphertext, identity_store, ctx).await?;

    usmc.sender()?
        .verify_signature(ServerSignature {
            trust_root: *trust_root,
            validation_time: timestamp,
        })
        .map_err(|e| {
            SignalProtocolError::InvalidSealedSenderMessage(format!(
                "trust root validation failed: {:?}",
                e
            ))
        })?;

    let is_local_uuid = local_uuid == usmc.sender()?.sender_uuid()?;

    let is_local_e164 = match (local_e164, usmc.sender()?.sender_e164()?) {
        (Some(l), Some(s)) => l == s,
        (_, _) => false,
    };

    if (is_local_e164 || is_local_uuid) && usmc.sender()?.sender_device_id()? == local_device_id {
        return Err(SignalProtocolError::SealedSenderSelfSend);
    }

    let mut rng = rand::rngs::OsRng;

    let remote_address = ProtocolAddress::new(
        usmc.sender()?.sender_uuid()?.to_string(),
        usmc.sender()?.sender_device_id()?,
    );

    let message = match usmc.message_type() {
        CiphertextMessageType::Whisper => {
            let ctext = SignalMessage::try_from(usmc.contents()?)?;
            session_cipher::message_decrypt_signal(
                &ctext,
                &remote_address,
                session_store,
                identity_store,
                &mut rng,
                ctx,
            )
            .await?
        }
        CiphertextMessageType::PreKey => {
            let ctext = PreKeySignalMessage::try_from(usmc.contents()?)?;
            session_cipher::message_decrypt_prekey(
                &ctext,
                &remote_address,
                session_store,
                identity_store,
                pre_key_store,
                signed_pre_key_store,
                &mut rng,
                ctx,
            )
            .await?
        }
        msg_type => {
            return Err(SignalProtocolError::InvalidSealedSenderMessage(format!(
                "Unexpected message type {}",
                msg_type as i32,
            )))
        }
    };

    Ok(SealedSenderDecryptionResult {
        sender_uuid: usmc.sender()?.sender_uuid()?.to_string(),
        sender_e164: usmc.sender()?.sender_e164()?.map(|s| s.to_string()),
        device_id: usmc.sender()?.sender_device_id()?,
        message,
    })
}

#[test]
fn test_lossless_round_trip() -> Result<()> {
    let trust_root = PrivateKey::try_from([0u8; 32].as_ref())?;

    // To test a hypothetical addition of a new field:
    //
    // Step 1: tempororarily add a new field to the .proto.
    //
    //    --- a/rust/protocol/src/proto/sealed_sender.proto
    //    +++ b/rust/protocol/src/proto/sealed_sender.proto
    //    @@ -26,3 +26,4 @@ message SenderCertificate {
    //             optional bytes             identityKey   = 4;
    //             optional ServerCertificate signer        = 5;
    //    +        optional string someFakeField = 999;
    //     }
    //
    // Step 2: Add `some_fake_field: None` to the above construction of
    // proto::sealed_sender::sender_certificate::Certificate.
    //
    // Step 3: Serialize and print out the new fixture data (uncomment the following)
    //
    // let mut rng = rand::rngs::OsRng;
    // let server_key = KeyPair::generate(&mut rng);
    // let sender_key = KeyPair::generate(&mut rng);
    //
    // let server_cert =
    //     ServerCertificate::new(1, server_key.public_key, &trust_root, &mut rng)?;
    //
    // let sender_cert = proto::sealed_sender::sender_certificate::Certificate {
    //     sender_uuid: Some("aaaaaaaa-7000-11eb-b32a-33b8a8a487a6".to_string()),
    //     sender_e164: None,
    //     sender_device: Some(1),
    //     expires: Some(31337),
    //     identity_key: Some(sender_key.public_key.serialize().to_vec()),
    //     signer: Some(server_cert.to_protobuf()?),
    //     some_fake_field: Some("crashing right down".to_string()),
    // };
    //
    // eprintln!("<SNIP>");
    // let mut serialized_certificate_data = vec![];
    // sender_cert.encode(&mut serialized_certificate_data).expect("can't fail encoding to Vec");
    // let certificate_data_encoded = hex::encode(&serialized_certificate_data);
    // eprintln!("let certificate_data_encoded = \"{}\";", certificate_data_encoded);
    //
    // let certificate_signature = server_key.calculate_signature(&serialized_certificate_data, &mut rng);
    // let certificate_signature_encoded = hex::encode(certificate_signature);
    // eprintln!("let certificate_signature_encoded = \"{}\";", certificate_signature_encoded);

    // Step 4: update the following *_encoded fixture data with the new values from above.
    let certificate_data_encoded = "100119697a0000000000002221056c9d1f8deb82b9a898f9c277a1b74989ec009afb5c0acb5e8e69e3d5ca29d6322a690a2508011221053b03ca070e6f6b2f271d32f27321689cdf4e59b106c10b58fbe15063ed868a5a124024bc92954e52ad1a105b5bda85c9db410dcfeb42a671b45a523b3a46e9594a8bde0efc671d8e8e046b32c67f59b80a46ffdf24071850779bc21325107902af89322461616161616161612d373030302d313165622d623332612d333362386138613438376136ba3e136372617368696e6720726967687420646f776e";
    let certificate_signature_encoded = "a22d8f86f5d00794f319add821e342c6ffffb6b34f741e569f8b321ab0255f2d1757ecf648e53a3602cae8f09b3fc80dcf27534d67efd272b6739afc31f75c8c";

    // The rest of the test should be stable.
    let certificate_data = hex::decode(certificate_data_encoded).expect("valid hex");
    let certificate_signature = hex::decode(certificate_signature_encoded).expect("valid hex");

    let sender_certificate_data = proto::sealed_sender::SenderCertificate {
        certificate: Some(certificate_data),
        signature: Some(certificate_signature),
    };

    let sender_certificate = SenderCertificate::from_protobuf(&sender_certificate_data)?;
    sender_certificate.verify_signature(ServerSignature {
        trust_root: trust_root.public_key()?,
        validation_time: 31336,
    })?;
    Ok(())
}
