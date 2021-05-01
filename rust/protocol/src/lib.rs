//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Rust implementation of the **[Signal Protocol]** for asynchronous
//! forward-secret public-key cryptography.
//!
//! In particular, this library implements operations conforming to the following specifications:
//! - the **[X3DH]** key agreement protocol,
//! - the **[Double Ratchet]** *(Axolotl)* messaging protocol,
//! - the **[Sesame]** session agreement protocol.
//!
//! [Signal Protocol]: https://signal.org/
//! [X3DH]: https://signal.org/docs/specifications/x3dh/
//! [Double Ratchet]: https://signal.org/docs/specifications/doubleratchet/
//! [Sesame]: https://signal.org/docs/specifications/sesame/

#![warn(clippy::unwrap_used)]
#![deny(unsafe_code)]

pub mod address;
pub mod consts;
pub mod crypto;
pub mod curve;
pub mod error;
mod fingerprint;
mod group_cipher;
pub mod identity_key;
pub mod kdf;
pub mod proto;
pub mod protocol;
pub mod ratchet;
pub mod sealed_sender;
pub mod sender_keys;
pub mod session;
pub mod session_cipher;
pub mod state;
pub mod storage;
pub mod utils;

use error::Result;

pub use {
    address::ProtocolAddress,
    curve::{KeyPair, PrivateKey, PublicKey, PublicKeySignature},
    error::SignalProtocolError,
    fingerprint::{DisplayableFingerprint, Fingerprint, ScannableFingerprint},
    group_cipher::{
        create_sender_key_distribution_message, group_decrypt, group_encrypt,
        process_sender_key_distribution_message,
    },
    identity_key::{IdentityKey, IdentityKeyPair},
    kdf::HKDF,
    protocol::{
        PreKeySignalMessage, SenderKeyDistributionMessage, SenderKeyMessage, SignalMessage,
    },
    ratchet::{
        initialize_alice_session_record, initialize_bob_session_record,
        AliceSignalProtocolParameters, BobSignalProtocolParameters,
    },
    sealed_sender::{
        sealed_sender_decrypt, sealed_sender_decrypt_to_usmc, sealed_sender_encrypt,
        sealed_sender_encrypt_from_usmc, sealed_sender_multi_recipient_encrypt,
        sealed_sender_multi_recipient_fan_out, CiphertextMessage, CiphertextMessageType,
        ContentHint, SealedSenderDecryptionResult, SealedSenderV1, SealedSenderV2,
        SenderCertificate, ServerCertificate, ServerSignature, UnidentifiedSenderMessageContent,
    },
    sender_keys::SenderKeyRecord,
    session::{process_prekey, process_prekey_bundle},
    session_cipher::{
        message_decrypt, message_decrypt_prekey, message_decrypt_signal, message_encrypt,
    },
    state::{PreKeyBundle, PreKeyRecord, SessionRecord, SignedPreKeyRecord},
    storage::{
        Context, Direction, IdentityKeyStore, InMemIdentityKeyStore, InMemPreKeyStore,
        InMemSenderKeyStore, InMemSessionStore, InMemSignalProtocolStore, InMemSignedPreKeyStore,
        PreKeyStore, ProtocolStore, SenderKeyStore, SessionStore, SignedPreKeyStore,
    },
};
