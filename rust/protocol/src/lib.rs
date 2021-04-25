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
pub mod fingerprint;
pub mod group_cipher;
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
    address::{DeviceId, ProtocolAddress},
    consts::types::{Counter, IVBytes, KeyBytes, SignatureBytes},
    error::SignalProtocolError,
    fingerprint::Fingerprint,
    group_cipher::{group_decrypt, group_encrypt},
    identity_key::{IdentityKey, IdentityKeyPair},
    kdf::{HKDF, KDF},
    protocol::{
        PreKeySignalMessage, SenderKeyDistributionMessage, SenderKeyMessage, SignalMessage,
    },
    ratchet::{
        initialize_alice_session_record, initialize_bob_session_record,
        params::{AliceSignalProtocolParameters, BobSignalProtocolParameters},
    },
    sealed_sender::{
        sealed_sender_decrypt, sealed_sender_decrypt_to_usmc, sealed_sender_encrypt_from_usmc,
        sealed_sender_multi_recipient_encrypt, sealed_sender_multi_recipient_fan_out, ContentHint,
        SealedSenderDecryptionResult, SenderCertificate, ServerCertificate, ServerSignature,
        UnidentifiedSenderMessageContent,
    },
    session::process_prekey,
    session_cipher::{message_decrypt_prekey, message_decrypt_signal},
    storage::traits::{
        Context, Direction, IdentityKeyStore, PreKeyStore, ProtocolStore, SenderKeyStore,
        SessionStore, SignedPreKeyStore,
    },
    utils::{
        traits::{
            message::{SequencedMessage, SignalProtocolMessage, SignatureVerifiable},
            serde::{Deserializable, RefSerializable, Serializable},
        },
        unwrap,
    },
};
