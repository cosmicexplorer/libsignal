//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Magic numbers.

/// Lengths of byte strings used throughout the protocol.
pub mod byte_lengths {
    pub use crate::curve::{
        AGREEMENT_LENGTH, PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH,
    };

    pub use crate::crypto::{AES_INPUT_SIZE, AES_NONCE_SIZE, HMAC_OUTPUT_SIZE};
}

/// Types which must stay static for correctness, and often correlate to fields of structs in
/// [crate::proto].
pub mod types {
    /// The definition of the data used to represent the message version in
    /// [super::CIPHERTEXT_MESSAGE_CURRENT_VERSION].
    pub type VersionType = u8;

    /// Type for the incrementing counter used in all [crate::ratchet] chains.
    pub type Counter = u32;
}

/// Each [crate::SignalMessage] has this message version mixed into it when created. Prefer to
/// reference this value over use of the literal version number.
pub const CIPHERTEXT_MESSAGE_CURRENT_VERSION: types::VersionType = 3;

/// Various positive integers bounding the maximum size of other data structures.
pub mod limits {
    /// The maximum number of encrypted messages that the client chain which decrypts Signal
    /// messages in a [Double Ratchet] instance can retrieve at once (tracked in
    /// [crate::proto::storage::session_structure::chain::ChainKey::index] as well as a separate
    /// `counter`).
    ///
    /// [Double Ratchet]: https://signal.org/docs/specifications/doubleratchet/
    pub const MAX_FORWARD_JUMPS: usize = 25_000;
    /// The maximum number of per-message keys that can be retained to decrypt messages within
    /// a specific chain from `message_keys` in [crate::proto::storage::session_structure::Chain].
    pub const MAX_MESSAGE_KEYS: usize = 2000;
    /// The maximum number of temporary backup chains to allow for `receiver_chains` in
    /// [crate::proto::storage::SessionStructure]. These backup chains corresponds to the [Sesame]
    /// protocol for syncing a Double Ratchet chain between two users.
    ///
    /// [Sesame]: https://signal.org/docs/specifications/sesame/#server
    pub const MAX_RECEIVER_CHAINS: usize = 5;
    /// The maximum number of sessions allowed for
    /// [crate::proto::storage::RecordStructure::previous_sessions].
    pub const ARCHIVED_STATES_MAX_LENGTH: usize = 40;
    /// The maximum number of sender key states allowed for
    /// [crate::proto::storage::SenderKeyRecordStructure::sender_key_states].
    pub const MAX_SENDER_KEY_STATES: usize = 5;
}
