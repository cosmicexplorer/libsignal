//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// TODO
// #![warn(missing_docs)]

//! Interfaces in [traits] and reference implementations in [inmem] for various mutable stores.

pub mod inmem;
pub mod traits;

pub use {
    inmem::{
        InMemIdentityKeyStore, InMemPreKeyStore, InMemSenderKeyStore, InMemSessionStore,
        InMemSignalProtocolStore, InMemSignedPreKeyStore,
    },
    traits::{
        Context, Direction, IdentityKeyStore, PreKeyStore, ProtocolStore, SenderKeyStore,
        SessionStore, SignedPreKeyStore,
    },
};
