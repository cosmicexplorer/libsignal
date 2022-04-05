//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

mod keys;
mod params;

use std::convert::TryInto;

pub use self::keys::{
    ChainKey, HeaderEncryptedMessageKeys, HeaderEncryptedRatchetingMessageKeys, MessageKeys,
    RatchetingMessageKeys, RootKey,
};
pub use self::params::{AliceSignalProtocolParameters, BobSignalProtocolParameters};
use crate::state::{SessionState, SessionStructure};
use crate::{KeyPair, Result, SessionRecord};
use rand::{CryptoRng, Rng};

fn derive_keys(secret_input: &[u8]) -> (RootKey, ChainKey) {
    let mut secrets = [0; 64];
    hkdf::Hkdf::<sha2::Sha256>::new(None, secret_input)
        .expand(b"WhisperText", &mut secrets)
        .expect("valid length");
    let (root_key_bytes, chain_key_bytes) = secrets.split_at(32);

    let root_key = RootKey::new(root_key_bytes.try_into().expect("correct length"));
    let chain_key = ChainKey::new(chain_key_bytes.try_into().expect("correct length"), 0);

    (root_key, chain_key)
}

pub(crate) fn initialize_alice_session<R: Rng + CryptoRng, S: SessionStructure>(
    parameters: &AliceSignalProtocolParameters,
    mut csprng: &mut R,
) -> Result<SessionState<S>> {
    let local_identity = parameters.our_identity_key_pair().identity_key();

    let sending_ratchet_key = KeyPair::generate(&mut csprng);

    let mut secrets = Vec::with_capacity(32 * 5);

    secrets.extend_from_slice(&[0xFFu8; 32]); // "discontinuity bytes"

    let our_base_private_key = parameters.our_base_key_pair().private_key;

    secrets.extend_from_slice(
        &parameters
            .our_identity_key_pair()
            .private_key()
            .calculate_agreement(parameters.their_signed_pre_key())?,
    );

    secrets.extend_from_slice(
        &our_base_private_key.calculate_agreement(parameters.their_identity_key().public_key())?,
    );

    secrets.extend_from_slice(
        &our_base_private_key.calculate_agreement(parameters.their_signed_pre_key())?,
    );

    if let Some(their_one_time_prekey) = parameters.their_one_time_pre_key() {
        secrets
            .extend_from_slice(&our_base_private_key.calculate_agreement(their_one_time_prekey)?);
    }

    let (root_key, chain_key) = derive_keys(&secrets);

    let (sending_chain_root_key, sending_chain_chain_key) = root_key.create_chain(
        parameters.their_ratchet_key(),
        &sending_ratchet_key.private_key,
    )?;

    let session = S::initialize(
        *local_identity.public_key(),
        *parameters.their_identity_key().public_key(),
        sending_chain_root_key,
        Some((*parameters.their_ratchet_key(), chain_key)),
        sending_ratchet_key,
        sending_chain_chain_key,
    );

    let mut session = SessionState::new(session);

    session.add_receiver_chain(parameters.their_ratchet_key(), &chain_key);
    session.set_sender_chain(&sending_ratchet_key, &sending_chain_chain_key);

    Ok(session)
}

pub(crate) fn initialize_bob_session<S: SessionStructure>(
    parameters: &BobSignalProtocolParameters,
) -> Result<SessionState<S>> {
    let local_identity = parameters.our_identity_key_pair().identity_key();

    let mut secrets = Vec::with_capacity(32 * 5);

    secrets.extend_from_slice(&[0xFFu8; 32]); // "discontinuity bytes"

    secrets.extend_from_slice(
        &parameters
            .our_signed_pre_key_pair()
            .private_key
            .calculate_agreement(parameters.their_identity_key().public_key())?,
    );

    secrets.extend_from_slice(
        &parameters
            .our_identity_key_pair()
            .private_key()
            .calculate_agreement(parameters.their_base_key())?,
    );

    secrets.extend_from_slice(
        &parameters
            .our_signed_pre_key_pair()
            .private_key
            .calculate_agreement(parameters.their_base_key())?,
    );

    if let Some(our_one_time_pre_key_pair) = parameters.our_one_time_pre_key_pair() {
        secrets.extend_from_slice(
            &our_one_time_pre_key_pair
                .private_key
                .calculate_agreement(parameters.their_base_key())?,
        );
    }

    let (root_key, chain_key) = derive_keys(&secrets);

    let session = S::initialize(
        *local_identity.public_key(),
        *parameters.their_identity_key().public_key(),
        root_key,
        None,
        *parameters.our_ratchet_key_pair(),
        chain_key,
    );

    let mut session = SessionState::new(session);

    session.set_sender_chain(parameters.our_ratchet_key_pair(), &chain_key);

    Ok(session)
}

pub fn initialize_alice_session_record<R: Rng + CryptoRng, S: SessionStructure>(
    parameters: &AliceSignalProtocolParameters,
    csprng: &mut R,
) -> Result<SessionRecord<S>> {
    Ok(SessionRecord::new(initialize_alice_session(
        parameters, csprng,
    )?))
}

pub fn initialize_bob_session_record<S: SessionStructure>(
    parameters: &BobSignalProtocolParameters,
) -> Result<SessionRecord<S>> {
    Ok(SessionRecord::new(initialize_bob_session(parameters)?))
}
