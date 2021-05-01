//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Transform a signed pre-key into an active "session" or message chain.
//!
//! These functions are on [`SessionBuilder`] in the Java implementation. However, using
//! `SessionBuilder` and `SessionCipher` ([crate::session_cipher] in Rust) at the same time causes
//! `&mut` sharing issues. And as `SessionBuilder` has no actual state beyond its reference to the
//! various data stores, instead the functions are free standing.
//!
//! [`SessionBuilder`]: https://github.com/signalapp/libsignal-protocol-java/blob/fde96d22004f32a391554e4991e4e1f0a14c2d50/java/src/main/java/org/whispersystems/libsignal/SessionBuilder.java#L62

use crate::{
    curve::{KeyPair, PublicKeySignature},
    ratchet::{self, AliceSignalProtocolParameters, BobSignalProtocolParameters},
    state::{PreKeyBundle, PreKeyId, SessionRecord},
    utils::traits::{message::SignatureVerifiable, serde::Serializable},
    Context, Direction, IdentityKeyStore, PreKeySignalMessage, PreKeyStore, ProtocolAddress,
    Result, SessionStore, SignalProtocolError, SignedPreKeyStore,
};

use arrayref::array_ref;
use rand::{CryptoRng, Rng};

/// Transform a signed pre-key into an active "session" or message chain.
///
/// This function is [`SessionBuilder::process`] (overloaded method) in the Java implementation.
///
/// [`SessionBuilder::process`]: https://github.com/signalapp/libsignal-protocol-java/blob/fde96d22004f32a391554e4991e4e1f0a14c2d50/java/src/main/java/org/whispersystems/libsignal/SessionBuilder.java#L98
pub async fn process_prekey(
    message: &PreKeySignalMessage,
    remote_address: &ProtocolAddress,
    session_record: &mut SessionRecord,
    identity_store: &mut dyn IdentityKeyStore,
    pre_key_store: &mut dyn PreKeyStore,
    signed_prekey_store: &mut dyn SignedPreKeyStore,
    ctx: Context,
) -> Result<Option<PreKeyId>> {
    let their_identity_key = message.identity_key();

    if !identity_store
        .is_trusted_identity(
            &remote_address,
            their_identity_key,
            Direction::Receiving,
            ctx,
        )
        .await?
    {
        return Err(SignalProtocolError::UntrustedIdentity(
            remote_address.clone(),
        ));
    }

    let unsigned_pre_key_id = process_prekey_v3(
        message,
        session_record,
        signed_prekey_store,
        pre_key_store,
        identity_store,
        ctx,
    )
    .await?;

    identity_store
        .save_identity(&remote_address, their_identity_key, ctx)
        .await?;

    Ok(unsigned_pre_key_id)
}

async fn process_prekey_v3(
    message: &PreKeySignalMessage,
    session_record: &mut SessionRecord,
    signed_prekey_store: &mut dyn SignedPreKeyStore,
    pre_key_store: &mut dyn PreKeyStore,
    identity_store: &mut dyn IdentityKeyStore,
    ctx: Context,
) -> Result<Option<PreKeyId>> {
    if session_record.has_session_state(
        message.message_version().into(),
        &message.base_key().serialize(),
    )? {
        // We've already setup a session for this V3 message, letting bundled message fall through
        return Ok(None);
    }

    let our_signed_pre_key_pair = signed_prekey_store
        .get_signed_pre_key(message.signed_pre_key_id(), ctx)
        .await?
        .key_pair()?;

    let our_one_time_pre_key_pair = if let Some(pre_key_id) = message.pre_key_id() {
        Some(
            pre_key_store
                .get_pre_key(pre_key_id, ctx)
                .await?
                .key_pair()?,
        )
    } else {
        log::warn!("Processing PreKey message which had no one-time prekey");
        None
    };

    let parameters = BobSignalProtocolParameters::new(
        identity_store.get_identity_key_pair(ctx).await?,
        our_signed_pre_key_pair, // signed pre key
        our_one_time_pre_key_pair,
        our_signed_pre_key_pair, // ratchet key
        *message.identity_key(),
        *message.base_key(),
    );

    session_record.archive_current_state()?;

    let mut new_session = ratchet::initialize_bob_session(&parameters)?;

    new_session.set_local_registration_id(identity_store.get_local_registration_id(ctx).await?)?;
    new_session.set_remote_registration_id(message.registration_id())?;
    new_session.set_alice_base_key(&message.base_key().serialize())?;

    session_record.promote_state(new_session)?;

    Ok(message.pre_key_id())
}

/// Transform a signed pre-key into an active "session" or message chain.
///
/// This function is [`SessionBuilder::process`] (overloaded method) in the Java implementation.
///
/// [`SessionBuilder::process`]: https://github.com/signalapp/libsignal-protocol-java/blob/fde96d22004f32a391554e4991e4e1f0a14c2d50/java/src/main/java/org/whispersystems/libsignal/SessionBuilder.java#L165
pub async fn process_prekey_bundle<R: Rng + CryptoRng>(
    remote_address: &ProtocolAddress,
    session_store: &mut dyn SessionStore,
    identity_store: &mut dyn IdentityKeyStore,
    bundle: &PreKeyBundle,
    mut csprng: &mut R,
    ctx: Context,
) -> Result<()> {
    let their_identity_key = bundle.identity_key()?;

    if !identity_store
        .is_trusted_identity(&remote_address, their_identity_key, Direction::Sending, ctx)
        .await?
    {
        return Err(SignalProtocolError::UntrustedIdentity(
            remote_address.clone(),
        ));
    }

    if !their_identity_key
        .public_key()
        .verify_signature(PublicKeySignature {
            message: &bundle.signed_pre_key_public()?.serialize(),
            signature: array_ref![bundle.signed_pre_key_signature()?, 0, 64],
        })?
    {
        return Err(SignalProtocolError::SignatureValidationFailed);
    }

    let mut session_record = session_store
        .load_session(&remote_address, ctx)
        .await?
        .unwrap_or_else(SessionRecord::new_fresh);

    let our_base_key_pair = KeyPair::generate(&mut csprng);
    let their_signed_prekey = bundle.signed_pre_key_public()?;

    let their_one_time_prekey = bundle.pre_key_public()?;
    let their_one_time_prekey_id = bundle.pre_key_id()?;

    let our_identity_key_pair = identity_store.get_identity_key_pair(ctx).await?;

    let parameters = AliceSignalProtocolParameters::new(
        our_identity_key_pair,
        our_base_key_pair,
        *their_identity_key,
        their_signed_prekey,
        their_one_time_prekey,
        their_signed_prekey,
    );

    let mut session = ratchet::initialize_alice_session(&parameters, csprng)?;

    log::info!(
        "set_unacknowledged_pre_key_message for: {} with preKeyId: {}",
        remote_address,
        their_one_time_prekey_id.map_or_else(|| "<none>".to_string(), |id| id.to_string())
    );

    session.set_unacknowledged_pre_key_message(
        their_one_time_prekey_id,
        bundle.signed_pre_key_id()?,
        &our_base_key_pair.public_key,
    )?;

    session.set_local_registration_id(identity_store.get_local_registration_id(ctx).await?)?;
    session.set_remote_registration_id(bundle.registration_id()?)?;
    session.set_alice_base_key(&our_base_key_pair.public_key.serialize())?;

    identity_store
        .save_identity(&remote_address, their_identity_key, ctx)
        .await?;

    session_record.promote_state(session)?;

    session_store
        .store_session(&remote_address, &session_record, ctx)
        .await?;

    Ok(())
}
