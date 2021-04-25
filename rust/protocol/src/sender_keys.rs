//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Ephemeral keys used to kick off communication in a [Double Ratchet] chain.
//!
//! [Double Ratchet]: https://signal.org/docs/specifications/doubleratchet/#diffie-hellman-ratchet

use crate::{
    consts::{
        self,
        types::{as_iv_bytes, as_key_bytes, Counter, IVBytes, KeyBytes},
    },
    crypto::hmac_sha256,
    curve::{PrivateKey, PublicKey},
    kdf::KDF,
    proto::storage as storage_proto,
    utils::{
        unwrap::no_encoding_error,
        traits::serde::{Deserializable, Serializable},
    },
    Result, SignalProtocolError, HKDF,
};

use arrayref::array_ref;
use prost::Message;

use std::collections::VecDeque;
use std::convert::TryFrom;

/// Key information *derived* from an [HKDF] which is used to encrypt or decrypt
/// a [crate::protocol::SignalMessage].
#[derive(Debug, Clone)]
pub struct SenderMessageKey {
    iteration: Counter,
    iv: IVBytes,
    cipher_key: KeyBytes,
    seed: Vec<u8>,
}

impl SenderMessageKey {
    pub fn new(iteration: Counter, seed: &[u8]) -> Self {
        let hkdf = HKDF::new();
        let derived = hkdf.derive_secrets(&seed, b"WhisperGroup", 48);
        Self {
            iteration,
            seed: seed.to_vec(),
            iv: *as_iv_bytes(&derived[0..16]),
            cipher_key: *as_key_bytes(&derived[16..48]),
        }
    }

    pub fn from_protobuf(smk: storage_proto::sender_key_state_structure::SenderMessageKey) -> Self {
        Self::new(smk.iteration, &smk.seed)
    }

    pub fn iteration(&self) -> Counter {
        self.iteration
    }

    pub fn iv(&self) -> IVBytes {
        self.iv.clone()
    }

    pub fn cipher_key(&self) -> KeyBytes {
        self.cipher_key.clone()
    }

    pub fn seed(&self) -> Vec<u8> {
        self.seed.clone()
    }

    pub fn as_protobuf(&self) -> storage_proto::sender_key_state_structure::SenderMessageKey {
        storage_proto::sender_key_state_structure::SenderMessageKey {
            iteration: self.iteration(),
            seed: self.seed(),
        }
    }
}

/// The key information needed to iterate an [HKDF].
#[derive(Debug, Clone)]
pub struct SenderChainKey {
    iteration: Counter,
    chain_key: KeyBytes,
}

impl SenderChainKey {
    const MESSAGE_KEY_SEED: u8 = 0x01;
    const CHAIN_KEY_SEED: u8 = 0x02;

    pub fn new(iteration: Counter, chain_key: KeyBytes) -> Self {
        Self {
            iteration,
            chain_key,
        }
    }

    #[inline]
    pub fn iteration(&self) -> Counter {
        self.iteration
    }

    #[inline]
    pub fn seed(&self) -> KeyBytes {
        self.chain_key.clone()
    }

    pub fn next(&self) -> SenderChainKey {
        SenderChainKey::new(
            self.iteration + 1,
            self.get_derivative(Self::CHAIN_KEY_SEED),
        )
    }

    pub fn sender_message_key(&self) -> SenderMessageKey {
        SenderMessageKey::new(
            self.iteration(),
            &self.get_derivative(Self::MESSAGE_KEY_SEED),
        )
    }

    fn get_derivative(&self, label: u8) -> KeyBytes {
        let label = [label];
        hmac_sha256(&self.chain_key, &label)
    }

    pub fn as_protobuf(&self) -> storage_proto::sender_key_state_structure::SenderChainKey {
        storage_proto::sender_key_state_structure::SenderChainKey {
            iteration: self.iteration(),
            seed: self.seed().to_vec(),
        }
    }
}

/// Deserializes a [storage_proto::SenderKeyStateStructure] to obtain the state of a message chain.
#[derive(Debug, Clone)]
pub struct SenderKeyState {
    state: storage_proto::SenderKeyStateStructure,
}

/// Type used to record the identity of a specific [crate::ratchet] chain in the
/// [crate::storage::traits::SenderKeyStore].
pub type ChainId = u32;

impl SenderKeyState {
    /// Create a new instance.
    pub fn new(
        chain_id: ChainId,
        iteration: Counter,
        chain_key: &KeyBytes,
        signature_key: PublicKey,
        signature_private_key: Option<PrivateKey>,
    ) -> SenderKeyState {
        let state = storage_proto::SenderKeyStateStructure {
            chain_id,
            sender_chain_key: Some(SenderChainKey::new(iteration, chain_key.clone()).as_protobuf()),
            sender_signing_key: Some(
                storage_proto::sender_key_state_structure::SenderSigningKey {
                    public: signature_key.serialize().to_vec(),
                    private: match signature_private_key {
                        None => vec![],
                        Some(k) => k.serialize().to_vec(),
                    },
                },
            ),
            sender_message_keys: vec![],
        };

        Self { state }
    }

    pub fn from_protobuf(state: storage_proto::SenderKeyStateStructure) -> Self {
        Self { state }
    }

    pub fn chain_id(&self) -> ChainId {
        self.state.chain_id
    }

    pub fn sender_chain_key(&self) -> Result<SenderChainKey> {
        let sender_chain = self
            .state
            .sender_chain_key
            .as_ref()
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        Ok(SenderChainKey::new(
            sender_chain.iteration,
            *as_key_bytes(&sender_chain.seed),
        ))
    }

    pub fn set_sender_chain_key(&mut self, chain_key: SenderChainKey) {
        self.state.sender_chain_key = Some(chain_key.as_protobuf());
    }

    pub fn signing_key_public(&self) -> Result<PublicKey> {
        if let Some(ref signing_key) = self.state.sender_signing_key {
            Ok(PublicKey::try_from(&signing_key.public[..])?)
        } else {
            Err(SignalProtocolError::InvalidProtobufEncoding)
        }
    }

    pub fn signing_key_private(&self) -> Result<PrivateKey> {
        if let Some(ref signing_key) = self.state.sender_signing_key {
            Ok(PrivateKey::deserialize(&signing_key.private)?)
        } else {
            Err(SignalProtocolError::InvalidProtobufEncoding)
        }
    }

    pub fn has_sender_message_key(&self, iteration: Counter) -> Result<bool> {
        for sender_message_key in &self.state.sender_message_keys {
            if sender_message_key.iteration == iteration {
                return true;
            }
        }
        false
    }

    pub fn as_protobuf(&self) -> storage_proto::SenderKeyStateStructure {
        self.state.clone()
    }

    pub fn add_sender_message_key(&mut self, sender_message_key: &SenderMessageKey) -> () {
        self.state
            .sender_message_keys
            .push(sender_message_key.as_protobuf());
        while self.state.sender_message_keys.len() > consts::limits::MAX_MESSAGE_KEYS {
            self.state.sender_message_keys.remove(0);
        }
    }

    pub fn remove_sender_message_key(
        &mut self,
        iteration: Counter,
    ) -> Result<Option<SenderMessageKey>> {
        if let Some(index) = self
            .state
            .sender_message_keys
            .iter()
            .position(|x| x.iteration == iteration)
        {
            let smk = self.state.sender_message_keys.remove(index);
            Ok(Some(SenderMessageKey::from_protobuf(smk)))
        } else {
            None
        }
    }
}

impl Deserializable for SenderKeyState {
    fn deserialize(buf: &[u8]) -> Result<Self> {
        let state = storage_proto::SenderKeyStateStructure::decode(buf)?;
        Ok(Self { state })
    }
}

impl Serializable<Vec<u8>> for SenderKeyState {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = vec![];
        no_encoding_error(self.state.encode(&mut buf));
        buf
    }
}

/// Manages sender key states to converge on a single chain for a specific conversation. Part of the
/// [Sesame] algorithm for session agreement.
///
/// [Sesame]: https://signal.org/docs/specifications/sesame/
#[derive(Debug, Clone)]
pub struct SenderKeyRecord {
    states: VecDeque<SenderKeyState>,
}

impl SenderKeyRecord {
    /// Create a new instance.
    pub fn new_empty() -> Self {
        Self {
            states: VecDeque::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }

    pub fn sender_key_state(&mut self) -> Result<&mut SenderKeyState> {
        if !self.states.is_empty() {
            return Ok(&mut self.states[0]);
        }
        Err(SignalProtocolError::NoSenderKeyState)
    }

    pub fn sender_key_state_for_chain_id(
        &mut self,
        chain_id: ChainId,
    ) -> Result<&mut SenderKeyState> {
        for i in 0..self.states.len() {
            if self.states[i].chain_id() == chain_id {
                return Ok(&mut self.states[i]);
            }
        }
        Err(SignalProtocolError::NoSenderKeyState)
    }

    pub fn add_sender_key_state(
        &mut self,
        chain_id: ChainId,
        iteration: Counter,
        chain_key: &KeyBytes,
        signature_key: PublicKey,
        signature_private_key: Option<PrivateKey>,
    ) {
        self.states.push_front(SenderKeyState::new(
            chain_id,
            iteration,
            chain_key,
            signature_key,
            signature_private_key,
        ));

        while self.states.len() > consts::limits::MAX_SENDER_KEY_STATES {
            self.states.pop_back();
        }
    }

    pub fn set_sender_key_state(
        &mut self,
        chain_id: ChainId,
        iteration: Counter,
        chain_key: &KeyBytes,
        signature_key: PublicKey,
        signature_private_key: Option<PrivateKey>,
    ) {
        self.states.clear();
        self.add_sender_key_state(
            chain_id,
            iteration,
            chain_key,
            signature_key,
            signature_private_key,
        );
    }

    pub fn as_protobuf(&self) -> storage_proto::SenderKeyRecordStructure {
        let mut states = Vec::with_capacity(self.states.len());
        for state in &self.states {
            states.push(state.as_protobuf());
        }

        storage_proto::SenderKeyRecordStructure {
            sender_key_states: states,
        }
    }
}

impl Deserializable for SenderKeyRecord {
    fn deserialize(buf: &[u8]) -> Result<Self> {
        let skr = storage_proto::SenderKeyRecordStructure::decode(buf)?;

        let mut states = VecDeque::with_capacity(skr.sender_key_states.len());
        for state in skr.sender_key_states {
            states.push_back(SenderKeyState::from_protobuf(state))
        }
        Ok(Self { states })
    }
}

impl Serializable<Vec<u8>> for SenderKeyRecord {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = vec![];
        no_encoding_error(self.as_protobuf().encode(&mut buf));
        buf
    }
}
