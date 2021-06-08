//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::VecDeque;
use std::convert::{TryFrom, TryInto};

use arrayref::array_ref;
use itertools::Itertools;
use prost::Message;
use uuid::Uuid;

use crate::consts::limits::{MAX_MESSAGE_KEYS, MAX_SENDER_KEY_STATES};
use crate::crypto::{hmac_sha256, AES_NONCE_SIZE, HMAC_OUTPUT_SIZE};
use crate::curve::curve25519::PUBLIC_KEY_LENGTH;
use crate::proto::storage as storage_proto;
use crate::protocol::SENDERKEY_MESSAGE_CURRENT_VERSION;
use crate::utils::no_encoding_error;
use crate::{AsymmetricRole, KeyType, PrivateKey, PublicKey, Result, SignalProtocolError, HKDF};

pub const CHAIN_KEY_LENGTH: usize = 32;

#[derive(Debug, Clone)]
pub struct SenderMessageKey {
    iteration: u32,
    iv: [u8; AES_NONCE_SIZE],
    cipher_key: [u8; PUBLIC_KEY_LENGTH],
    seed: [u8; HMAC_OUTPUT_SIZE],
}

impl SenderMessageKey {
    pub fn new(iteration: u32, seed: [u8; HMAC_OUTPUT_SIZE]) -> Result<Self> {
        let hkdf = HKDF::new(3)?;
        let derived_bytes =
            hkdf.derive_secrets(&seed, b"WhisperGroup", AES_NONCE_SIZE + PUBLIC_KEY_LENGTH)?;
        let derived = <[u8; AES_NONCE_SIZE + PUBLIC_KEY_LENGTH]>::try_from(derived_bytes.as_ref())
            .expect("requested this many bytes from HKDF::derive_secrets()");
        Ok(Self {
            iteration,
            iv: *array_ref![&derived, 0, AES_NONCE_SIZE],
            cipher_key: *array_ref![&derived, AES_NONCE_SIZE, PUBLIC_KEY_LENGTH],
            seed,
        })
    }

    pub fn from_protobuf(
        smk: storage_proto::sender_key_state_structure::SenderMessageKey,
    ) -> Result<Self> {
        let seed: &[u8; HMAC_OUTPUT_SIZE] = &smk.seed.try_into().map_err(|e: Vec<u8>| {
            SignalProtocolError::BadKeyLength(KeyType::Curve25519, AsymmetricRole::Hmac, e.len())
        })?;
        Self::new(smk.iteration, *seed)
    }

    pub fn iteration(&self) -> u32 {
        self.iteration
    }

    pub fn iv(&self) -> [u8; AES_NONCE_SIZE] {
        self.iv
    }

    pub fn cipher_key(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.cipher_key
    }

    pub fn seed(&self) -> [u8; HMAC_OUTPUT_SIZE] {
        self.seed
    }

    pub fn as_protobuf(&self) -> storage_proto::sender_key_state_structure::SenderMessageKey {
        storage_proto::sender_key_state_structure::SenderMessageKey {
            iteration: self.iteration,
            seed: self.seed.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SenderChainKey {
    iteration: u32,
    chain_key: [u8; CHAIN_KEY_LENGTH],
}

impl SenderChainKey {
    const MESSAGE_KEY_SEED: u8 = 0x01;
    const CHAIN_KEY_SEED: u8 = 0x02;

    pub fn new(iteration: u32, chain_key: [u8; CHAIN_KEY_LENGTH]) -> Self {
        Self {
            iteration,
            chain_key,
        }
    }

    pub fn iteration(&self) -> u32 {
        self.iteration
    }

    pub fn seed(&self) -> [u8; CHAIN_KEY_LENGTH] {
        self.chain_key
    }

    pub fn next(&self) -> SenderChainKey {
        SenderChainKey::new(
            self.iteration + 1,
            self.get_derivative(Self::CHAIN_KEY_SEED),
        )
    }

    pub fn sender_message_key(&self) -> Result<SenderMessageKey> {
        SenderMessageKey::new(self.iteration, self.get_derivative(Self::MESSAGE_KEY_SEED))
    }

    fn get_derivative(&self, label: u8) -> [u8; HMAC_OUTPUT_SIZE] {
        let label = [label];
        hmac_sha256(&self.chain_key, &label)
    }

    pub fn as_protobuf(&self) -> storage_proto::sender_key_state_structure::SenderChainKey {
        storage_proto::sender_key_state_structure::SenderChainKey {
            iteration: self.iteration,
            seed: self.chain_key.to_vec(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SenderKeyState {
    state: storage_proto::SenderKeyStateStructure,
}

impl SenderKeyState {
    pub fn new(
        message_version: u8,
        chain_id: u32,
        iteration: u32,
        chain_key: &[u8; CHAIN_KEY_LENGTH],
        signature_key: PublicKey,
        signature_private_key: Option<PrivateKey>,
    ) -> Result<SenderKeyState> {
        let state = storage_proto::SenderKeyStateStructure {
            message_version: message_version as u32,
            chain_id,
            sender_chain_key: Some(SenderChainKey::new(iteration, *chain_key).as_protobuf()),
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

        Self::from_protobuf(state)
    }

    pub fn deserialize(buf: &[u8]) -> Result<Self> {
        let state = storage_proto::SenderKeyStateStructure::decode(buf)?;
        Self::from_protobuf(state)
    }

    pub fn from_protobuf(state: storage_proto::SenderKeyStateStructure) -> Result<Self> {
        Ok(Self { state })
    }

    pub fn serialize(&self) -> Box<[u8]> {
        no_encoding_error(self.state.clone())
    }

    pub fn message_version(&self) -> u32 {
        match self.state.message_version {
            0 => SENDERKEY_MESSAGE_CURRENT_VERSION.into(),
            v => v,
        }
    }

    pub fn chain_id(&self) -> u32 {
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
            sender_chain.seed.clone().try_into().map_err(|e: Vec<u8>| {
                SignalProtocolError::BadKeyLength(
                    KeyType::Curve25519,
                    AsymmetricRole::Hmac,
                    e.len(),
                )
            })?,
        ))
    }

    pub fn set_sender_chain_key(&mut self, chain_key: SenderChainKey) {
        self.state.sender_chain_key = Some(chain_key.as_protobuf());
    }

    pub fn signing_key_public(&self) -> Result<PublicKey> {
        if let Some(ref signing_key) = self.state.sender_signing_key {
            Ok(PublicKey::deserialize_result(&signing_key.public)?)
        } else {
            Err(SignalProtocolError::InvalidProtobufEncoding)
        }
    }

    pub fn signing_key_private(&self) -> Result<PrivateKey> {
        if let Some(ref signing_key) = self.state.sender_signing_key {
            Ok(PrivateKey::deserialize_result(&signing_key.private)?)
        } else {
            Err(SignalProtocolError::InvalidProtobufEncoding)
        }
    }

    pub fn has_sender_message_key(&self, iteration: u32) -> bool {
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

    pub fn add_sender_message_key(&mut self, sender_message_key: &SenderMessageKey) {
        self.state
            .sender_message_keys
            .push(sender_message_key.as_protobuf());
        while self.state.sender_message_keys.len() > MAX_MESSAGE_KEYS {
            self.state.sender_message_keys.remove(0);
        }
    }

    pub fn remove_sender_message_key(
        &mut self,
        iteration: u32,
    ) -> Result<Option<SenderMessageKey>> {
        if let Some(index) = self
            .state
            .sender_message_keys
            .iter()
            .position(|x| x.iteration == iteration)
        {
            let smk = self.state.sender_message_keys.remove(index);
            Ok(Some(SenderMessageKey::from_protobuf(smk)?))
        } else {
            Ok(None)
        }
    }
}

#[derive(Debug, Clone)]
pub struct SenderKeyRecord {
    states: VecDeque<SenderKeyState>,
}

impl SenderKeyRecord {
    pub fn new_empty() -> Self {
        Self {
            states: VecDeque::with_capacity(MAX_SENDER_KEY_STATES),
        }
    }

    pub fn deserialize(buf: &[u8]) -> Result<SenderKeyRecord> {
        let skr = storage_proto::SenderKeyRecordStructure::decode(buf)?;

        let mut states = VecDeque::with_capacity(skr.sender_key_states.len());
        for state in skr.sender_key_states {
            states.push_back(SenderKeyState::from_protobuf(state)?)
        }
        Ok(Self { states })
    }

    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.states.is_empty())
    }

    pub fn sender_key_state(&mut self) -> Result<&mut SenderKeyState> {
        if !self.states.is_empty() {
            return Ok(&mut self.states[0]);
        }
        Err(SignalProtocolError::NoSenderKeyState)
    }

    pub fn sender_key_state_for_chain_id(
        &mut self,
        chain_id: u32,
        distribution_id: Uuid,
    ) -> Result<&mut SenderKeyState> {
        for i in 0..self.states.len() {
            if self.states[i].chain_id() == chain_id {
                return Ok(&mut self.states[i]);
            }
        }
        log::error!(
            "SenderKey distribution {} could not find chain ID {} (known chain IDs: {:?})",
            distribution_id,
            chain_id,
            self.states
                .iter()
                .map(|state| state.chain_id())
                .collect::<Vec<_>>()
        );
        Err(SignalProtocolError::NoSenderKeyState)
    }

    pub fn add_sender_key_state(
        &mut self,
        message_version: u8,
        chain_id: u32,
        iteration: u32,
        chain_key: &[u8; CHAIN_KEY_LENGTH],
        signature_key: PublicKey,
        signature_private_key: Option<PrivateKey>,
    ) -> Result<()> {
        let existing_state = self.remove_state(chain_id, signature_key);

        if self.remove_states_with_chain_id(chain_id) > 0 {
            log::warn!(
                "Removed a matching chain_id ({}) found with a different public key",
                chain_id
            );
        }

        let state = match existing_state {
            None => SenderKeyState::new(
                message_version,
                chain_id,
                iteration,
                chain_key,
                signature_key,
                signature_private_key,
            )?,
            Some(state) => state,
        };

        while self.states.len() >= MAX_SENDER_KEY_STATES {
            self.states.pop_back();
        }

        self.states.push_front(state);

        Ok(())
    }

    /// Remove the state with the matching `chain_id` and `signature_key`.
    ///
    /// Skips any bad protobufs.
    fn remove_state(&mut self, chain_id: u32, signature_key: PublicKey) -> Option<SenderKeyState> {
        let (index, _state) = self.states.iter().find_position(|state| {
            state.chain_id() == chain_id && state.signing_key_public().ok() == Some(signature_key)
        })?;

        self.states.remove(index)
    }

    /// Returns the number of removed states.
    ///
    /// Skips any bad protobufs.
    fn remove_states_with_chain_id(&mut self, chain_id: u32) -> usize {
        let initial_length = self.states.len();
        self.states.retain(|state| state.chain_id() != chain_id);
        initial_length - self.states.len()
    }

    pub fn set_sender_key_state(
        &mut self,
        message_version: u8,
        chain_id: u32,
        iteration: u32,
        chain_key: &[u8; CHAIN_KEY_LENGTH],
        signature_key: PublicKey,
        signature_private_key: Option<PrivateKey>,
    ) -> Result<()> {
        self.states.clear();
        self.add_sender_key_state(
            message_version,
            chain_id,
            iteration,
            chain_key,
            signature_key,
            signature_private_key,
        )
    }

    pub fn as_protobuf(&self) -> Result<storage_proto::SenderKeyRecordStructure> {
        let mut states = Vec::with_capacity(self.states.len());
        for state in &self.states {
            states.push(state.as_protobuf());
        }

        Ok(storage_proto::SenderKeyRecordStructure {
            sender_key_states: states,
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        Ok(self.as_protobuf()?.encode_to_vec())
    }
}

#[cfg(test)]
mod sender_key_record_add_sender_key_state_tests {
    use itertools::Itertools;
    use rand::rngs::OsRng;

    use crate::KeyPair;

    use super::*;

    fn random_public_key() -> PublicKey {
        KeyPair::generate(&mut OsRng).public_key
    }

    fn chain_key(i: u128) -> [u8; CHAIN_KEY_LENGTH] {
        [i.to_be_bytes(), i.to_be_bytes()]
            .concat()
            .try_into()
            .expect("fixed-size slice")
    }

    struct TestContext {
        sender_key_record: SenderKeyRecord,
    }

    impl TestContext {
        fn new() -> Self {
            Self {
                sender_key_record: SenderKeyRecord::new_empty(),
            }
        }

        /// Associates the `record_key` with the `chain_key` via `add_sender_key_state` which is the
        /// method under test in this module.
        fn add_sender_key_state_record(
            &mut self,
            record_key: (PublicKey, u32),
            chain_key: &[u8; CHAIN_KEY_LENGTH],
        ) {
            let (public_key, chain_id) = record_key;
            self.sender_key_record
                .add_sender_key_state(1, chain_id, 1, chain_key, public_key, None)
                .expect("to be able to add new state");
        }

        fn assert_number_of_states(&self, expected: usize) {
            assert_eq!(expected, self.sender_key_record.states.len());
        }

        /// Asserts that for the supplied `record_key` the chain key is as expected when looked up
        /// by both `chain_id` and `public_key` and `chain_id`.
        fn assert_records_chain_key(
            &mut self,
            record_key: (PublicKey, u32),
            expected_chain_key: &[u8],
        ) {
            let (public_key, chain_id) = record_key;
            let found_chain_key = self
                .sender_key_record
                .sender_key_state_for_chain_id(chain_id, Uuid::default())
                .expect("Expect to find chain id")
                .sender_chain_key()
                .expect("Expect to find chain key")
                .chain_key;

            assert_eq!(found_chain_key, expected_chain_key);

            let matching_state = self
                .sender_key_record
                .states
                .iter()
                .filter(|state| {
                    state.chain_id() == chain_id
                        && state.signing_key_public().expect("expect public key") == public_key
                })
                .exactly_one()
                .expect("Expected exactly one record key match");

            assert_eq!(
                &matching_state
                    .sender_chain_key()
                    .expect("Expect to find chain key")
                    .chain_key,
                expected_chain_key
            );
        }

        fn assert_record_order(&self, order: Vec<(PublicKey, u32)>) {
            let record_keys = self
                .sender_key_record
                .states
                .iter()
                .map(|state| {
                    (
                        state.signing_key_public().expect("expect public key"),
                        state.chain_id(),
                    )
                })
                .collect::<Vec<_>>();

            assert_eq!(record_keys, order);
        }
    }

    #[test]
    fn add_single_state() {
        let mut context = TestContext::new();

        let public_key = random_public_key();
        let chain_id = 1;
        let chain_key = chain_key(1);
        let record_key = (public_key, chain_id);

        context.add_sender_key_state_record(record_key, &chain_key);

        context.assert_number_of_states(1);
        context.assert_records_chain_key(record_key, &chain_key);
    }

    #[test]
    fn add_second_state() {
        let mut context = TestContext::new();

        let chain_id_1 = 1;
        let chain_id_2 = 2;
        let record_key_1 = (random_public_key(), chain_id_1);
        let record_key_2 = (random_public_key(), chain_id_2);
        let chain_key_1 = chain_key(1);
        let chain_key_2 = chain_key(2);

        context.add_sender_key_state_record(record_key_1, &chain_key_1);
        context.add_sender_key_state_record(record_key_2, &chain_key_2);

        context.assert_number_of_states(2);
        context.assert_records_chain_key(record_key_1, &chain_key_1);
        context.assert_records_chain_key(record_key_2, &chain_key_2);
    }

    #[test]
    fn when_exceed_maximum_states_then_oldest_is_ejected() {
        assert_eq!(
            5, MAX_SENDER_KEY_STATES,
            "Test written to expect this limit"
        );

        let mut context = TestContext::new();

        let record_key_1 = (random_public_key(), 1);
        let record_key_2 = (random_public_key(), 2);
        let record_key_3 = (random_public_key(), 3);
        let record_key_4 = (random_public_key(), 4);
        let record_key_5 = (random_public_key(), 5);
        let record_key_6 = (random_public_key(), 6);

        context.add_sender_key_state_record(record_key_1, &chain_key(1));
        context.add_sender_key_state_record(record_key_2, &chain_key(2));
        context.add_sender_key_state_record(record_key_3, &chain_key(3));
        context.add_sender_key_state_record(record_key_4, &chain_key(4));
        context.add_sender_key_state_record(record_key_5, &chain_key(5));

        context.assert_record_order(vec![
            record_key_5,
            record_key_4,
            record_key_3,
            record_key_2,
            record_key_1,
        ]);

        context.add_sender_key_state_record(record_key_6, &chain_key(6));

        context.assert_record_order(vec![
            record_key_6,
            record_key_5,
            record_key_4,
            record_key_3,
            record_key_2,
        ]);
    }

    #[test]
    fn when_second_state_with_same_public_key_and_chain_id_added_then_it_keeps_first_data() {
        let mut context = TestContext::new();

        let chain_id = 1;
        let record_key = (random_public_key(), chain_id);
        let chain_key_1 = chain_key(1);
        let chain_key_2 = chain_key(2);

        context.add_sender_key_state_record(record_key, &chain_key_1);
        context.add_sender_key_state_record(record_key, &chain_key_2);

        context.assert_number_of_states(1);
        context.assert_records_chain_key(record_key, &chain_key_1);
    }

    #[test]
    fn when_second_state_with_different_public_key_but_same_chain_id_added_then_it_gets_replaced() {
        let mut context = TestContext::new();

        let chain_id = 1;
        let record_key_1 = (random_public_key(), chain_id);
        let record_key_2 = (random_public_key(), chain_id);
        let chain_key_1 = chain_key(1);
        let chain_key_2 = chain_key(2);

        context.add_sender_key_state_record(record_key_1, &chain_key_1);
        context.add_sender_key_state_record(record_key_2, &chain_key_2);

        context.assert_number_of_states(1);
        context.assert_records_chain_key(record_key_2, &chain_key_2);
    }

    #[test]
    fn when_second_state_with_same_public_key_and_chain_id_added_then_it_becomes_the_most_recent() {
        let mut context = TestContext::new();

        let chain_id_1 = 1;
        let chain_id_2 = 2;
        let record_key_1 = (random_public_key(), chain_id_1);
        let record_key_2 = (random_public_key(), chain_id_2);
        let chain_key_1 = chain_key(1);
        let chain_key_2 = chain_key(2);
        let chain_key_3 = chain_key(3);

        context.add_sender_key_state_record(record_key_1, &chain_key_1);
        context.add_sender_key_state_record(record_key_2, &chain_key_2);

        context.assert_record_order(vec![record_key_2, record_key_1]);

        context.add_sender_key_state_record(record_key_1, &chain_key_3);

        context.assert_record_order(vec![record_key_1, record_key_2]);
    }
}
