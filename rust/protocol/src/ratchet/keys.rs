//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::crypto;
use crate::curve::KeyType;
use crate::proto::storage;
use crate::{
    CiphertextMessageType, PrivateKey, PublicKey, Result, SignalProtocolError, ViaProtobuf,
};

use std::convert::TryInto;
use std::fmt;

use arrayref::array_ref;

const CIPHER_KEY_LEN: usize = 32;
pub const MAC_KEY_LEN: usize = 32;
const IV_LEN: usize = 16;

pub trait RatchetingMessageKeys: ViaProtobuf + Clone {
    fn derive_keys(input_key_material: &[u8], counter: u32) -> Self
    where
        Self: Sized;
    fn cipher_key(&self) -> &[u8; CIPHER_KEY_LEN];
    fn mac_key(&self) -> &[u8; MAC_KEY_LEN];
    fn iv(&self) -> &[u8; IV_LEN];
    fn counter(&self) -> u32;
}

#[derive(Copy, Clone, Debug)]
pub struct MessageKeys {
    cipher_key: [u8; CIPHER_KEY_LEN],
    mac_key: [u8; MAC_KEY_LEN],
    iv: [u8; IV_LEN],
    counter: u32,
}

impl MessageKeys {
    pub fn new(
        cipher_key: [u8; CIPHER_KEY_LEN],
        mac_key: [u8; MAC_KEY_LEN],
        iv: [u8; IV_LEN],
        counter: u32,
    ) -> Self {
        MessageKeys {
            cipher_key,
            mac_key,
            iv,
            counter,
        }
    }
}

impl ViaProtobuf for MessageKeys {
    type Proto = storage::MessageKey;
    fn into_protobuf(&self) -> Self::Proto {
        storage::MessageKey {
            index: self.counter(),
            cipher_key: self.cipher_key().to_vec(),
            mac_key: self.mac_key().to_vec(),
            iv: self.iv().to_vec(),
        }
    }
    fn from_protobuf(proto: &Self::Proto) -> Result<Self>
    where
        Self: Sized,
    {
        let storage::MessageKey {
            index,
            cipher_key,
            mac_key,
            iv,
        } = proto;
        Ok(Self {
            counter: *index,
            cipher_key: cipher_key.as_slice().try_into().map_err(|_| {
                SignalProtocolError::BadKeyLength(
                    KeyType::Djb,
                    cipher_key.len(),
                    CIPHER_KEY_LEN,
                    format!("cipher key {:?}", proto),
                )
            })?,
            mac_key: mac_key
                .as_slice()
                .try_into()
                .map_err(|_| SignalProtocolError::InvalidMacKeyLength(mac_key.len()))?,
            iv: iv.as_slice().try_into().map_err(|_| {
                SignalProtocolError::InvalidMessage(CiphertextMessageType::Whisper, "IV invalid")
            })?,
        })
    }
}

impl RatchetingMessageKeys for MessageKeys {
    fn derive_keys(input_key_material: &[u8], counter: u32) -> Self
    where
        Self: Sized,
    {
        let mut okm = [0; 80];
        hkdf::Hkdf::<sha2::Sha256>::new(None, input_key_material)
            .expand(b"WhisperMessageKeys", &mut okm)
            .expect("valid output length");

        let cipher_key = array_ref![okm, 0, CIPHER_KEY_LEN];
        let mac_key = array_ref![okm, CIPHER_KEY_LEN, MAC_KEY_LEN];
        let iv = array_ref![okm, CIPHER_KEY_LEN + MAC_KEY_LEN, IV_LEN];
        Self::new(*cipher_key, *mac_key, *iv, counter)
    }

    #[inline]
    fn cipher_key(&self) -> &[u8; CIPHER_KEY_LEN] {
        &self.cipher_key
    }

    #[inline]
    fn mac_key(&self) -> &[u8; MAC_KEY_LEN] {
        &self.mac_key
    }

    #[inline]
    fn iv(&self) -> &[u8; IV_LEN] {
        &self.iv
    }

    #[inline]
    fn counter(&self) -> u32 {
        self.counter
    }
}

const HEADER_KEY_LEN: usize = 32;

pub trait HeaderEncryptedRatchetingMessageKeys: RatchetingMessageKeys {
    fn header_key(&self) -> &[u8; HEADER_KEY_LEN];
    fn next_header_key(&self) -> &[u8; HEADER_KEY_LEN];
}

#[derive(Copy, Clone, Debug)]
pub struct HeaderEncryptedMessageKeys {
    inner: MessageKeys,
    header_key: [u8; HEADER_KEY_LEN],
    next_header_key: [u8; HEADER_KEY_LEN],
}

impl HeaderEncryptedMessageKeys {
    pub fn new(
        cipher_key: [u8; CIPHER_KEY_LEN],
        mac_key: [u8; MAC_KEY_LEN],
        iv: [u8; IV_LEN],
        counter: u32,
        header_key: [u8; HEADER_KEY_LEN],
        next_header_key: [u8; HEADER_KEY_LEN],
    ) -> Self {
        eprintln!("header_key: {:?}", header_key);
        eprintln!("next_header_key: {:?}", next_header_key);
        Self {
            inner: MessageKeys::new(cipher_key, mac_key, iv, counter),
            header_key,
            next_header_key,
        }
    }
}

impl ViaProtobuf for HeaderEncryptedMessageKeys {
    type Proto = storage::HeaderEncryptedMessageKey;
    fn into_protobuf(&self) -> Self::Proto {
        storage::HeaderEncryptedMessageKey {
            inner: Some(self.inner.into_protobuf()),
            header_key: self.header_key.to_vec(),
            next_header_key: self.next_header_key.to_vec(),
        }
    }
    fn from_protobuf(proto: &Self::Proto) -> Result<Self>
    where
        Self: Sized,
    {
        let storage::HeaderEncryptedMessageKey {
            inner,
            header_key,
            next_header_key,
        } = proto;
        let inner = inner
            .clone()
            .ok_or(SignalProtocolError::InvalidProtobufEncoding)?;
        Ok(Self {
            inner: MessageKeys::from_protobuf(&inner)?,
            header_key: header_key
                .as_slice()
                .try_into()
                .map_err(|_| SignalProtocolError::InvalidProtobufEncoding)?,
            next_header_key: next_header_key
                .as_slice()
                .try_into()
                .map_err(|_| SignalProtocolError::InvalidProtobufEncoding)?,
        })
    }
}

impl RatchetingMessageKeys for HeaderEncryptedMessageKeys {
    fn derive_keys(input_key_material: &[u8], counter: u32) -> Self
    where
        Self: Sized,
    {
        let mut okm = [0; 144];
        hkdf::Hkdf::<sha2::Sha256>::new(None, input_key_material)
            // Use a separate "info" string than is used for Hkdf expansion in MessageKeys.
            .expand(b"HeaderEncryptedWhisperMessageKeys", &mut okm)
            .expect("valid output length");

        let cipher_key = array_ref![okm, 0, CIPHER_KEY_LEN];
        let mac_key = array_ref![okm, CIPHER_KEY_LEN, MAC_KEY_LEN];
        let iv = array_ref![okm, CIPHER_KEY_LEN + MAC_KEY_LEN, IV_LEN];
        let header_key = array_ref![okm, CIPHER_KEY_LEN + MAC_KEY_LEN + IV_LEN, HEADER_KEY_LEN];
        let next_header_key = array_ref![
            okm,
            CIPHER_KEY_LEN + MAC_KEY_LEN + IV_LEN + HEADER_KEY_LEN,
            HEADER_KEY_LEN
        ];

        Self::new(
            *cipher_key,
            *mac_key,
            *iv,
            counter,
            *header_key,
            *next_header_key,
        )
    }

    #[inline]
    fn cipher_key(&self) -> &[u8; CIPHER_KEY_LEN] {
        self.inner.cipher_key()
    }

    #[inline]
    fn mac_key(&self) -> &[u8; MAC_KEY_LEN] {
        self.inner.mac_key()
    }

    #[inline]
    fn iv(&self) -> &[u8; IV_LEN] {
        self.inner.iv()
    }

    #[inline]
    fn counter(&self) -> u32 {
        self.inner.counter()
    }
}

impl HeaderEncryptedRatchetingMessageKeys for HeaderEncryptedMessageKeys {
    #[inline]
    fn header_key(&self) -> &[u8; HEADER_KEY_LEN] {
        &self.header_key
    }

    #[inline]
    fn next_header_key(&self) -> &[u8; HEADER_KEY_LEN] {
        &self.next_header_key
    }
}

const CHAIN_KEY_LEN: usize = 32;

#[derive(Copy, Clone, Debug)]
pub struct ChainKey {
    key: [u8; CHAIN_KEY_LEN],
    index: u32,
}

impl ChainKey {
    const MESSAGE_KEY_SEED: [u8; 1] = [0x01u8];
    const CHAIN_KEY_SEED: [u8; 1] = [0x02u8];

    pub fn new(key: [u8; CHAIN_KEY_LEN], index: u32) -> Self {
        Self { key, index }
    }

    #[inline]
    pub fn key(&self) -> &[u8; CHAIN_KEY_LEN] {
        &self.key
    }

    #[inline]
    pub(crate) fn index(&self) -> u32 {
        self.index
    }

    pub(crate) fn next_chain_key(&self) -> Self {
        Self {
            key: self.calculate_base_material(Self::CHAIN_KEY_SEED),
            index: self.index + 1,
        }
    }

    pub fn message_keys<Keys: RatchetingMessageKeys>(&self) -> Keys {
        Keys::derive_keys(
            &self.calculate_base_material(Self::MESSAGE_KEY_SEED),
            self.index,
        )
    }

    fn calculate_base_material(&self, seed: [u8; 1]) -> [u8; CHAIN_KEY_LEN] {
        crypto::hmac_sha256(&self.key, &seed)
    }
}

impl ViaProtobuf for ChainKey {
    type Proto = storage::ChainKey;
    fn into_protobuf(&self) -> Self::Proto {
        let ChainKey { key, index } = self;
        storage::ChainKey {
            key: key.to_vec(),
            index: *index,
        }
    }
    fn from_protobuf(proto: &Self::Proto) -> Result<Self>
    where
        Self: Sized,
    {
        let storage::ChainKey { index, key } = proto;
        Ok(Self {
            key: key
                .as_slice()
                .try_into()
                .map_err(|_| SignalProtocolError::InvalidProtobufEncoding)?,
            index: *index,
        })
    }
}

const ROOT_KEY_LEN: usize = 32;

#[derive(Copy, Clone, Debug)]
pub struct RootKey {
    key: [u8; ROOT_KEY_LEN],
}

impl RootKey {
    pub fn new(key: [u8; ROOT_KEY_LEN]) -> Self {
        Self { key }
    }

    pub fn key(&self) -> &[u8; ROOT_KEY_LEN] {
        &self.key
    }

    pub(crate) fn create_chain(
        &self,
        their_ratchet_key: &PublicKey,
        our_ratchet_key: &PrivateKey,
    ) -> (RootKey, ChainKey) {
        let shared_secret = our_ratchet_key.calculate_agreement(their_ratchet_key);
        let mut derived_secret_bytes = [0; ROOT_KEY_LEN + CHAIN_KEY_LEN];
        hkdf::Hkdf::<sha2::Sha256>::new(Some(&self.key), &shared_secret)
            .expand(b"WhisperRatchet", &mut derived_secret_bytes)
            .expect("valid output length");

        (
            RootKey {
                key: *array_ref![derived_secret_bytes, 0, ROOT_KEY_LEN],
            },
            ChainKey {
                key: *array_ref![derived_secret_bytes, ROOT_KEY_LEN, CHAIN_KEY_LEN],
                index: 0,
            },
        )
    }
}

impl fmt::Display for RootKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_key_derivation() -> Result<()> {
        let seed = [
            0x8au8, 0xb7, 0x2d, 0x6f, 0x4c, 0xc5, 0xac, 0x0d, 0x38, 0x7e, 0xaf, 0x46, 0x33, 0x78,
            0xdd, 0xb2, 0x8e, 0xdd, 0x07, 0x38, 0x5b, 0x1c, 0xb0, 0x12, 0x50, 0xc7, 0x15, 0x98,
            0x2e, 0x7a, 0xd4, 0x8f,
        ];
        let message_key = [
            0xbfu8, 0x51, 0xe9, 0xd7, 0x5e, 0x0e, 0x31, 0x03, 0x10, 0x51, 0xf8, 0x2a, 0x24, 0x91,
            0xff, 0xc0, 0x84, 0xfa, 0x29, 0x8b, 0x77, 0x93, 0xbd, 0x9d, 0xb6, 0x20, 0x05, 0x6f,
            0xeb, 0xf4, 0x52, 0x17,
        ];
        let mac_key = [
            0xc6u8, 0xc7, 0x7d, 0x6a, 0x73, 0xa3, 0x54, 0x33, 0x7a, 0x56, 0x43, 0x5e, 0x34, 0x60,
            0x7d, 0xfe, 0x48, 0xe3, 0xac, 0xe1, 0x4e, 0x77, 0x31, 0x4d, 0xc6, 0xab, 0xc1, 0x72,
            0xe7, 0xa7, 0x03, 0x0b,
        ];
        let next_chain_key = [
            0x28u8, 0xe8, 0xf8, 0xfe, 0xe5, 0x4b, 0x80, 0x1e, 0xef, 0x7c, 0x5c, 0xfb, 0x2f, 0x17,
            0xf3, 0x2c, 0x7b, 0x33, 0x44, 0x85, 0xbb, 0xb7, 0x0f, 0xac, 0x6e, 0xc1, 0x03, 0x42,
            0xa2, 0x46, 0xd1, 0x5d,
        ];

        let chain_key = ChainKey::new(seed, 0);
        assert_eq!(&seed, chain_key.key());
        /* FIXME: add tests for header encrypted message keys! */
        assert_eq!(
            &message_key,
            chain_key.message_keys::<MessageKeys>().cipher_key()
        );
        assert_eq!(&mac_key, chain_key.message_keys::<MessageKeys>().mac_key());
        assert_eq!(&next_chain_key, chain_key.next_chain_key().key());
        assert_eq!(0, chain_key.index());
        assert_eq!(0, chain_key.message_keys::<MessageKeys>().counter());
        assert_eq!(1, chain_key.next_chain_key().index());
        assert_eq!(
            1,
            chain_key
                .next_chain_key()
                .message_keys::<MessageKeys>()
                .counter()
        );
        Ok(())
    }
}
