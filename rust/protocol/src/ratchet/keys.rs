//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Structs forming the key material described in the [Double Ratchet] algorithm.
//!
//! [Double Ratchet]: https://signal.org/docs/specifications/doubleratchet/#kdf-chains

use arrayref::array_ref;

use crate::{
    consts::{
        byte_lengths::KEY_LENGTH,
        types::{as_iv_bytes, as_key_bytes, Counter, IVBytes, KeyBytes, SeedBytes},
    },
    crypto,
    curve::{PrivateKey, PublicKey},
    kdf::{HKDF, KDF},
    Result,
};

use std::fmt;

/// TODO: ???
pub struct MessageKeys {
    cipher_key: KeyBytes,
    mac_key: KeyBytes,
    iv: IVBytes,
    counter: Counter,
}

impl MessageKeys {
    /// TODO: ???
    pub fn derive_keys(input_key_material: &[u8], kdf: HKDF, counter: Counter) -> Self {
        let okm = kdf.derive_secrets(input_key_material, b"WhisperMessageKeys", 80);
        MessageKeys {
            cipher_key: *as_key_bytes(&okm[..KEY_LENGTH]),
            mac_key: *as_key_bytes(&okm[KEY_LENGTH..(2 * KEY_LENGTH)]),
            iv: *as_iv_bytes(&okm[(2 * KEY_LENGTH)..]),
            counter,
        }
    }

    /// Create a new instance.
    pub fn new(cipher_key: &KeyBytes, mac_key: &KeyBytes, iv: &IVBytes, counter: Counter) -> Self {
        MessageKeys {
            cipher_key: *array_ref![cipher_key, 0, 32],
            mac_key: *array_ref![mac_key, 0, 32],
            iv: *array_ref![iv, 0, 16],
            counter,
        }
    }

    #[inline]
    pub fn cipher_key(&self) -> &KeyBytes {
        &self.cipher_key
    }

    #[inline]
    pub fn mac_key(&self) -> &KeyBytes {
        &self.mac_key
    }

    #[inline]
    pub fn iv(&self) -> &IVBytes {
        &self.iv
    }

    #[inline]
    pub fn counter(&self) -> Counter {
        self.counter
    }
}

/// TODO: ???
#[derive(Clone, Debug)]
pub struct ChainKey {
    kdf: HKDF,
    key: KeyBytes,
    index: Counter,
}

impl ChainKey {
    const MESSAGE_KEY_SEED: SeedBytes = [0x01u8];
    const CHAIN_KEY_SEED: SeedBytes = [0x02u8];

    /// Create a new instance.
    pub fn new(kdf: HKDF, key: &KeyBytes, index: Counter) -> Self {
        Self {
            kdf,
            key: *key,
            index,
        }
    }

    #[inline]
    pub fn key(&self) -> &KeyBytes {
        &self.key
    }

    #[inline]
    pub fn index(&self) -> Counter {
        self.index
    }

    /// ???
    pub fn next_chain_key(&self) -> Self {
        Self {
            kdf: self.kdf,
            key: self.calculate_base_material(Self::CHAIN_KEY_SEED),
            index: self.index + 1,
        }
    }

    /// ???
    pub fn message_keys(&self) -> MessageKeys {
        MessageKeys::derive_keys(
            &self.calculate_base_material(Self::MESSAGE_KEY_SEED),
            self.kdf,
            self.index,
        )
    }

    /// ???
    fn calculate_base_material(&self, seed: SeedBytes) -> KeyBytes {
        crypto::hmac_sha256(&self.key, &seed)
    }
}

/// TODO: ???
#[derive(Clone, Debug)]
pub struct RootKey {
    kdf: HKDF,
    key: KeyBytes,
}

impl RootKey {
    /// Create a new instance.
    pub fn new(kdf: HKDF, key: &KeyBytes) -> Self {
        Self { kdf, key: *key }
    }

    #[inline]
    pub fn key(&self) -> &KeyBytes {
        &self.key
    }

    /// ???
    pub fn create_chain(
        &self,
        their_ratchet_key: &PublicKey,
        our_ratchet_key: &PrivateKey,
    ) -> Result<(RootKey, ChainKey)> {
        let shared_secret = our_ratchet_key.calculate_agreement(their_ratchet_key);
        let derived_secret_bytes = self.kdf.derive_salted_secrets(
            shared_secret.as_ref(),
            &self.key,
            b"WhisperRatchet",
            64,
        );
        Ok((
            RootKey {
                kdf: self.kdf,
                key: *as_key_bytes(&derived_secret_bytes[..KEY_LENGTH]),
            },
            ChainKey {
                kdf: self.kdf,
                key: *as_key_bytes(&derived_secret_bytes[KEY_LENGTH..]),
                index: 0,
            },
        ))
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
    use crate::{
        curve::{PrivateKey, PublicKey},
        utils::traits::serde::Deserializable,
    };

    #[test]
    fn test_chain_key_derivation_v2() -> Result<()> {
        let seed = [
            0x8au8, 0xb7, 0x2d, 0x6f, 0x4c, 0xc5, 0xac, 0x0d, 0x38, 0x7e, 0xaf, 0x46, 0x33, 0x78,
            0xdd, 0xb2, 0x8e, 0xdd, 0x07, 0x38, 0x5b, 0x1c, 0xb0, 0x12, 0x50, 0xc7, 0x15, 0x98,
            0x2e, 0x7a, 0xd4, 0x8f,
        ];
        let message_key = [
            0x02u8, 0xa9, 0xaa, 0x6c, 0x7d, 0xbd, 0x64, 0xf9, 0xd3, 0xaa, 0x92, 0xf9, 0x2a, 0x27,
            0x7b, 0xf5, 0x46, 0x09, 0xda, 0xdf, 0x0b, 0x00, 0x82, 0x8a, 0xcf, 0xc6, 0x1e, 0x3c,
            0x72, 0x4b, 0x84, 0xa7,
        ];
        let mac_key = [
            0xbfu8, 0xbe, 0x5e, 0xfb, 0x60, 0x30, 0x30, 0x52, 0x67, 0x42, 0xe3, 0xee, 0x89, 0xc7,
            0x02, 0x4e, 0x88, 0x4e, 0x44, 0x0f, 0x1f, 0xf3, 0x76, 0xbb, 0x23, 0x17, 0xb2, 0xd6,
            0x4d, 0xeb, 0x7c, 0x83,
        ];
        let next_chain_key = [
            0x28u8, 0xe8, 0xf8, 0xfe, 0xe5, 0x4b, 0x80, 0x1e, 0xef, 0x7c, 0x5c, 0xfb, 0x2f, 0x17,
            0xf3, 0x2c, 0x7b, 0x33, 0x44, 0x85, 0xbb, 0xb7, 0x0f, 0xac, 0x6e, 0xc1, 0x03, 0x42,
            0xa2, 0x46, 0xd1, 0x5d,
        ];

        let chain_key = ChainKey::new(HKDF::new_from_version(2)?, &seed, 0);
        assert_eq!(&seed, chain_key.key());
        assert_eq!(&message_key, chain_key.message_keys().cipher_key());
        assert_eq!(&mac_key, chain_key.message_keys().mac_key());
        assert_eq!(&next_chain_key, chain_key.next_chain_key().key());
        assert_eq!(0, chain_key.index());
        assert_eq!(0, chain_key.message_keys().counter());
        assert_eq!(1, chain_key.next_chain_key().index());
        assert_eq!(1, chain_key.next_chain_key().message_keys().counter());
        Ok(())
    }

    #[test]
    fn test_chain_key_derivation_v3() -> Result<()> {
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

        let chain_key = ChainKey::new(HKDF::new(), &seed, 0);
        assert_eq!(&seed, chain_key.key());
        assert_eq!(&message_key, chain_key.message_keys().cipher_key());
        assert_eq!(&mac_key, chain_key.message_keys().mac_key());
        assert_eq!(&next_chain_key, chain_key.next_chain_key().key());
        assert_eq!(0, chain_key.index());
        assert_eq!(0, chain_key.message_keys().counter());
        assert_eq!(1, chain_key.next_chain_key().index());
        assert_eq!(1, chain_key.next_chain_key().message_keys().counter());
        Ok(())
    }

    #[test]
    fn test_root_key_derivation_v2() -> Result<()> {
        let root_key_seed = [
            0x7bu8, 0xa6, 0xde, 0xbc, 0x2b, 0xc1, 0xbb, 0xf9, 0x1a, 0xbb, 0xc1, 0x36, 0x74, 0x04,
            0x17, 0x6c, 0xa6, 0x23, 0x09, 0x5b, 0x7e, 0xc6, 0x6b, 0x45, 0xf6, 0x02, 0xd9, 0x35,
            0x38, 0x94, 0x2d, 0xcc,
        ];
        let alice_private = [
            0x20u8, 0x68, 0x22, 0xec, 0x67, 0xeb, 0x38, 0x04, 0x9e, 0xba, 0xe7, 0xb9, 0x39, 0xba,
            0xea, 0xeb, 0xb1, 0x51, 0xbb, 0xb3, 0x2d, 0xb8, 0x0f, 0xd3, 0x89, 0x24, 0x5a, 0xc3,
            0x7a, 0x94, 0x8e, 0x50,
        ];
        let bob_public = [
            0x05u8, 0xab, 0xb8, 0xeb, 0x29, 0xcc, 0x80, 0xb4, 0x71, 0x09, 0xa2, 0x26, 0x5a, 0xbe,
            0x97, 0x98, 0x48, 0x54, 0x06, 0xe3, 0x2d, 0xa2, 0x68, 0x93, 0x4a, 0x95, 0x55, 0xe8,
            0x47, 0x57, 0x70, 0x8a, 0x30,
        ];

        // These differ from the libsignal-protocol-java test case because the test case there uses
        // an invalid alice private key that hasn't been properly scalar clamped. The x25519 code in
        // Java doesn't apply the scalar clamping before doing the montgomery point multiplication
        // whereas the rust x25519 library does scalar clamp the passed in private key before doing
        // the multiplication. You can confirm these keys with libsignal-protocol-java by changing
        // the first byte of alicePrivate from 0x21 to 0x20.
        let next_root = [
            0x67u8, 0x46, 0x77, 0x65, 0x21, 0x04, 0xe8, 0x64, 0xd0, 0x7c, 0x54, 0x33, 0xef, 0xaa,
            0x59, 0x25, 0xed, 0x43, 0x67, 0xd6, 0xb2, 0x5a, 0xaf, 0xe6, 0x99, 0x1d, 0xef, 0x5c,
            0x7f, 0x0f, 0xb8, 0x6f,
        ];
        let next_chain = [
            0xfau8, 0xed, 0x7f, 0xb2, 0xc3, 0xe6, 0xf6, 0x06, 0xfc, 0xbf, 0x26, 0x64, 0x6c, 0xf2,
            0x68, 0xad, 0x49, 0x58, 0x9f, 0xcb, 0xde, 0x01, 0xc1, 0x26, 0x75, 0xe5, 0xe8, 0x22,
            0xa7, 0xe3, 0x35, 0xd1,
        ];

        let alice_private_key = PrivateKey::deserialize(&alice_private)?;
        let bob_public_key = PublicKey::deserialize(&bob_public)?;
        let root_key = RootKey::new(HKDF::new_from_version(2)?, &root_key_seed);

        let (next_root_key, next_chain_key) =
            root_key.create_chain(&bob_public_key, &alice_private_key);

        assert_eq!(&root_key_seed, root_key.key());
        assert_eq!(&next_root, next_root_key.key());
        assert_eq!(&next_chain, next_chain_key.key());
        Ok(())
    }
}
