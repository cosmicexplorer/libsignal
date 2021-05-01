//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Contains [traits] used throughout the repo, as well as some private methods.

mod bit_ops {
    pub fn expand_top_bit(a: u8) -> u8 {
        //if (a >> 7) == 1 { 0xFF } else { 0 }
        0u8.wrapping_sub(a >> 7)
    }
}

mod constant_time_ops {
    use super::bit_ops::expand_top_bit;

    use std::cmp::Ordering;

    pub fn ct_is_zero(a: u8) -> u8 {
        //if a == 0 { 0xFF } else { 0 }
        expand_top_bit(!a & a.wrapping_sub(1))
    }

    pub fn ct_is_eq(a: u8, b: u8) -> u8 {
        //if a == b { 0xFF } else { 0 }
        ct_is_zero(a ^ b)
    }

    pub fn ct_is_lt(a: u8, b: u8) -> u8 {
        //if a < b { 0xFF } else { 0 }
        expand_top_bit(a ^ ((a ^ b) | ((a.wrapping_sub(b)) ^ a)))
    }

    pub fn ct_select(mask: u8, a: u8, b: u8) -> u8 {
        debug_assert!(mask == 0 || mask == 0xFF);
        //if mask == 0xFF { a } else if mask == 0x00 { b } else { unreachable!(); }
        b ^ (mask & (a ^ b))
    }

    /// Compare the byte slices `x` and `y` in constant time.
    ///
    /// If x and y are different lengths, this leaks information about
    /// their relative sizes. This is irrelevant as we always invoke it
    /// with two inputs of the same size.
    ///
    /// In addition it will leak the final comparison result, when the
    /// integer is translated to the Ordering enum. This seems unavoidable.
    ///
    /// The primary goal of this function is to not leak any additional
    /// information, besides the ordering, about the value of the two keys,
    /// say due to an early exit of the loop.
    ///
    /// It would be possible to instead have this function SHA-256 hash both
    /// inputs, then compare the resulting hashes in the usual non-const
    /// time way. We avoid this approach at the moment since it is not clear
    /// if applications will rely on public key ordering being defined in
    /// some particular way or not.
    pub fn constant_time_cmp(x: &[u8], y: &[u8]) -> Ordering {
        if x.len() < y.len() {
            return Ordering::Less;
        }
        if x.len() > y.len() {
            return Ordering::Greater;
        }

        let mut result: u8 = 0;

        for i in 0..x.len() {
            let a = x[x.len() - 1 - i];
            let b = y[x.len() - 1 - i];

            let is_eq = ct_is_eq(a, b);
            let is_lt = ct_is_lt(a, b);

            result = ct_select(is_eq, result, ct_select(is_lt, 1, 255));
        }

        debug_assert!(result == 0 || result == 1 || result == 255);

        if result == 0 {
            Ordering::Equal
        } else if result == 1 {
            Ordering::Less
        } else {
            Ordering::Greater
        }
    }
}
pub(crate) use constant_time_ops::constant_time_cmp;

/// Ensure consistent byte-level behavior across our structs, with type safety by using traits with
/// type parameters.
pub mod traits {
    /// Traits for consistent serialization and deserialization of data.
    pub mod serde {
        use crate::Result;
        use std::convert::AsRef;

        /// Protocol for structs that can convert themselves to bytes.
        pub trait Serializable<Out: AsRef<[u8]>> {
            fn serialize(&self) -> Out;
        }

        /// Similar to [Serializable], but retains a given lifetime.
        pub trait RefSerializable<'a> {
            fn serialize(&'a self) -> &'a [u8];
        }

        /// Defines a message which knows how to instantiate itself from a string of bytes.
        pub trait Deserializable {
            fn deserialize(data: &[u8]) -> Result<Self>
            where
                Self: Sized;
        }
    }

    /// Traits used to ensure consistent behavior across different message types in the
    /// Signal Protocol.
    pub mod message {
        use crate::{consts::types::VersionType, Result};

        /// Some messages have a signature to check. We use this interface to check that signature.
        pub trait SignatureVerifiable<Sig> {
            /// Verify whether a signature matches the message contents from `self`.
            ///
            /// TODO: returning a custom Result or enum would likely be safer. What should the
            /// caller do if the value is `false`? This applies to all `Result<bool>` return values
            /// in this repo.
            fn verify_signature(&self, signature: Sig) -> Result<bool>;
        }

        /// The similar base set of capabilities we expect from this library's
        /// in-memory representations of over-the-wire structs.
        pub trait SignalProtocolMessage<'a>: super::serde::RefSerializable<'a> {
            fn message_version(&self) -> VersionType;
        }

        /// Each message in the Double Ratchet protocol is associated with a particular
        /// numerical sequence type.
        pub trait SequencedMessage {
            /// This is typically an unsigned integer type.
            type Count;
            /// This value is incremented in some way when sending each message.
            fn counter(&self) -> Self::Count;
        }
    }
}

pub mod unwrap {
    pub fn no_encoding_error(result: Result<(), prost::EncodeError>) {
        // prost documents the only possible encoding error is if there is insufficient
        // space, which is not a problem when it is allowed to encode into a Vec.
        result.expect("No encoding error")
    }

    pub fn no_hmac_varkey_error<E: std::fmt::Debug>(
        result: Result<hmac::Hmac<sha2::Sha256>, E>,
    ) -> hmac::Hmac<sha2::Sha256> {
        result.expect("HMAC-SHA256 should accept any size key")
    }
}

#[cfg(test)]
mod tests {
    use super::constant_time_ops::*;
    use std::cmp::Ordering;

    #[test]
    fn test_constant_time_cmp() {
        use rand::Rng;

        assert_eq!(constant_time_cmp(&[1], &[1]), Ordering::Equal);
        assert_eq!(constant_time_cmp(&[0, 1], &[1]), Ordering::Greater);
        assert_eq!(constant_time_cmp(&[1], &[0, 1]), Ordering::Less);
        assert_eq!(constant_time_cmp(&[2], &[1, 0, 1]), Ordering::Less);

        let mut rng = rand::rngs::OsRng;
        for len in 1..320 {
            let x: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
            let y: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
            let expected = x.cmp(&y);
            let result = constant_time_cmp(&x, &y);
            assert_eq!(result, expected);

            let expected = y.cmp(&x);
            let result = constant_time_cmp(&y, &x);
            assert_eq!(result, expected);
        }
    }

    #[test]
    fn test_ct_is_zero() {
        assert_eq!(ct_is_zero(0), 0xFF);

        for i in 1..255 {
            assert_eq!(ct_is_zero(i), 0x00);
        }
    }

    #[test]
    fn test_ct_is_lt() {
        for x in 0..255 {
            for y in 0..255 {
                let expected = if x < y { 0xFF } else { 0 };
                let result = ct_is_lt(x, y);
                assert_eq!(result, expected);
            }
        }
    }

    #[test]
    fn test_ct_is_eq() {
        for x in 0..255 {
            for y in 0..255 {
                let expected = if x == y { 0xFF } else { 0 };
                let result = ct_is_eq(x, y);
                assert_eq!(result, expected);
            }
        }
    }
}
